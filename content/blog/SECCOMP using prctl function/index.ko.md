+++
title = "[SECCOMP] prctl를 이용한 SECCOMP 정리"
date = "2024-06-15"
description = "prctl 사용법부터 관련 도구, 예상 취약점까지"

[taxonomies]
tags = ["study", "linux", "seccomp", "mitigation"]
+++

## 0x00. Introduction
SECCOMP(SECure COMPuting mode)는 프로세스 샌드박싱을 제공하는 기능이다. 
자세하게는 프로세스에서 실행되는 syscall을 제한시켜, 호출 가능한 것 이외의 syscall이 호출될 경우 프로세스를 종료시킨다(`SIGKILL`). 
다른 보호 기법들처럼 컴파일 시 적용하는게 아니라 소스코드 단에서 설정하는 코드를 넣어주어야 한다.
  
예전에는 `/proc/<pid>/seccomp` 파일의 값을 통해 활성화 했었던 것 같으나, `prctl` 혹은 `sys_seccomp`를 통해서 설정되는 것으로 바뀌었다. (언제부터인지는 모르겠다...)  
  
본 포스트에서는 `prctl` 함수를 통한 SECCOMP 기법을 기술한다.

## 0x01. prctl 함수
``` c
int prctl(int option, ...
            /* unsigned long arg2, unsigned long arg3,
            unsigned long arg4, unsigned long arg5 */ );
```

`prctl` 함수는 프로세스나 쓰레드의 속성을 관리하기 위한 함수이다(PRocess ConTroL).
자세하게 설명할 SECCOMP 적용 이외에도 프로세스 이름을 얻는다든가, 엔디안 상태를 얻는다든가하는 다양한 행위를 할 수 있다.
원하는 행위에 따라 가변 인자를 받아서 동작하는 구조이다.

``` c
/* Values to pass as first argument to prctl() */
#define PR_SET_PDEATHSIG  1  /* Second arg is a signal */
#define PR_GET_PDEATHSIG  2  /* Second arg is a ptr to return the signal */
/* Get/set current->mm->dumpable */
#define PR_GET_DUMPABLE   3
#define PR_SET_DUMPABLE   4
/* Get/set unaligned access control bits (if meaningful) */
#define PR_GET_UNALIGN    5
#define PR_SET_UNALIGN    6
/* Set/Get process name */
#define PR_SET_NAME    15
#define PR_GET_NAME    16
/* Get/set process endian */
#define PR_GET_ENDIAN   19
#define PR_SET_ENDIAN   20
/* Get/set process seccomp mode */
// -----------------------------------------
#define PR_GET_SECCOMP  21                // |
#define PR_SET_SECCOMP  22                // |
#define PR_SET_NO_NEW_PRIVS     38        // |
#define PR_GET_NO_NEW_PRIVS     39        // |
// -----------------------------------------
```

`prctl.h`를 확인해보면 첫 번째 인자인 `option`에 들어가는 매크로의 값들을 확인할 수 있다.
이 중에서 SECCOMP와 관련이 있는 `PR_SET_NO_NEW_PRIVS`와 `PR_SET_SECCOMP`에 대해 자세히 알아보자.

### PR_SET_NO_NEW_PRIVS
``` c
int prctl(PR_SET_NO_NEW_PRIVS, int value);
```

현재 프로세스의 `no_new_privs` 속성을 `value` 값으로 설정해주는 동작을 수행한다.

이 속성은 리눅스 커널 4.10 이후부터는 `/proc/<pid>/status`의 `NoNewPrivs` 필드에서 확인할 수 있다고 한다.
이 속성이 1으로 설정되어있으면 현재 프로세스와 자식 프로세스에서 새로운 권한을 주는 명령을 수행할 수 없게 된다.
다만 권한을 제거하는 명령은 여전히 수행할 수 있다고 한다.

이 속성이 왜 중요한지는 [SECCOMP_MODE_FILTER](#seccomp-mode-filter) 파트에서 서술하겠다.

### PR_SET_SECCOMP
``` c
int prctl(PR_SET_SECCOMP, int mode, [...]);
```

드디어 SECCOMP를 실제 적용하는 부분으로, 두 가지 모드가 존재한다.

``` c
 /* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
 #define SECCOMP_MODE_DISABLED   0 /* seccomp is not in use. */
 #define SECCOMP_MODE_STRICT 1 /* uses hard-coded filter. */
 #define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */
```

`seccomp.h`를 확인해보면 모드가 각각 매크로로 정의되어있다.

#### SECCOMP_MODE_STRICT
`read`, `write`, `exit`, `sigreturn` 네 가지 syscall만 가능한 모드로 이미 가능한 syscall이 정해져있기 때문에 세 번째 인자가 필요없다.

``` c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

int main() {
        int fd;
        char buf[16] = {0};

        if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0) {
                perror("SET_SECCOMP error");
        }

        read(0, buf, 16);
        write(1, buf);

        fd = open("a.txt", 'w');
        write(fd, buf);
        close(fd);

        return 0;
}
```

예시 코드를 컴파일해서 실행한 결과, `open`에서 `SIGKILL`이 발생했다.

``` bash
$ ./strict
hihi
hihi
[1]    517393 killed     ./strict
```

#### SECCOMP_MODE_FILTER
사용자가 직접 어떤 syscall을 차단할지 룰 셋을 만들어서 SECCOMP를 설정하는 모드이다.
앞서 언급한 `PR_SET_NO_NEW_PRIVS`를 통해 `no_new_privs` 속성이 설정되어야 filter 모드를 실행할 수 있다.

이 때 룰 셋은 Berkeley Packet Filter(BPF)라는 어셈블리같은 문법을 사용하는데, [seccomp-tools](#0x03-seccomp-tools) 부분에서 자세하게 다뤄보자.
다음은 `write` syscall을 호출하지 못하게 필터링한 모드의 예시 코드이다.

``` c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

static unsigned char filter[] = {
    32, 0, 0, 0, 0, 0, 0, 0,    // A = sys_number
    21, 0, 1, 0, 1, 0, 0, 0,    // if (A == write) goto 0003
    6, 0, 0, 0, 0, 0, 255, 127,    // return ALLOW
    6, 0, 0, 0, 0, 0, 0, 0        // return KILL
}

struct sock_fprog {
    unsigned short len;
    unsigned char *filter;
};

int main() {
    int fd;
    char buf[16] = {0};
    struct sock_fprog prog;

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("SET_NO_NEW_PRIVS error");
    }

    prog.len = sizeof(filter) / 8;
    prog.filter = filter;

    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("SET_SECCOMP error");
    }

    read(0, buf, 16);
    write(1, buf);          // <----- This will be blocked

    fd = open("a.txt", 'w');
    write(fd, buf);
    close(fd);

    return 0;
}
```

``` bash
$ ./filter
hihi
[1]    669145 invalid system call (core dumped)  ./filter
```

예시 코드를 컴파일해서 실행한 결과, `write`에서 `SIGSYS`가 발생했다.
Strict mode에서의 `SIGKILL`과는 다른 메세지가 출력되길래 디버깅을 해봤는데 filter mode에서는 `SIGSYS`로 인해 프로세스가 종료되는 것을 확인했다.

## 0x03 seccomp-tools
`SECCOMP_MODE_FILTER`의 예시 코드를 보면, `filter` 배열에 필터링 룰을 바이트 코드처럼 바꾸어서 넣어야 한다.
하지만 아무리 숙련자라고 하더라도 원하는 BPF 룰을 자유자재로 바이트 코드화 하기는 어렵다.
이럴 때 쓰기 좋은 것이 바로 seccomp-tools이다.

``` bash
$ sudo apt install gcc ruby-dev -y
$ gem install seccomp-tools
```

seccomp-tools 설치는 위와 같이 하면 된다.

``` bash
$ seccomp-tools
Usage: seccomp-tools [--version] [--help] <command> [<options>]

List of commands:

        asm     Seccomp bpf assembler.
        disasm  Disassemble seccomp bpf.
        dump    Automatically dump seccomp bpf from execution file(s).
        emu     Emulate seccomp rules.

See 'seccomp-tools <command> --help' to read about a specific subcommand.
```

Usage에서 확인할 수 있듯이 `asm`, `disasm`, `dump`, `emu` 기능을 지원하고 있다.

### asm
BPF로 작성한 룰을 바이트 코드로 변환해주는 기능으로 BPF는 주로 다음과 같이 작성한다.

``` txt
A = arch
if (A != ARCH_X86_64) goto dead
A = sys_number
if (A >= 0x40000000) goto dead
if (A == write) goto ok
if (A == close) goto ok
if (A == dup) goto ok
if (A == exit) goto ok
return ERRNO(5)
ok:
return ALLOW
dead:
return KILL
```

뜬금없이 `A`라는 변수가 등장해서 처음에 뭐지 싶었는데, 그냥 임의 변수라고 생각하면 편하다.

이제 이 내용을 파일로 저장해서 seccomp-tools의 인자로 전달해주면 된다.

``` bash
$ seccomp-tools asm rule.txt
" \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\b>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x005\x00\x06\x00\x00\x00\x00@\x15\x00\x04\x00\x01\x00\x00\x00\x15\x00\x03\x00\x03\x00\x00\x00\x15\x00\x02\x00 \x00\x00\x00\x15\x00\x01\x00<\x00\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00"

$ seccomp-tools asm rule.txt -f c_array
unsigned char bpf[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,1,0,0,0,21,0,3,0,3,0,0,0,21,0,2,0,32,0,0,0,21,0,1,0,60,0,0,0,6,0,0,0,5,0,5,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};

$ seccomp-tools asm rule.txt -f c_source
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
static void install_seccomp() {
  static unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,1,0,0,0,21,0,3,0,3,0,0,0,21,0,2,0,32,0,0,0,21,0,1,0,60,0,0,0,6,0,0,0,5,0,5,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}
```

예시를 보면 결과를 다양한 포맷으로 출력할 수 있는데, -f 옵션에 `raw`, `c_array`, `c_source`, `assembly` 등 바로 사용하기 좋은 포맷들이 있다.

### disasm
`asm`과는 반대로 바이트 코드 형식의 BPF를 필터링 룰로 변환해준다.
입력 파일로 바이트 코드가 저장된 파일을 인자로 주면 된다.

``` bash
$ xxd rule.raw
00000000: 2000 0000 0400 0000 1500 0008 3e00 00c0   ...........>...
00000010: 2000 0000 0000 0000 3500 0600 0000 0040   .......5......@
00000020: 1500 0400 0100 0000 1500 0300 0300 0000  ................
00000030: 1500 0200 2000 0000 1500 0100 3c00 0000  .... .......<...
00000040: 0600 0000 0500 0500 0600 0000 0000 ff7f  ................
00000050: 0600 0000 0000 0000                      ........

$ seccomp-tools disasm rule.raw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
 0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

$ seccomp-tools asm rule.txt -f raw | seccomp-tools disasm -
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
 0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

`asm`기능과 연계해서 출력값을 `raw` 포맷으로 지정한 뒤 파이프라인을 연결해주면 BPF 룰이 제대로 작성되었는지 확인할 수 있다.

### dump
바이너리 내에 적용되는 BPF 룰을 출력해주는 기능이다.
동작 방식이 궁금해서 찾아보니 `ptrace`를 이용하여 동적으로 분석해주는 모양이다.

단 첫 번째 `prctl(PR_SET_SECCOMP)`를 기준으로 룰을 출력해주기 때문에 `prctl` 함수가 여러번 호출된다면 실제와 다를 수 있다.
그럴 때는 `-l` 혹은 `--limit` 옵션을 줘서 검사할 `prctl` 함수의 개수를 늘릴 수 있다.  
  
또한 `-p` 혹은 `--pid` 옵션을 줘서 현재 실행중인 프로세스에 걸려있는 룰을 확인할 수도 있다.

``` bash
$ seccomp-tools dump ./filter
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000000  return KILL

$ sudo seccomp-tools dump -p `pgrep filter`
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000000  return KILL
```

`dump` 기능을 이렇게 활용할 수 있다.

### emu
`emu`는 룰셋을 에뮬레이팅해서 syscall이 잘 호출되는지 혹은 잘 차단되는지를 확인하기 좋은 기능이다.

`bash`에서 사용하면 색깔이 입혀져서 출력이 나오기 때문에 보기 편하다.

![image](https://github.com/user-attachments/assets/386bcaed-3ac9-4bd9-b084-8bc85ff8f442)

![image](https://github.com/user-attachments/assets/31a4405c-73b6-4427-8868-2352f33690e3)

## 0x04. Expected Vulnerability
당연히 코딩을 어떻게 하느냐에 따라 다르겠지만 발생할 법한 취약점들을 생각해보았다.
좋은 아이디어나 댓글이 있다면 추가할 예정이다.

### x32 Syscall
앞선 seccomp-tools `disasm`의 예시에서 이런 룰이 있었다.

``` txt
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
```

`0001` 라인은 아키텍처가 `X86_64`인지 확인하는 로직이고, `0003` 라인의 `sys_number`가 `0x40000000`보다 큰지는 왜 확인하는걸까?

이유는 `X86_64` 아키텍처의 호환성에 있다.
64비트 아키텍처에서 이전 32비트에서 사용하던 명령어들을 그대로 사용할 수 있게끔 개발되었는데, 이런걸 x32 ABI라고 한다.
때문에 64비트 아키텍처에서도 32비트의 syscall을 호출할 수 있는데, 그 방법이 리눅스에서는 64bit syscall number에 `0x40000000`을 더하는 것이다.

실제 리눅스 커널에서 32비트 syscall을 호출했을 때 호출되는 `do_syscall_x32` 함수의 코드를 보자.

``` c
static __always_inline bool do_syscall_x32(struct pt_regs *regs, int nr)
{
    /*
     * Adjust the starting offset of the table, and convert numbers
     * < __X32_SYSCALL_BIT to very high and thus out of range
     * numbers for comparisons.
     */
    unsigned int xnr = nr - __X32_SYSCALL_BIT;
    if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(xnr < X32_NR_syscalls)) {
        xnr = array_index_nospec(xnr, X32_NR_syscalls);
        regs->ax = x32_sys_call_table[xnr](regs);
        return true;
    }
    return false;
}
```

함수의 첫 줄에서 `xnr = nr - __X32_SYSCALL_BIT`으로 할당이 되는데, 이 때 `__X32_SYSCALL_BIT` 값이 사전 정의된 `0x40000000`이라고 한다.

따라서 어떤 64비트 바이너리의 BPF 룰에 syscall number가 `0x40000000`보다 작은지 검증하는 로직이 존재하지 않는다면,
특정 syscall이 차단되었다고 하더라도 x32 ABI를 이용하여 syscall number에 `0x40000000`을 더해서 32비트 아키텍처의 syscall을 호출할 수 있다.

### Filter Overwrite
가장 단순하게 떠오른 생각으로 메모리에 있는 BPF 필터 룰 부분을 SECCOMP가 설정되기 전에 원하는 값으로 덮을 수 있을 때 발생할 수 있는 취약점이다.
원하는 syscall을 호출할 수 있도록 룰을 바꿔준다든가, 룰을 `return ALLOW`로 도배한다든가하는 방법이 있을 것이다.

이와 관련된 문제가 [dreamhack.io](https://dreamhack.io)에 있으니 풀어보길 추천한다.

### SECCOMP Bypass
`PR_SET_SECCOMP` 하다가 알게 된 사실인데, BPF 룰이 좀 잘못되어있으면 prctl 함수가 에러만 리턴하고 프로세스를 종료시키지는 않는다.

``` bash
$ cat wrong.txt
A = sys_number
if (A == write) goto 3
return ALLOW
return KILL

$ seccomp-tools asm wrong.txt -f raw | seccomp-tools disasm -
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0005
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x06 0x00 0x00 0x00000000  return KILL
```

잘못된 BPF룰의 예시로, 잘 보면 0001 라인에서 goto 0005라고 되어있다.
`wrong.txt`를 구성할 때 `goto`에서 생각 없이 `return KILL`이 위치하게 될 3번 라인으로 가라고 했는데, 알고보니 상대주소 개념으로 값을 넣어주어야 했다.

예를 들어 현재 라인인 0001에서 `goto 0`이면 다음 라인인 0002, `goto 1`이면 다음 X 2 라인인 0003으로 가라는 식으로 해석되어서, `goto 3`은 0005 라인으로 가라는 명령어가 되었다.
`wrong.txt`에는 0005라인이 존재하지 않으니 `prctl`의 옵션으로 전달 시 에러가 발생한다.

``` bash
$ ./filter
SET_SECCOMP error: Invalid argument
hihi
hihi
```

잘못된 룰을 적용했을 때 이런 식으로 SECCOMP 에러가 발생한다.
결과적으로 `write` syscall을 차단하려는 룰이 적용되지 않아 입력받은 문자열을 `STDOUT`에 출력할 수 있게 되었다.

따라서 Filter Overwrite처럼 필터 전체를 덮어쓰지 못하더라도 몇 바이트로 룰 자체를 말이 안되게 할 수 있다면 에러는 발생하되 프로세스는 유지되므로 SECCOMP bypass가 가능할 것이다.

## 0x05. 참고자료
 - [https://man7.org/linux/man-pages/man2/prctl.2.html](https://man7.org/linux/man-pages/man2/prctl.2.html)
 - [https://jeongzero.oopy.io/06eebad5-8306-493f-9c6d-e7a04d5aacff](https://jeongzero.oopy.io/06eebad5-8306-493f-9c6d-e7a04d5aacff)
- [https://velog.io/@woounnan/LINUX-Seccomp](https://velog.io/@woounnan/LINUX-Seccomp)
- [https://velog.io/@dandb3/SECCOMP2](https://velog.io/@dandb3/SECCOMP2)
- [https://learn.dreamhack.io/280](https://learn.dreamhack.io/280)
- [https://github.com/david942j/seccomp-tools](https://github.com/david942j/seccomp-tools)