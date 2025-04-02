+++
title = "Tokyo Westerns CTF 2018 - swap returns"
date = "2024-07-12"
description = "Tokyo Westerns CTF 2018 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fsb", "got overwrite"]
+++
## 0x00. Introduction

``` bash
[*] '/home/user/swap_returns'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Concept

``` c
int __fastcall __noreturn main()
{
  ...
      print_menu();
      choice = read_int();
      if ( choice == 1 )
      {
        puts("1st address: ");
        __isoc99_fscanf(stdin, "%lu", &first);
        puts("2nd address: ");
        __isoc99_fscanf(stdin, "%lu", &second);
      }
      if ( choice == 2 )
      {
        tmp = *first;
        *first = *second;
        *second = tmp;
        tmp = 0LL;
      }
  ...
}
```

값을 두 개 입력받고, 그 값이 가리키는 값을 서로 바꿔준다.

쉽게 말하면 두 주소를 입력받아 주소에 저장된 값을 서로 바꿔준다.

## 0x01. Vulnerability

문제에서 강력한 primitive를 주었지만 생각보다 해볼 만한 것이 없었다.

우선 지금 가지고 있는 것으로부터 할 수 있는 것을 생각해보면, **쓰기 권한이 있고, 고정적인 주소값들끼리 swap이 가능**하다.

따라서 먼저 이러한 조건이 맞는 주소를 확인해보았다.

```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/user/swap_returns
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/user/swap_returns
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/user/swap_returns
0x00007ffff7d87000 0x00007ffff7d8a000 0x0000000000000000 rw-
0x00007ffff7d8a000 0x00007ffff7db2000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7db2000 0x00007ffff7f47000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f47000 0x00007ffff7f9f000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f000 0x00007ffff7fa0000 0x0000000000215000 