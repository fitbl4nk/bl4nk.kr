+++
title = "CSAW 2024 - Archeology"
date = "2025-03-28"
description = "CSAW 2024 reversing challenge"

[taxonomies]
tags = ["ctf", "reversing", "virtual machine"]
+++

## 0x00. Introduction
``` bash
➜  ls
chal  hieroglyphs.txt  message.txt
➜  file chal 
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=bbcf6cbfa61b68c7b8bfa3145852d06580a55643, for GNU/Linux 3.2.0, not stripped
```

## 0x01. Concept
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  ...
  if ( argc == 2 )
  {
    *(_DWORD *)magic = 0xDDCCBBAA;
    magic[4] = 0xEE;
    plain = (char *)argv[1];
    plain_len = strlen(plain);
    index = 0;
    printf("Encrypted data: ");
    washing_machine(plain, plain_len);
    ...
  }
}
```

먼저 바이너리를 실행할 때 입력한 인자를 `washing_machine()`에 전달해서 실행한다.

``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    ...
    for ( i = 0; i < plain_len; ++i )
    {
      buf[index] = 0; 
      buf[index + 1] = 1;
      buf[index + 2] = plain[i];
      index += 3;
      for ( j = 0; j <= 9; ++j )
      {
        buf[index] = 0; 
        buf[index + 1] = 0;
        buf[index + 2] = magic[(10 * i + j) % 5];
        buf[index + 3] = 8; 
        buf[index + 4] = 1;
        buf[index + 5] = 3;
        buf[index + 6] = 3; 
        buf[index + 7] = 1;
        buf[index + 8] = 1; 
        buf[index + 9] = 1;
        buf[index + 10] = 0;
        buf[index + 11] = 2; 
        buf[index + 12] = 1;
        buf[index + 13] = 3;
        index += 14;
      }
      buf[index] = 4; 
      buf[index + 1] = 1;
      buf[index + 2] = i;
      index += 3;
    }
    buf[index] = 7; 
    runnnn(buf);
    washing_machine((char *)memory, plain_len);
    ...
}
```

그 다음 `washing_machine()`에 의해 변경된 `plain`의 값을 `buf`에 한 바이트씩 템플릿처럼 넣어준다.

이 `buf`는 `runnnn()`의 인자로 들어가고, 함수 내부에서는 값에 맞는 동작을 수행한다.

말하자면 바이너리는 사전 정의된 instruction set을 가지는 virtual machine이고, `buf`에 값을 넣어주는 행위는 shellcode를 만들어주는 동작이라고 보면 된다.

### Goal
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
    ...
    stream = fopen("hieroglyphs.txt", "r");
    if ( stream )
    {
      for ( k = 0; fgets(&symbols[256 * k], 256, stream) && k <= 255; ++k )
        *(&savedregs + 256 * k + strcspn(&symbols[256 * k], "\n") - (char *)&unk_12730) = 0;
      fclose(stream);
      for ( m = 0; m < plain_len; ++m )
        printf("%s", &symbols[256 * memory[m]]);
      putchar(10);
      exit(0);
    }
    perror("Failed to open hieroglyphs.txt");
    return 1;
    ...
}
```

연산이 끝나면 `hieroglyphs.txt`를 읽어서 왜인지 모르겠지만 256바이트마다 상형문자의 유니코드 값을 로드한다.

그리고 `memory`의 값을 읽어 그 값 번째의 상형문자를 출력해준다.

말이 어려운데, `memory[0]`에 저장된 값이 123이라고 하면 123번째 상형문자를 출력해준다.

따라서 목표는 어떤 plaintext를 입력해야 `message.txt`에 쓰여진 내용이 출력되는지 역산하는 것이다.

## 0x02. Exploit
Ciphertext가 생성되는 과정을 pseudocode로 나타내면 다음과 같다.

``` txt
tmp = washing_machine(plain)
shellcode = generate_shellcode(tmp)
runnnn(shellcode)
cipher = washing_machine(memory)
```

`generate_shellcode()`는 그렇다치고, `washing_machine()`과 `runnnn()`의 동작을 리버싱해야한다.

### washing_machine
``` c
unsigned __int64 __fastcall washing_machine(char *data, unsigned __int64 data_len)
{
  ...
  curr = *data;
  for ( i = 1LL; i < data_len; ++i )
  {
    next = curr ^ data[i];
    data[i] = next;
    curr = next;
  }
  for ( j = 0LL; ; ++j )
  {
    result = data_len >> 1;
    if ( j >= data_len >> 1 )
      break;
    tmp = data[j];
    data[j] = data[data_len - j - 1];
    data[data_len - j - 1] = tmp;
  }
  return result;
}
```

다음과 같이 크게 두 가지 연산을 한다.

1. `data[i] = data[i] ^ data[i + 1]`
2. 문자열 뒤집기

따라서 이 연산을 복호화하려면 다음과 같다.

``` python
def dewashing_machine(data):
    res = data[::-1]
    for i in range(len(res) - 1, 0, -1):
        res[i] = res[i] ^ res[i - 1]
    return res
```

### runnnn
``` c
int __fastcall runnnn(__int64 start)
{
  ...
  cnt = 0;
  flag = 1;
  while ( flag )
  {
    index = cnt++;
    opcode = *(index + start);
    switch ( opcode )
    {
      case 0u:                                  // mov regs[op1], op2
        op1 = *(start + cnt);
        op2 = *(start + cnt + 1);
        cnt += 2;
        regs[op1] = op2;
        break;
      ...
      default:
        LODWORD(v2) = puts("Invalid instruction");
        flag = 0;
        break;
    }
  }
}
```

`runnnn()`은 위와 같은데, 다 보기엔 너무 많으니 정리하자면 다음과 같다.

|opcode|instruction|
|------|-----------|
|0     |`mov regs[op1], op2`|
|1     |`xor regs[op1], regs[op2]`|
|2     |`rol regs[op1], op2`|
|3     |`sbox regs[op1]`|
|4     |`mov memory[op2], regs[op1]`|
|8     |`mov regs[op1], memory[op2]`|
|6     |`print regs[op1]`|
|7     |`exit`|
|8     |`ror regs[op1], op2`|

참고로 `sbox regs[op1]`은 `sbox`에서 `regs[op1]`에 담긴 값의 인덱스에 저장된 값을 가져오는 instruction이다.

이를 바탕으로 `buf`를 해석해보면 다음과 같다.

``` c
for ( i = 0; i < plain_len; ++i )
{
  mov regs[1], plain[i];
  for ( j = 0; j < 10; ++j )
  {
    mov regs[0], AA | BB | CC | DD | EE
    ror regs[1], 3
    sbox regs[1]
    xor regs[1], regs[0]
    rol regs[1], 3
  }
  mov memory[i], reg[1]
}
exit
```

따라서 이 연산을 복호화하려면 다음과 같다.

``` python
def nnnnur(data):
    res = []
    key = [0xEE, 0xDD, 0xCC, 0xBB, 0xAA]
    for d in data:
        for i in range(10):
            # ror 3
            d = ((d >> 3) | (d << 5)) & 0xff
            # xor EE | DD | CC | BB | AA
            d = d ^ key[i % 5]
            # inv_sbox
            d = sbox.index(d)
            # rol 3
            d = ((d << 3) | (d >> 5)) & 0xff
        res.append(d)
    return res
```

## 0x03. Payload
``` python
sbox = [
    0x48, 0x5c, 0xbc, 0x97, 0x81, 0x91, 0x60, 0xad, 0x94, 0xcb, 0x92, 0x39, 0x1a, 0xf,  0x30, 0x2d, 
    0x45, 0xde, 0x14, 0xa2, 0x8,  0x57, 0xb6, 0xae, 0x76, 0x8e, 0x87, 0x15, 0xc,  0xe7, 0x62, 0xc8, 
    0x58, 0x29, 0x6d, 0xc9, 0xa7, 0xbe, 0x4,  0x49, 0x5,  0xfa, 0x75, 0x9f, 0xfd, 0x95, 0xbb, 0x5b, 
    0x79, 0xbf, 0xda, 0xeb, 0x21, 0x9b, 0xa5, 0x82, 0x3a, 0x3e, 0xb9, 0x99, 0xf0, 0xf5, 0x6b, 0x6,
    0xfc, 0xaf, 0xf2, 0xb0, 0x78, 0x86, 0xcf, 0xd4, 0x83, 0x59, 0x0,  0x4a, 0xb5, 0xfe, 0xab, 0x3d, 
    0xc7, 0x8c, 0xe3, 0xc3, 0xe5, 0x3,  0x5a, 0x1d, 0x9d, 0x1f, 0xa,  0x56, 0xc0, 0xba, 0x43, 0x25, 
    0x77, 0x24, 0x7c, 0xa6, 0xdf, 0xf1, 0x4b, 0x44, 0xff, 0x4c, 0xaa, 0xc1, 0x69, 0xf9, 0x38, 0x88, 
    0x9a, 0xa4, 0xe6, 0x10, 0xdc, 0xea, 0x68, 0x8d, 0x5f, 0x63, 0xbd, 0x8b, 0xf3, 0x7e, 0xdb, 0x73, 
    0x5d, 0x65, 0x67, 0xa1, 0x72, 0xd8, 0xb1, 0x1b, 0x9e, 0x84, 0x16, 0x32, 0xe1, 0xf4, 0xef, 0x93, 
    0xac, 0x74, 0x36, 0x8f, 0xcc, 0x61, 0xd,  0x35, 0x12, 0xdd, 0x4e, 0xc4, 0x64, 0x3f, 0x9,  0x70, 
    0x2a, 0xfb, 0xc5, 0x85, 0x3b, 0x1c, 0x50, 0x19, 0xd5, 0xe9, 0x47, 0xb,  0xe2, 0xca, 0xc6, 0xf7, 
    0xb2, 0xd6, 0xf8, 0x11, 0x54, 0x6e, 0x90, 0xc2, 0xec, 0x96, 0x51, 0xd7, 0xe8, 0x31, 0x80, 0x7d, 
    0x18, 0x34, 0xb7, 0x2,  0xa0, 0x7a, 0xb3, 0xd0, 0x46, 0x66, 0x37, 0x1e, 0x7b, 0x42, 0x6c, 0x17, 
    0xd9, 0x33, 0x2b, 0x22, 0xce, 0xa9, 0x7f, 0xb4, 0x7,  0x6a, 0x41, 0x40, 0x26, 0x2f, 0xa8, 0xcd, 
    0x71, 0xb8, 0x53, 0x13, 0x5e, 0xf6, 0xe0, 0x52, 0x4f, 0x6f, 0xe4, 0x89, 0x3c, 0x9c, 0xa3, 0x8a, 
    0x4d, 0x28, 0xe,  0xd3, 0xd2, 0x98, 0xee, 0x2c, 0x2e, 0xed, 0x27, 0x20, 0x1,  0x23, 0x55, 0xd1
]

def get_cipher_index():
    with open("./hieroglyphs.txt") as f:
        h = f.readlines()
        h = [c[0] for c in h]

    with open("./message.txt") as f:
        m = f.read()

    res = []
    for c in m:
        if c == '\n':
            break
        res.append(h.index(c))

    return res

def dewashing_machine(data):
    res = data[::-1]
    for i in range(len(res) - 1, 0, -1):
        res[i] = res[i] ^ res[i - 1]
    return res

def nnnnur(data):
    res = []
    key = [0xEE, 0xDD, 0xCC, 0xBB, 0xAA]
    for d in data:
        for i in range(10):
            # ror 3
            d = ((d >> 3) | (d << 5)) & 0xff
            # xor EE | DD | CC | BB | AA
            d = d ^ key[i % 5]
            # inv_sbox
            d = sbox.index(d)
            # rol 3
            d = ((d << 3) | (d >> 5)) & 0xff
        res.append(d)
    return res

if __name__ == '__main__':
    data = get_cipher_index()
    data = dewashing_machine(data)
    data = nnnnur(data)
    data = dewashing_machine(data)
    print(data)
    print(''.join(chr(_) for _ in data))
```