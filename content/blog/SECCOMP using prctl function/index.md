+++
title = "[SECCOMP] SECCOMP using prctl function"
date = "2024-06-15"
description = "From usage of prctl function to related tool and expected vulnerailities"

[taxonomies]
tags = ["study", "linux", "seccomp", "mitigation"]
+++

## 0x00. Introduction
The SECCOMP (SECure COMPuting mode) is a feature of Linux kernel that provides sandboxing of process.
In detail, it restricts the syscalls that are executed in the process, and terminates the process (SIGKILL) if a syscall is not allowed one.
Unlike other mitigations, it is not applied at compile time, but rather at run time.

It seems that it was activated through the value of the `/proc/<pid>/seccomp` in the past, but it had been changed to be set through `prctl` or `sys_seccomp`.(I don't know since when...)

In this post, I will describe the SECCOMP using the `prctl` function.


## 0x01. prctl function
``` c
int prctl(int option, ...
            /* unsigned long arg2, unsigned long arg3,
            unsigned long arg4, unsigned long arg5 */ );
```

The `prctl` function is a function for managing the properties of processes or threads (PRocess ConTroL).
In addition to applying SECCOMP, which will be explained in detail, it can be used to obtain the process name or the endian information.
Basically it receives a variable number of arguments and operates according to the desired action.

``` c
/* Values to pass as first argument to prctl() */
#define PR_SET_PDEATHSIG  1  /* Second arg is a signal */
#define PR_GET_PDEATHSIG  2  /* Second arg is a ptr to return the signal */
/* Get/set current->mm->dumpable */
#define PR_GET_DUMPABLE   3
#define PR_SET_DUMPABLE   4
/* Get/set unaligned access control bits (if meaningful) */
#define PR_GET_UNALIGN    5
#define PR_SET_UNALIGN    6
/* Set/Get process name */
#define PR_SET_NAME    15
#define PR_GET_NAME    16
/* Get/set process endian */
#define PR_GET_ENDIAN   19
#define PR_SET_ENDIAN   20
/* Get/set process seccomp mode */
// -----------------------------------------
#define PR_GET_SECCOMP  21                // |
#define PR_SET_SECCOMP  22                // |
#define PR_SET_NO_NEW_PRIVS     38        // |
#define PR_GET_NO_NEW_PRIVS     39        // |
// -----------------------------------------
```

In the `prctl.h`, you can check the values of the macros that go into the first argument, `option`.
Among them, let's take a closer look at `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECCOMP`, which are related to the SECCOMP.

### PR_SET_NO_NEW_PRIVS
``` c
int prctl(PR_SET_NO_NEW_PRIVS, int value);
```

The example above sets the `no_new_privs` property of the current process as `value`.

This property can be checked in the `NoNewPrivs` field of `/proc/<pid>/status` since the Linux kernel 4.10.
If the value of this property is set to 1, the current process and it's child processes cannot execute codes that grant new privileges.
However, they can still execute codes that revoke privileges.

The importance of this property will be described in the [SECCOMP_MODE_FILTER](#seccomp-mode-filter) part.

### PR_SET_SECCOMP
``` c
int prctl(PR_SET_SECCOMP, int mode, [...]);
```

Now, we come to the actual control of SECCOMP, which has two modes.

``` c
 /* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
 #define SECCOMP_MODE_DISABLED   0 /* seccomp is not in use. */
 #define SECCOMP_MODE_STRICT 1 /* uses hard-coded filter. */
 #define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */
```

In the `seccomp.h`, each mode is defined as a macro.

#### SECCOMP_MODE_STRICT
In this mode, only four syscalls are allowed: `read`, `write`, `exit`, and `sigreturn`. The third argument is not necessary because the available syscalls are already defined.

``` c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

int main() {
        int fd;
        char buf[16] = {0};

        if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) != 0) {
                perror("SET_SECCOMP error");
        }

        read(0, buf, 16);
        write(1, buf);

        fd = open("a.txt", 'w');
        write(fd, buf);
        close(fd);

        return 0;
}
```

As a result of compiling and executing the code above, `SIGKILL` occurred in `open` like the following.

``` bash
$ ./strict
hihi
hihi
[1]    517393 killed     ./strict
```

#### SECCOMP_MODE_FILTER
This is a mode that the user builds a rule set to block certain syscalls.
The filter mode can be executed only when `no_new_privs` property is set via the `PR_SET_NO_NEW_PRIVS`.

The rule set is an assembly-like syntax called Berkeley Packet Filter (BPF), which will be covered in detail in the [seccomp-tools](#0x02-seccomp-tools) section.
The following is an example code of filtering out `write` syscalls.


``` c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>

static unsigned char filter[] = {
    32, 0, 0, 0, 0, 0, 0, 0,    // A = sys_number
    21, 0, 1, 0, 1, 0, 0, 0,    // if (A == write) goto 0003
    6, 0, 0, 0, 0, 0, 255, 127,    // return ALLOW
    6, 0, 0, 0, 0, 0, 0, 0        // return KILL
}

struct sock_fprog {
    unsigned short len;
    unsigned char *filter;
};

int main() {
    int fd;
    char buf[16] = {0};
    struct sock_fprog prog;

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("SET_NO_NEW_PRIVS error");
    }

    prog.len = sizeof(filter) / 8;
    prog.filter = filter;

    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("SET_SECCOMP error");
    }

    read(0, buf, 16);
    write(1, buf);          // <----- This will be blocked

    fd = open("a.txt", 'w');
    write(fd, buf);
    close(fd);

    return 0;
}
```

As a result of compiling and executing the code above, `SIGSYS` occurred in `open` like the following.

``` bash
$ ./filter
hihi
[1]    669145 invalid system call (core dumped)  ./filter
```

I tried to debug the process because it printed a different message from the `SIGKILL` message of the strict mode, and I found that the process was terminated by `SIGSYS` in filter mode.


## 0x02. seccomp-tools
Looking at the example code of `SECCOMP_MODE_FILTER`, you need to change the filtering rule into bytecodes and put them in the `filter` array.
However, even if you are an expert, it is difficult to freely convert the desired BPF rule into bytecodes.
In this case, seccomp-tools is a good tool to use.

``` bash
$ sudo apt install gcc ruby-dev -y
$ gem install seccomp-tools
```

You can install seccomp-tools like the above.

``` bash
$ seccomp-tools
Usage: seccomp-tools [--version] [--help] <command> [<options>]

List of commands:

        asm     Seccomp bpf assembler.
        disasm  Disassemble seccomp bpf.
        dump    Automatically dump seccomp bpf from execution file(s).
        emu     Emulate seccomp rules.

See 'seccomp-tools <command> --help' to read about a specific subcommand.
```

As you can see in the usage, there are commands like `asm`, `disasm`, `dump`, and `emu`.

### asm
This command converts BPF rules written like the following to bytecodes.

``` txt
A = arch
if (A != ARCH_X86_64) goto dead
A = sys_number
if (A >= 0x40000000) goto dead
if (A == write) goto ok
if (A == close) goto ok
if (A == dup) goto ok
if (A == exit) goto ok
return ERRNO(5)
ok:
return ALLOW
dead:
return KILL
```

The variable `A` appeared out of nowhere, so I wondered what it was at first, but it's easier to think of it as just a variable.

Now, you can save this content as a file and pass it to the argument of seccomp-tools.

``` bash
$ seccomp-tools asm rule.txt
" \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\b>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x005\x00\x06\x00\x00\x00\x00@\x15\x00\x04\x00\x01\x00\x00\x00\x15\x00\x03\x00\x03\x00\x00\x00\x15\x00\x02\x00 \x00\x00\x00\x15\x00\x01\x00<\x00\x00\x00\x06\x00\x00\x00\x05\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F\x06\x00\x00\x00\x00\x00\x00\x00"

$ seccomp-tools asm rule.txt -f c_array
unsigned char bpf[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,1,0,0,0,21,0,3,0,3,0,0,0,21,0,2,0,32,0,0,0,21,0,1,0,60,0,0,0,6,0,0,0,5,0,5,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};

$ seccomp-tools asm rule.txt -f c_source
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
static void install_seccomp() {
  static unsigned char filter[] = {32,0,0,0,4,0,0,0,21,0,0,8,62,0,0,192,32,0,0,0,0,0,0,0,53,0,6,0,0,0,0,64,21,0,4,0,1,0,0,0,21,0,3,0,3,0,0,0,21,0,2,0,32,0,0,0,21,0,1,0,60,0,0,0,6,0,0,0,5,0,5,0,6,0,0,0,0,0,255,127,6,0,0,0,0,0,0,0};
  struct prog {
    unsigned short len;
    unsigned char *filter;
  } rule = {
    .len = sizeof(filter) >> 3,
    .filter = filter
  };
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("prctl(PR_SET_NO_NEW_PRIVS)"); exit(2); }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) < 0) { perror("prctl(PR_SET_SECCOMP)"); exit(2); }
}
```

As you can see from the example above, you can output the results in various formats. The `-f` option provides ready-to-use formats such as `raw`, `c_array`, `c_source`, and `assembly`.

### disasm
The opposite command of `asm`. It converts BPF in bytecode format to filtering rules.
You can give the file where the bytecodes are saved as an input file as an argument.

``` bash
$ xxd rule.raw
00000000: 2000 0000 0400 0000 1500 0008 3e00 00c0   ...........>...
00000010: 2000 0000 0000 0000 3500 0600 0000 0040   .......5......@
00000020: 1500 0400 0100 0000 1500 0300 0300 0000  ................
00000030: 1500 0200 2000 0000 1500 0100 3c00 0000  .... .......<...
00000040: 0600 0000 0500 0500 0600 0000 0000 ff7f  ................
00000050: 0600 0000 0000 0000                      ........

$ seccomp-tools disasm rule.raw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
 0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL

$ seccomp-tools asm rule.txt -f raw | seccomp-tools disasm -
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
 0004: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0009
 0005: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0009
 0006: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0009
 0007: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0009
 0008: 0x06 0x00 0x00 0x00050005  return ERRNO(5)
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

By pipelining the `asm` command, you can check whether the BPF rule is written correctly.

### dump
This is a command that outputs the BPF rules applied within the binary.
I looked up how it works out of curiosity, and it seems to analyze the binary dynamically using `ptrace`.

However, since it prints the rules based on the first `prctl(PR_SET_SECCOMP)`, it may be different from the actual result if the `prctl` function was called multiple times.

In that case, you can increase the number of `prctl` functions to be checked by giving the `-l` or `--limit` option.

You can also give the `-p` or `--pid` option to check the rules applied to the running process.

``` bash
$ seccomp-tools dump ./filter
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000000  return KILL

$ sudo seccomp-tools dump -p `pgrep filter`
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000000  return KILL
```

You can use the `dump` command like this.

### emu
The `emu` is a good command to check whether syscalls are properly called or blocked by emulating rule sets.
When ran in `bash`, the output is colored and easy to check.

![image](./image.png)

![image](./image-1.png)


## 0x03. Expected Vulnerability
Of course, it depends on how it was coded, but I thought about vulnerabilities that could occur easily.

### x32 Syscall
In the previous example of `disasm` command in seccomp-tools, there were rules like these.

``` txt
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x06 0x00 0x40000000  if (A >= 0x40000000) goto 0010
```

The `0001` line is the logic to check if the architecture is `X86_64`, then why does it check if the `sys_number` of the `0003` line is greater than `0x40000000`?

The reason is the compatibility of the `X86_64` architecture.
It was developed for the instructions used in the previous 32-bit to be also used in the 64-bit architecture, and this whole concept is called the x32 ABI.
Therefore, 32-bit syscalls can be called in the 64-bit architecture, and the method for doing so is to add `0x40000000` to the 64-bit syscall number in Linux.

Let's look at the code of the `do_syscall_x32` function that is called when a 32-bit syscall is actually called in the Linux kernel.

``` c
static __always_inline bool do_syscall_x32(struct pt_regs *regs, int nr)
{
    /*
     * Adjust the starting offset of the table, and convert numbers
     * < __X32_SYSCALL_BIT to very high and thus out of range
     * numbers for comparisons.
     */
    unsigned int xnr = nr - __X32_SYSCALL_BIT;
    if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(xnr < X32_NR_syscalls)) {
        xnr = array_index_nospec(xnr, X32_NR_syscalls);
        regs->ax = x32_sys_call_table[xnr](regs);
        return true;
    }
    return false;
}
```

In the first line of the function, `xnr = nr - __X32_SYSCALL_BIT` is executed, and the `__X32_SYSCALL_BIT` value is predefined value `0x40000000`.

Therefore, if there is no logic to verify that the syscall number is less than `0x40000000` in the BPF rule of a 64-bit binary, even if a specific syscall is blocked, you can still call the syscall of the 32-bit architecture by adding `0x40000000` to the syscall number using the x32 ABI.

### Filter Overwrite
The simplest idea that comes to mind is that it is a vulnerability that can occur when the BPF filter rule part in memory can be overwritten with a desired value before SECCOMP is set. There are ways to do this, such as changing the rule to allow calling the desired syscall, or overwriting the rule with `return ALLOW`.

There is a related challenge on [dreamhack.io](https://dreamhack.io), which I recommend trying.

### SECCOMP Bypass
I found out while using `PR_SET_SECCOMP` that if the BPF rule is slightly wrong, the prctl function only returns an error and does not terminate the process.

``` bash
$ cat wrong.txt
A = sys_number
if (A == write) goto 3
return ALLOW
return KILL

$ seccomp-tools asm wrong.txt -f raw | seccomp-tools disasm -
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0005
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x06 0x00 0x00 0x00000000  return KILL
```

Here is an example of a wrong BPF rule. If you look closely, you will see that it says goto 0005 on line 0001.
When composing `wrong.txt`, I thoughtlessly set line of `goto` as 3 where `return KILL` is located, but I found out that I had to calculate the line as a relative address.

For example, if `goto 0` is on the current line 0001, it is interpreted as going to the next line, 0002; and if it's `goto 1`, it is interpreted as going to the next next line, 0003. So `goto 3` becomes a command to go to line 0005.
Since line 0005 does not exist in `wrong.txt`, an error occurs when passing it as an option to `prctl`.

``` bash
$ ./filter
SET_SECCOMP error: Invalid argument
hihi
hihi
```

When the wrong rule is applied, a SECCOMP error occurs like this.
As a result, the rule that was supposed to block the `write` syscall was not applied, so the input string was output to `STDOUT`.

Therefore, even if the entire filter cannot be overwritten like [Filter Overwrite](#filter-overwrite), if the rule itself can be made nonsensical with a few bytes, an error will occur, but the process will be maintained, so SECCOMP bypass is possible.


## 0x04. References
 - [https://man7.org/linux/man-pages/man2/prctl.2.html](https://man7.org/linux/man-pages/man2/prctl.2.html)
 - [https://jeongzero.oopy.io/06eebad5-8306-493f-9c6d-e7a04d5aacff](https://jeongzero.oopy.io/06eebad5-8306-493f-9c6d-e7a04d5aacff)
- [https://velog.io/@woounnan/LINUX-Seccomp](https://velog.io/@woounnan/LINUX-Seccomp)
- [https://velog.io/@dandb3/SECCOMP2](https://velog.io/@dandb3/SECCOMP2)
- [https://learn.dreamhack.io/280](https://learn.dreamhack.io/280)
- [https://github.com/david942j/seccomp-tools](https://github.com/david942j/seccomp-tools)