+++
title = "TFC CTF 2024 - VIRTUAL-REV"
date = "2025-03-26"
description = "TFC CTF 2024 reversing challenge"

[taxonomies]
tags = ["ctf", "reversing", "virtual machine"]
+++

## 0x00. Introduction
``` bash
➜  file virtual-rev
virtual-rev: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f76d6fbdb37632d0860645824c3e3bb5e3df31c7, for GNU/Linux 3.2.0, stripped
```

## 0x01. Conecpt
``` c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  ...
  reg_info_1AEC(&reg);
  puts("