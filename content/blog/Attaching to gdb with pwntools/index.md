+++
title = "Attaching to gdb with pwntools"
date = "2024-05-31"
description = "How to attach a debugger to a process with python code"

[taxonomies]
tags = ["tools", "pwnable", "pwntools", "gdb"]
+++

## 0x00. Introduction
I mostly use `pwntools` for solving pwnable challenges, and `gdb` for debugging.
In general I had to run a process and attach to the process in another terminal, but I could automate this procedure in python code with `pwntools` and `tmux`.


## 0x01. Debugging with pwntools
### Attach process
The `attach` function of `gdb` module in `pwntools` lets us attach to a running process.

``` python
bp = {
    'main' : 0x555555555249,
    'end_of_main' : 0x5555555552d3,
    'foo' : 0x55555555566f,
}

gs = f'''
b *{bp['main']}
continue
'''

gdb.attach(s, gs)
```

If gdb script was given to the second argument, making `breakpoints` and running `continue` can also be automated.

### Set terminal
We can set where to display the attached debugger.
The `terminal` variable of `context` module decides where and how to display, you can choose whatever you want.

``` python
context.terminal = ['tmux', 'splitw', '-h']     # split current window horizontally
context.terminal = ['tmux', 'splitw', '-v']     # split current window vertically
context.terminal = ['tmux', 'splitw', '-hf']    # split entire window horizontally
context.terminal = ['tmux', 'splitw', '-vf']    # split entire window vertically
```

Using `tmux` is old-fashioned, but still powerful. You should note that the python code should be run after `tmux` session was opened. (refer to [Troubleshooting](#0x03-troubleshooting).)


## 0x02. Conclusion
For now I'm using the following code as a template for pwnable.

``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
from time import sleep
from argparse import ArgumentParser

BINARY = ""
LIBRARY = ""
CONTAINER = ""
code_base = 0x555555554000
bp = {
    'main' : code_base + 0x16ae,
}

gs = f'''
b *{bp["main"]}
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

    s.interactive()

if __name__=='__main__':
    parser = ArgumentParser()
    parser.add_argument('-s', '--server', type=str, default="0.0.0.0")
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-d', '--debug', type=int, default=1)
    args = parser.parse_args()
    main(args.server, args.port, args.debug)
```

There are three arguments given to `main` function.
First, if `-p` or `--port` was given, it uses `remote` to connect to the server and if not, it attaches local process.

``` bash
➜  python3 exploit.py -p 7777
➜  python3 exploit.py --port 7777
```

And if debugging is not needed anymore, give `-d` or `--debug` option and set 0 like the following. Then it will execute without debugging.

``` bash
➜  python3 exploit.py -d 0
➜  python3 exploit.py --debug 0
```

For sending payload to the actual server, give `-s` or `--server` option and set the domain or IP address of the server, without debugging.

``` bash
➜  python3 exploit.py -s server.com -d 0
➜  python3 exploit.py --server x.x.x.x --debug 0
```

FYI, the reason for importing the functions related to the packing again after `from pwn import *` is simply because vscode couldn't find the definition of these functions for no reason.


## 0x03. Troubleshooting
### Tmux session error
This error occurred when I ran the code for the first time.

``` bash
➜  python3 exploit.py
[+] Starting local process './challenge': pid 3886107
[*] running in new terminal: ['/usr/bin/gdb', '-q', './challenge', '3886107', '-x', '/tmp/pwnjmmmxq9k.gdb']
Traceback (most recent call last):
  File "/home/user/exploit.py", line 133, in <module>
    main()
  File "/home/user/exploit.py", line 60, in main
    gdb.attach(s, gs)
  File "/home/user/.local/lib/python3.10/site-packages/pwnlib/context/__init__.py", line 1581, in setter
    return function(*a, **kw)
  File "/home/user/.local/lib/python3.10/site-packages/pwnlib/gdb.py", line 1100, in attach
    gdb_pid = misc.run_in_new_terminal(cmd, preexec_fn = preexec_fn)
  File "/home/user/.local/lib/python3.10/site-packages/pwnlib/util/misc.py", line 413, in run_in_new_terminal
    pid = int(out)
ValueError: invalid literal for int() with base 10: b''
[*] Stopped process './challenge' (pid 3886107)
```

At first, I thought the error was something to do with the type of the pid because it occurred in `gdb.attach(s, gs)` and was ValueError, but it was a completely different problem.
This error occurs because there is no existing `tmux` session, though the code creates a terminal in a `tmux` session.

I thought it would make one if there isn't :p

```
➜  tmux
➜  python3 exploit.py
```
