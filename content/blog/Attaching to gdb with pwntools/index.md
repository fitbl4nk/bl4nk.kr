+++
title = "Attaching to gdb with pwntools"
date = "2024-05-31"
description = "How to attach a debugger to a process with python code"

[taxonomies]
tags = ["tools", "pwnable", "pwntools", "gdb"]
+++

## 0x00. Introduction
When solving pwnable challenges, I primarily use `pwntools` for scripting and `gdb` for debugging.
Usually, you'd spawn a process and attach `gdb` from another terminal - but with `pwntools` and `tmux`, we can automate all of this within the script itself.


## 0x01. Debugging with pwntools
### Attach process
The `attach` function from pwntools' `gdb` module lets you attach a debugger to a running process:

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

The second argument takes a gdb script, so you can automate setting breakpoints and continuing execution.

### Set terminal
You need to configure where the attached debugger shows up.
Simple enough with the `context` module's `terminal` variable - just pick your preferred layout:

``` python
context.terminal = ['tmux', 'splitw', '-h']     # split current window horizontally
context.terminal = ['tmux', 'splitw', '-v']     # split current window vertically
context.terminal = ['tmux', 'splitw', '-hf']    # split entire window horizontally
context.terminal = ['tmux', 'splitw', '-vf']    # split entire window vertically
```

I know it's pretty old-fashioned, but I've been using `tmux` since it's pretty clean.
The one thing you should notice is make sure you're actually running inside a `tmux` session before executing the script (see [Troubleshooting](#0x03-troubleshooting)).


## 0x02. Conclusion
Here's the final script I use as my `exploit.py` template:

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

The `main` function takes three arguments.
If `-p` or `--port` is provided, it connects remotely.
Otherwise, it runs locally for debugging:

``` bash
➜  python3 exploit.py -p 7777
➜  python3 exploit.py --port 7777
```

When you're done debugging, pass 0 to `-d` or `--debug` to run without a debugger:

``` bash
➜  python3 exploit.py -d 0
➜  python3 exploit.py --debug 0
```

Finally, to hit the actual server, pass the domain or IP to `-s` or `--server` - and definitely disable debugging:

``` bash
➜  python3 exploit.py -s server.com -d 0
➜  python3 exploit.py --server x.x.x.x --debug 0
```

Side note: I'm already doing `from pwn import *`, but I explicitly import the packing functions again on line 2 because vscode doesn't seem to find them.
Otherwise it shows annoying underlines.


## 0x03. Troubleshooting
### Tmux session error
This is what greeted me when I first ran the script:

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

The error hit at `gdb.attach(s, gs)` with a type issue, so I spent way too long thinking it was a pid datatype mismatch.
Turns out it was something completely different.

The script tries to create a terminal in a `tmux` session - but there was no active `tmux` session to attach to.
I naively assumed it would just create one automatically...

```
➜  tmux
➜  python3 exploit.py
```
