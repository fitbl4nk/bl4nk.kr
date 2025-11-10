+++
title = "Attaching to gdb with pwntools"
date = "2024-05-31"
description = "How to attach a debugger to a process with python code"

[taxonomies]
tags = ["tools", "pwnable", "pwntools", "gdb"]

[extra]
pinned = true
+++

## 0x00. Introduction
When solving pwnable challenges, I primarily use `pwntools` for scripting and `gdb` for debugging.
Usually, you'd spawn a process and attach `gdb` from another terminal - but with `pwntools` and `tmux`, we can automate all of this within the script itself.


## 0x01. Debugging with pwntools
### Spawning Process
``` python
BINARY = ""
LIBRARY = ""

# for remote
s = remote(server, port)
# for local
s = process(BINARY, env={"LD_PRELOAD" : LIBRARY})
```

Use `remote` for remote, and `process` for local to run and connect to processes.
Especially, `remote` is used not only when connecting to actual servers but also when connecting to locally running docker.

### Open Debugger
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

The second argument takes a gdb script, so you can automate setting breakpoints and continuing code flow.

Also, you can attach debugger to a process inside of docker with `pid`, using the following script:

``` python
CONTAINER = ""

pid = os.popen(f"sudo docker top {CONTAINER} -eo pid,comm | grep {BINARY} | awk '{{print $1}}'").read()
gdb.attach(int(pid), gs, exe=BINARY)
```

With this script, it is possible to minimize the difference between local and remote environment.
However, errors can occasionally occur when inside and outside of container has permissions that don't match (see [Permission Error](#permission-error)).

### Set Terminal
You need to configure where the attached debugger shows up.
Simple enough with the `context` module's `terminal` variable - just pick your preferred layout:

``` python
context.terminal = ['tmux', 'splitw', '-h']     # split current window horizontally
context.terminal = ['tmux', 'splitw', '-v']     # split current window vertically
context.terminal = ['tmux', 'splitw', '-hf']    # split entire window horizontally
context.terminal = ['tmux', 'splitw', '-vf']    # split entire window vertically
```

I know it's pretty old-fashioned, but I've been using `tmux` since it's pretty clean.
You should also note that you're actually running inside a `tmux` session before executing the script (see [Tmux Session Error](#tmux-session-error)).


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
### Permission Error
``` bash
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.10
Reading symbols from challenge...
(No debugging symbols found in challenge)
Attaching to program: /home/user/challenge, process 165353
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
ptrace: Operation not permitted.
/home/user/challenge/165353: No such file or directory.
/tmp/pwnlib-gdbscript-kd8sfrgq.gdb:4: Error in sourced command file:
The program is not being run.
gef➤
```

When debugging a process inside of docker, the error above might occurs sometimes.
If we take a closer look at the error, it's something to do with permission.
Printing out the current process list is as follows:

``` bash
➜  ps -ef | grep challenge
root      165261  165241  0 16:01 ?        00:00:00 /bin/sh -c socat TCP-LISTEN:8794,reuseaddr,fork EXEC:/home/ctf/challenge
root      165284  165261  0 16:01 ?        00:00:00 socat TCP-LISTEN:8794,reuseaddr,fork EXEC:/home/ctf/challenge
root      165521  165284  0 16:05 ?        00:00:00 socat TCP-LISTEN:8794,reuseaddr,fork EXEC:/home/ctf/challenge
root      165524  165521  0 16:05 ?        00:00:00 /home/ctf/challenge
user      165545   66182  0 16:05 pts/9    00:00:00 /usr/bin/gdb -q challenge 165524 -x /tmp/pwnlib-gdbscript-webj6wb7.gdb
```

The debugger opened via python script is executed with `user` permission, whereas the target process `challenge` is executed with `root` permission.
In this case attaching to the process fails, so the following lines should be added to `Dockerfile`.

``` docker
RUN /usr/sbin/useradd -u 1000 ctf
USER ctf
```

You should note that the `uid` above should be identical with the `user`'s, who is running the python script.
In the case of Ubuntu 24.04, for example, the user `ubuntu` is preempting `uid` 1000, possibly causing error because a new user will have `uid` 1001.

### Tmux Session Error
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

``` bash
➜  tmux
➜  python3 exploit.py
```