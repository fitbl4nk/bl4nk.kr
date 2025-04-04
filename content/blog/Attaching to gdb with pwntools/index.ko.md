+++
title = "pwntools로 gdb 연결하기"
date = "2024-05-31"
description = "python 코드로 프로세스 디버거에 붙이기"

[taxonomies]
tags = ["tools", "pwnable", "pwntools", "gdb"]
+++

## 0x00. Introduction
pwnable 문제를 풀 때 스크립트 작성을 위해 `pwntools`를 주로 사용하고, 디버깅을 위해 `gdb`를 주로 사용하게 된다.
일반적으로 프로세스를 생성하고 다른 터미널에서 `gdb`를 붙이는데, `pwntools`와 `tmux`를 이용해서 스크립트 내에서 이 작업을 자동화할 수 있다.

## 0x01. Debugging with pwntools
### Attach process
`pwntools`에서 제공하는 `gdb` 모듈의 `attach` 함수를 이용해서 실행중인 프로세스에 디버거를 연결할 수 있다.

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

이 때 두번째 인자에 gdb script를 넣을 수 있어서 `breakpoint`를 잡고 `continue`하는 과정도 자동화할 수 있다.

### Set terminal
연결한 디버거를 어디에 표시할지 설정이 필요하다.
간단하게 `context` 모듈의 `terminal` 변수를 통해서 설정해줄 수 있는데, 마음에 드는 모양을 선택하면 된다.

``` python
context.terminal = ['tmux', 'splitw', '-h']     # 현재 창을 세로로 분리
context.terminal = ['tmux', 'splitw', '-v']     # 현재 창을 가로로 분리
context.terminal = ['tmux', 'splitw', '-hf']    # 전체 창을 세로로 분리
context.terminal = ['tmux', 'splitw', '-vf']    # 전체 창을 가로로 분리
```

`tmux`를 쓰는게 꽤 깔끔해서 채용중인데, 다만 주의할 것이 꼭 `tmux` 세션을 열고 스크립트를 실행해야 한다.([Troubleshooting](#0x03-troubleshooting) 참고)

## 0x02. Conclusion
결과적으로 다음 스크립트를 `exploit.py` 포맷처럼 사용하고 있다.

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

`main`에 세 개의 인자가 전달되는데, 먼저 `-p` 혹은 `--port` 인자가 있으면 `remote`를 이용해서 실행하고, 없으면 로컬에서 디버깅을 하게끔 구성했다.

``` bash
➜  python3 exploit.py -p 7777
➜  python3 exploit.py --port 7777
```

그리고 디버깅이 더 이상 필요 없을 경우 `-d` 혹은 `--debug` 인자에 0을 전달해주면 디버깅 없이 실행하게 된다.

``` bash
➜  python3 exploit.py -d 0
➜  python3 exploit.py --debug 0
```

마지막으로 실제 서버에 payload를 전송하기 위해서는 `-s` 혹은 `--server` 인자에 서버 도메인이나 IP를 전달해주면 되는데, 이 때 디버깅은 꺼주는게 좋다.

``` bash
➜  python3 exploit.py -s server.com -d 0
➜  python3 exploit.py --server x.x.x.x --debug 0
```

참고로, `from pwn import *`을 해놓고 두 번째 줄에서 굳이 또 packing 함수들을 import 하는 이유는 vscode에서 이상하게 packing 함수들을 못찾아서 underline이 생기기 때문에 단순히 보기 좋으라고 추가한 것이다.

## 0x03. Troubleshooting
### Tmux session error
처음에 스크립트를 실행했을 때 발생한 오류이다.

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

`gdb.attach(s, gs)`에서 발생한 자료형 관련 에러라서 pid 데이터 타입이 안맞는건가 싶어서 한참을 헤맸는데 아예 다른 문제였다.
위 스크립트를 실행하면 `tmux` 세션에 터미널을 생성해서 스크립트를 실행하게 되는데 존재하는 `tmux` 세션이 없어서 발생하는 에러였다.
나는 알아서 세션 생성해서 연결할 줄 알았지...

```
➜  tmux
➜  python3 exploit.py
```
