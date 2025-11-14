+++
title = "Setting up Windows for pwnable"
date = "2025-01-15"
description = "Useful tools and settings for pwnable"

[taxonomies]
tags = ["tools", "pwnable", "setting", "wsl", "vscode"]
+++

## 0x00. Introduction
After purchasing a new desktop and frequently reconfiguring the environment due to driver issues, I thought it would be nice to document the setup process for reference.
The installation environment is Windows 11 + Ubuntu(WSL).

I'll add more useful settings or tools as I discover them.


## 0x01. Windows
### WSL
In `Turn Windows Features On or Off`, check the following items.

![wsl](https://github.com/user-attachments/assets/8cb36560-c5a5-43e1-8a4d-cbae336fdf34)

After restarting, execute these commands in the terminal.

``` powershell
# Install WSL
wsl --install

# Check available packages and versions
wsl --list --online

# Specific version
wsl --install -d Ubuntu-[xx.xx]
# Latest version
wsl --install -d Ubuntu
```

### Visual Studio Code
#### Theme Settings
After installing the desired theme, press `ctrl + shift + p` -> `Preferences: Color Theme` -> `Browse Additional Color Themes...` to select it.

#### Keyboard Shortcuts
Press `ctrl + shift + p` -> `Preferences: Open Keyboard Shortcuts(JSON)` and paste the following.
This is good when switching between editor and terminal.

``` json
[
    {
        "key":     "ctrl+`",
        "command": "workbench.action.terminal.focus"
    },
    {
        "key":     "ctrl+`",
        "command": "workbench.action.focusActiveEditorGroup",
        "when":    "terminalFocus"
    }    
]
```

This is more convenient when switching between multiple windows.

``` json
[
    {
        "key": "ctrl+`",
        "command": "workbench.action.focusNextGroup"
    }
]
```

### VMware
You need to register on the [Broadcom official website](https://support.broadcom.com/).
I had trouble because the verification email didn't arrive when I thoughtlessly used my university email, so just use `gmail.com` to be safe.

- After logging in, select `Software` -> `VMware Cloud Foundation` -> `My Downloads`
- Find `VMware Workstation Pro` and select the desired release
- Note that you must check `I agree to the Terms and Conditions` to enable the download button

Fill in the address field that appears and click the download button again to complete the installation.

### IDA Free
While it only supports x86/x86-64 architectures, IDA is now available for free.
On the [hex-rays official website](https://hex-rays.com/), select `Products` -> `IDA Free` and receive a license through email verification.

It seems fine now, but I once had an experience where it was too slow, and using a VPN to Belgium (where their headquarters is) made it much faster.

### shell:sendto
Typing `shell:sendto` in the `win + r` run window lets you register programs that appear in the `send to` menu when right-clicking files.

![shell_sendto](https://github.com/user-attachments/assets/fd79c254-35f6-48cc-85d4-5a0d8dcc8332)

For example, create an IDA shortcut and place it in that folder.
Then right-click a binary and select IDA from `send to` to analyze it directly.
It's a bit inconvenient in Windows 11 since you need to press `Show more options` to see it, but it's quite useful.

You can apparently edit the registry to revert to the Windows 10 menu, but I skipped it to keep the new computer feeling.


## 0x02. Linux
### Packages
``` bash
# initialize
sudo apt update
sudo apt upgrade -y

# oh my zsh
sudo apt install zsh git -y
sh -c "$(wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O -)"

# zsh plugins
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions zsh-syntax-highlighting)/' ~/.zshrc
source .zshrc

# python packages
sudo apt install python3-pwntools -y

# one gadget
sudo apt install ruby -y
sudo gem install one_gadget

# gef
bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

### jekyll
``` bash
# Install dependencies
sudo apt install ruby-full build-essential zlib1g-dev -y

# Change the file according to your shell
echo '# Install Ruby Gems to ~/.gems' >> ~/.zshrc
echo 'export GEM_HOME="$HOME/.gems"' >> ~/.zshrc
echo 'export PATH="$HOME/.gems/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Install jekyll
gem install jekyll bundler

# Execute in jekyll directory such as github.io repository
cd fitbl4nk.github.io
bundle install
```

### zola
``` bash
# Download the latest version of zola (https://github.com/getzola/zola/releases)
wget https://github.com/getzola/zola/releases/download/v0.20.0/zola-v0.20.0-x86_64-unknown-linux-gnu.tar.gz
rm zola-v0.20.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv zola /usr/local/bin

# Execute in zola directory such as github.io repository
cd bl4nk.kr
zola serve
```