+++
title = "가상머신에 IDA MCP Server 구축하고 LLM 연결하기 (feat. Gemini CLI)"
date = "2025-12-10"
description = "게스트(IDA)와 호스트(Gemini CLI) 분리를 통한 효율적인 병행 분석 환경 구축"

[taxonomies]
tags = ["tools", "pwnable", "reversing", "ida", "mcp", "llm"]
+++

## 0x00. Introduction
MCP는 Model Context Protocol으로 AI가 다른 시스템과 통신하기 위한 규약이다.
이 MCP를 이용하면 LLM이 PC나 데이터베이스와 같은 저장소, 검색 엔진이나 계산기같은 도구 등과 연결되어 복잡하고 가치있는 작업을 수행할 수 있다.
비유적으로는 **AI를 위한 USB-C 포트**라는 표현이 자주 쓰인다.

hex-rays 공식 플러그인도 있지만 star가 더 많은 [github](https://github.com/mrexodia/ida-pro-mcp)을 기준으로 작성했다.
또한 agent에게 작업을 맡겨두고, 나 또한 자유롭게 분석을 병행할 수 있도록 가상머신을 사용하여 MCP 서버를 구축하는 환경을 기준으로 작성했다.


## 0x01. Install
### Guest
앞서 언급했듯이 MCP 서버를 가상머신 내에 구성할 것이다.
IDA를 실행할 수 있는 OS (MacOS, Linux, Windows) 중 아무거나 환경을 구축하면 되는데, 나는 Windows 10 x64 환경을 구축했다.

#### Python
3.11 혹은 더 높은 버전이 필요하다.
보통 IDA를 설치할 때 python이 없으면 같이 설치되는데, 최신 기준으로는 모르겠으나 내 IDA 버전에서는 3.10을 설치한다.
어차피 가상머신 안에서 돌릴 것이기 때문에 미리 설치해두는게 훨씬 편하다.

개인적으로 `C:\Python\Python[VER]`에 설치하는 편인데, 주의할 것은 시스템 환경변수 `PATH`에 해당 경로가 추가되어 있어야 한다.
내 기준으로는 다음과 같다.

 - `C:\Python\Python314\`
 - `C:\Python\Python314\Scripts\`

#### IDA Pro
Github에서는 IDA Pro 8.3 버전이나 그 이상 혹은, 9 버전을 추천한다.
그리고 IDA Free는 지원되지 않는다고 되어있는데, 지인의 정보에 따르면 개인 플랜인 IDA Home에서도 지원된다고 한다.

설치 시 python 설치를 해제해야 이미 설치되어 있는 python을 찾기 때문에 꼭 해제해주어야 한다.

#### IDA MCP
자세한 MCP 서버 설치 방법은 [github](https://github.com/mrexodia/ida-pro-mcp?tab=readme-ov-file#installation)을 참고하면 된다.

``` cmd
pip uninstall ida-pro-mcp
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip

ida-pro-mcp --install
```

설치 후 IDA 메뉴에서 `Edit` -> `Plugins` -> `MCP`를 선택했을 때 Output에 다음과 같이 나오면 성공이다.

``` txt
[MCP] Server started:
  Streamable HTTP: http://127.0.0.1:13337/mcp
  SSE: http://127.0.0.1:13337/sse
  Config: http://127.0.0.1:13337/config.html
```

`127.0.0.1`로 열리기 때문에 호스트와 통신을 위해서 포트 포워딩을 설정해도 되지만 그냥 다음 명령어를 실행해도 된다.

``` cmd
ida-pro-mcp --transport http://0.0.0.0:13337/sse
```

### Host
사실 AI 어플리케이션도 게스트에 설치하면 간단하다.
하지만 호스트에서 어차피 어플리케이션을 자주 쓰기도 하고 이게 조금 더 빠른 것 같아 게스트와 호스트를 분리했다.

호스트는 Windows 11 + WSL이고, WSL에 설치하는 것을 기준으로 작성했다.

#### Gemini CLI
Github에서는 Claude Desktop을 기준으로 데모 영상이 제공되는데, 여러가지 이유로 Gemini를 구독 중이기 때문에 Gemini CLI를 설치해야 한다.

``` bash
# npm install
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

# Node.js install; require version > 20
nvm install node

# Gemini CLI install
npm install -g @google/gemini-cli
```

마찬가지로 게스트와 통신을 위해서 `~/.gemini/settings.json` 파일에 MCP 서버의 정보를 추가해주어야 한다.

``` json
{
  "mcpServers": {
    "ida-vm": {
      "url": "http://xxx.xxx.xxx.xxx:13337/sse"
    }
  }
}
```

설치와 설정이 잘 되었다면 `gemini` 명령어를 실행했을 때 다음과 같이 `Using: 1 MCP server`라는 로그를 볼 수 있다.

``` bash

   ░░░            ░░░░░░░░░  ░░░░░░░░░░ ░░░░░░   ░░░░░░ ░░░░░ ░░░░░░   ░░░░░ ░░░░░
     ░░░         ░░░     ░░░ ░░░        ░░░░░░   ░░░░░░  ░░░  ░░░░░░   ░░░░░  ░░░
       ░░░      ░░░          ░░░        ░░░ ░░░ ░░░ ░░░  ░░░  ░░░ ░░░  ░░░    ░░░
 ███     ░░░    █████████░░██████████ ██████ ░░██████░█████░██████ ░░█████ █████░
   ███ ░░░     ███░    ███░███░░      ██████  ░██████░░███░░██████  ░█████  ███░░
     ███      ███░░░     ░░███░░      ███░███ ███ ███░░███░░███░███  ███░░  ███░░
   ░░░ ███    ███ ░░░█████░██████░░░░░███░░█████  ███░░███░░███░░███ ███░░░ ███░░░
     ███      ███      ███ ███        ███   ███   ███  ███  ███   ██████    ███
   ███         ███     ███ ███        ███         ███  ███  ███    █████    ███
 ███            █████████  ██████████ ███         ███ █████ ███     █████  █████

Tips for getting started:
1. Ask questions, edit files, or run commands.
2. Be specific for the best results.
3. Create GEMINI.md files to customize your interactions with Gemini.
4. /help for more information.

 Using: 1 MCP server
╭──────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ >   Type your message or @path/to/file                                                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
 ~/mcp                          no sandbox (see /docs)                           Auto (Gemini 3) /model
```

또한 `/mcp` 명령어를 통해서 어떤 기능이 있는지 확인할 수 있다.

``` bash
> /mcp

Configured MCP servers:

🟢 ida-vm - Ready (71 tools, 15 resources)
  Tools:
  - analyze_funcs
  - analyze_strings
  - apply_types
  ...
  Resources:
  - idb_metadata_resource (ida://idb/metadata) [application/json]
  - idb_segments_resource (ida://idb/segments) [application/json]
  - idb_entrypoints_resource (ida://idb/entrypoints) [application/json]
  ...
```


## 0x02. Prompt Engineering
CTF를 준비할 때에는 미처 확인하지 못한 부분인데, 당연하게도 더 나은 분석 결과를 위해 프롬프트가 권장된다.
기본적으로 제시된 프롬프트는 다음과 같다.

```
Your task is to analyze the open file in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the `int_convert` MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found
```

다른 유저 ([@can1357](https://github.com/can1357))가 공유한 프롬프트는 다음과 같다.

```
Your task is to create a complete and comprehensive reverse engineering analysis. Reference AGENTS.md to understand the project goals and ensure the analysis serves our purposes.

Use the following systematic methodology:

1. **Decompilation Analysis**
   - Thoroughly inspect the decompiler output
   - Add detailed comments documenting your findings
   - Focus on understanding the actual functionality and purpose of each component (do not rely on old, incorrect comments)

2. **Improve Readability in the Database**
   - Rename variables to sensible, descriptive names
   - Correct variable and argument types where necessary (especially pointers and array types)
   - Update function names to be descriptive of their actual purpose

3. **Deep Dive When Needed**
   - If more details are necessary, examine the disassembly and add comments with findings
   - Document any low-level behaviors that aren't clear from the decompilation alone
   - Use sub-agents to perform detailed analysis

4. **Important Constraints**
   - NEVER convert number bases yourself - use the int_convert MCP tool if needed
   - Use MCP tools to retrieve information as necessary
   - Derive all conclusions from actual analysis, not assumptions

5. **Documentation**
   - Produce comprehensive RE/*.md files with your findings
   - Document the steps taken and methodology used
   - When asked by the user, ensure accuracy over previous analysis file
      - Organize findings in a way that serves the project goals outlined in AGENTS.md or CLAUDE.md
   ```