+++
title = "Connecting LLM to IDA MCP Server in a Virtual Machine (feat. Gemini CLI)"
date = "2025-12-10"
description = "Setting up a parallel analysis workflow with IDA in a VM and Gemini CLI on Host"

[taxonomies]
tags = ["tools", "pwnable", "reversing", "ida", "mcp", "llm"]
+++

## 0x00. Introduction
MCP (Model Context Protocol) is an open standard that enables AI models to communicate with other systems. 
By using MCP, LLMs can connect to various data sources like PCs or databases, and tools like search engines or calculators to perform complex and valuable tasks. 
It's often described as a **"USB-C port for AI."**

While there is an official plugin from Hex-Rays, this guide is based on the [GitHub repository](https://github.com/mrexodia/ida-pro-mcp) which has more stars and community traction. 
I also structured this setup using a virtual machine for the MCP Server, enabling a workflow where I can freely analyze in parallel while the agent handles its tasks.


## 0x01. Install
### Guest
As mentioned, the MCP server will be set up inside a virtual machine. 
You can use any OS that supports IDA (macOS, Linux, and Windows), but I used Windows 10 x64.

#### Python
Python 3.11 or higher is required. 
Usually, IDA installs Python if it's missing, but older versions might install 3.10. 
Since we're running this in a VM, it's easier to install the latest version beforehand.

I personally install it in `C:\Python\Python[VER]`. Make sure to add the following paths to your system's `PATH` environment variable:

 - `C:\Python\Python314\`
 - `C:\Python\Python314\Scripts\`

#### IDA Pro
The GitHub repository recommends IDA Pro 8.3 or higher, or version 9. 
Note that IDA Free is not supported, but according to sources, IDA Home (the individual plan) works fine.

During installation, uncheck the option to install Python so that IDA uses the version you previously installed.

#### IDA MCP
Refer to the [GitHub installation guide](https://github.com/mrexodia/ida-pro-mcp?tab=readme-ov-file#installation) for detailed steps.

``` cmd
pip uninstall ida-pro-mcp
pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip

ida-pro-mcp --install
```

After installation, go to `Edit` -> `Plugins` -> `MCP` in the IDA menu. If the output looks like this, the installation was successful:

``` txt
[MCP] Server started:
  Streamable HTTP: http://127.0.0.1:13337/mcp
  SSE: http://127.0.0.1:13337/sse
  Config: http://127.0.0.1:13337/config.html
```

Since it listens on `127.0.0.1` by default, you can set up port forwarding or simply run the following command to allow host communication:

``` cmd
ida-pro-mcp --transport http://0.0.0.0:13337/sse
```

### Host
While you could install the AI application on the guest OS, I preferred separating the guest and host. I use these applications frequently on my host, and it feels slightly faster.

The host environment is Windows 11 with WSL, and the following steps are for WSL.

#### Gemini CLI
The demo on GitHub uses Claude Desktop, but since I subscribe to Gemini, I'll be using the Gemini CLI.

``` bash
# Install nvm and Node.js (requires version > 20)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
nvm install node

# Install Gemini CLI
npm install -g @google/gemini-cli
```

To communicate with the guest, add the MCP server information to `~/.gemini/settings.json`:

``` json
{
  "mcpServers": {
    "ida-vm": {
      "url": "http://xxx.xxx.xxx.xxx:13337/sse"
    }
  }
}
```

If everything is set up correctly, running the `gemini` command should show a log saying `Using: 1 MCP server`.

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

You can verify the available tools using the `/mcp` command.

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
For better analysis results, using a well-crafted prompt is highly recommended. 
Here is the default recommended prompt:

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

And here is a more detailed prompt shared by another user ([@can1357](https://github.com/can1357)):

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