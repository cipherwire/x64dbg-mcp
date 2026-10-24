# x64dbg-MCP: Model Context Protocol Server & Native Plugin for x64dbg

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![MCP: 2.0](https://img.shields.io/badge/MCP-2.0-orange.svg)](https://modelcontextprotocol.io)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](README.md)
[![CI Status](https://github.com/cipherwire/x64dbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/cipherwire/x64dbg-mcp/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://x64dbg-mcp.cipherwire.link)
[![Discord](https://img.shields.io/badge/Discord-Join%20Chat-5865F2?logo=discord&logoColor=white)](https://discord.gg/QphWRKHvH2)

`x64dbg-MCP` connects AI models, autonomous agents, and automation tools to the **x64dbg** debugger using the standardized [Model Context Protocol (MCP)](https://modelcontextprotocol.io).

It provides **234 verified debugging and reverse engineering tools** spanning live execution control, registers, memory inspection and modification, disassembly, symbol resolution, hardware and software breakpoints, thread scheduling, structured type decoding, call stacks, live execution tracing, offline trace file parsing, console input and output capture, and PE binary inspection.

The native plugin and Python server are target-agnostic and work reliably with arbitrary 64-bit and 32-bit Windows executables, modules, and threads supported by x64dbg and x32dbg.

---

## Key Features

* **234 Verified MCP Tools**: Comprehensive coverage of the x64dbg/x32dbg Bridge SDK and debugging engine.
* **Dual-Architecture Support**: Full production-grade support for both 64-bit (`x64dbg_mcp.dp64`) and 32-bit (`x32dbg_mcp.dp32`) debuggers.
* **Dual-Layer Architecture**: High-speed native C++ plugins communicating via Win32 named pipes (`\\.\pipe\x64dbg_mcp` and `\\.\pipe\x32dbg_mcp`) with an official FastMCP Python server that auto-detects the active debugger.
* **Bi-directional Console I/O**: Direct keyboard input simulation (`send_console_input`) and screen buffer capture (`read_console_output`) for interactive console targets without disrupting runtime buffering.
* **Offline Trace Inspector**: Dedicated binary parser (`trace_reader.py`) for `.trace32` and `.trace64` files, supporting instruction search, register lookups, and timeline navigation without requiring x64dbg to be running.
* **Strict Code Quality**: Native plugin compiles under MSVC with `/W4 /WX` (strict warnings treated as errors, 0 warnings across both x64 and x86).
* **Automated CI/CD**: End-to-end regression testing and automated GitHub Releases for pre-built binaries.

---

## Table of Contents

* [Architecture](#architecture)
* [Quick Start (Pre-built Release)](#quick-start-pre-built-release)
* [Building from Source](#building-from-source)
* [Client Configuration](#client-configuration)
  * [Google Gemini / Antigravity](#1-google-gemini--antigravity)
  * [Claude Desktop](#2-claude-desktop)
  * [Cursor](#3-cursor)
  * [Windsurf](#4-windsurf)
  * [VS Code / Cline / Roo-Code](#5-vs-code--cline--roo-code)
* [Example AI Workflow](#example-ai-workflow)
* [Verified Tool Surface (234 Tools)](#verified-tool-surface-234-tools)
* [Offline Trace File Analysis](#offline-trace-file-analysis)
* [Testing and Regression](#testing-and-regression)
* [Contributing](#contributing)
* [License](#license)

---

## Architecture

```text
+-------------------------------------------------------------+
|                         MCP Client                          |
|       (Claude Desktop, Cursor, Windsurf, Custom Agent)      |
+------------------------------+------------------------------+
                               |
                               | JSON-RPC over Standard I/O (stdio)
                               v
+-------------------------------------------------------------+
|                      Python MCP Server                      |
|           (mcp_server/server.py & trace_reader.py)          |
+------------------------------+------------------------------+
                               |
                               | Win32 Named Pipe (\\.\pipe\x64dbg_mcp)
                               v
+-------------------------------------------------------------+
|                     Native C++ Plugin                       |
|               (x64dbg_mcp.dp64 inside x64dbg)               |
+------------------------------+------------------------------+
                               |
                               | x64dbg Bridge APIs
                               v
+-------------------------------------------------------------+
|                      Target Executable                      |
+-------------------------------------------------------------+
```

* **Python Server (`mcp_server/server.py`)**: Implements the Model Context Protocol (v2.0), performs strict input validation, serializes commands to the named pipe, and handles offline trace parsing.
* **Native Plugin (`src/` -> `bin/x64dbg_mcp.dp64`)**: High-performance multi-threaded C++ plugin hosting a non-blocking named pipe server directly inside x64dbg.
* **Trace Parser (`mcp_server/trace_reader.py`)**: Standalone binary file reader for historical trace logs recorded by x64dbg.

---

## Quick Start (Pre-built Release)

For users who want to run the server immediately without compiling C++:

### 1. Download Plugin Binary
Download the pre-compiled native plugins from the latest [GitHub Release](https://github.com/cipherwire/x64dbg-mcp/releases):
* `x64dbg_mcp.dp64` for 64-bit (`x64dbg`)
* `x32dbg_mcp.dp32` for 32-bit (`x32dbg`)

### 2. Copy Plugin to x64dbg / x32dbg
Place the plugin file into your respective debugger plugins folder:
* For 64-bit:
  ```text
  <x64dbg_installation_path>\release\x64\plugins\x64dbg_mcp.dp64
  ```
* For 32-bit:
  ```text
  <x64dbg_installation_path>\release\x32\plugins\x32dbg_mcp.dp32
  ```

### 3. Install Python Package
```powershell
# Clone the repository
git clone https://github.com/cipherwire/x64dbg-mcp.git
cd x64dbg-mcp

# Install required dependencies
pip install -r requirements.txt
pip install -e .
```

### 4. Start Debugger
Launch either `x64dbg.exe` (64-bit) or `x32dbg.exe` (32-bit). In the debugger Log tab, verify the startup message:
* In x64dbg:
  ```text
  [x64dbg-MCP] Plugin loaded successfully.
  [x64dbg-MCP] Named pipe server listening on \\.\pipe\x64dbg_mcp
  ```
* In x32dbg:
  ```text
  [x64dbg-MCP] Plugin loaded successfully.
  [x64dbg-MCP] Named pipe server listening on \\.\pipe\x32dbg_mcp
  ```

The Python MCP server automatically discovers and connects to whichever debugger is active. You can also override the pipe using the `X64DBG_PIPE_NAME` environment variable.

Now connect your favorite AI client using the configuration below!

---

## Building from Source

### Prerequisites
* **Operating System**: Windows 10, Windows 11, or Windows Server (64-bit).
* **Compiler**: Microsoft Visual Studio 2019, 2022, or 2026 with the "Desktop development with C++" workload installed (`vcvars64.bat` / `vcvars32.bat`).
* **Python**: Python 3.10 or newer.
* **x64dbg SDK**: An x64dbg installation or snapshot containing `release\x64\x64dbg.exe`, `release\x32\x32dbg.exe`, and `pluginsdk\`.

### Build & Deploy Command
Set your x64dbg directory and compile both architectures with strict `/W4 /WX` flags:

```powershell
# Optional: Set environment variable
$env:X64DBG_DIR = "C:\path\to\x64dbg"

# Compile and automatically deploy both x64 and x86 plugins:
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Platform All -Deploy
```

You can also build a single architecture:
```powershell
# Build x64 only:
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Platform x64 -Deploy

# Build x86 (32-bit) only:
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Platform x86 -Deploy
```

The output binaries are produced at `bin/x64dbg_mcp.dp64` and `bin/x32dbg_mcp.dp32`.

---

## Client Configuration

Configure your AI tool to launch the MCP server via `python -m mcp_server.server` or `x64dbg-mcp`.

### 1. Google Gemini / Antigravity
Add to your global MCP configuration file at `~/.gemini/config/mcp_config.json` (or `%USERPROFILE%\.gemini\config\mcp_config.json`):

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\x64dbg-mcp"
    }
  }
}
```

Or if installed as a Python package via pip (`pip install .`):
```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "x64dbg-mcp"
    }
  }
}
```

### 2. Claude Desktop
Add to your `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\x64dbg-mcp"
    }
  }
}
```

### 3. Cursor
In Cursor, open **Settings** -> **Features** -> **MCP**, click **Add New MCP Server**:
* **Name**: `x64dbg`
* **Type**: `command`
* **Command**: `python -m mcp_server.server`
* **Working Directory**: `C:\path\to\x64dbg-mcp`

Or in project `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\x64dbg-mcp"
    }
  }
}
```

### 4. Windsurf
Add to `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\x64dbg-mcp"
    }
  }
}
```

### 5. VS Code / Cline / Roo-Code
In your extension MCP configuration file:
```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "C:\\path\\to\\x64dbg-mcp"
    }
  }
}
```

---

## Example AI Workflow

Once connected, your AI assistant can interact with live debugging sessions seamlessly:

1. **Check Bridge Health**:
   ```json
   Tool: get_bridge_status
   Result: {"connected": true, "state": "paused", "stop_address": "0x00007FF7F72F1125", "pid": 14220, "tid": 9812}
   ```
2. **Inspect Code & Registers**:
   ```json
   Tool: disassemble {"address": "0x00007FF7F72F1125", "count": 5}
   Tool: get_registers {}
   ```
3. **Set Breakpoint and Resume**:
   ```json
   Tool: set_breakpoint {"address": "0x00007FF7F72F1AA0"}
   Tool: resume {}
   ```
4. **Interact with Console Prompts**:
   ```json
   Tool: read_console_output {"max_lines": 10}
   Result: {"text": "Enter password: ", "cursor_position": {"x": 16, "y": 0}}

   Tool: send_console_input {"text": "Secret123!", "send_enter": true}
   ```

---

## Verified Tool Surface (234 Tools)

The system exposes 234 fine-grained tools organized across 31 functional domains:

1. **Execution Control & Stepping (15)**: `step_into`, `step_over`, `step_out`, `step_over_pass_exceptions`, `step_out_pass_exceptions`, `step_user`, `step_system`, `skip_instruction`, `resume`, `pause`, `restart_debuggee`, `stop_debuggee`, `run_to_address`, `run_to_user_code`, `run_to_party`
2. **State & Diagnostics (3)**: `get_debugger_state`, `get_bridge_status`, `get_command_line`
3. **Registers (2)**: `get_registers`, `set_register`
4. **Memory Operations (12)**: `read_memory`, `write_memory`, `allocate_memory`, `free_memory`, `fill_memory`, `copy_memory`, `patch_memory`, `get_memory_region`, `list_memory_regions`, `get_page_rights`, `set_page_rights`, `is_code_page`
5. **Disassembly & Assembly (2)**: `disassemble`, `assemble`
6. **Breakpoints (17)**: `set_breakpoint`, `delete_breakpoint`, `enable_breakpoint`, `list_breakpoints`, `configure_breakpoint`, `reset_breakpoint_hit_count`, `get_breakpoint_details`, `set_hardware_breakpoint`, `delete_hardware_breakpoint`, `enable_hardware_breakpoint`, `set_memory_breakpoint`, `delete_memory_breakpoint`, `enable_memory_breakpoint`, `set_memory_range_breakpoint`, `set_dll_breakpoint`, `delete_dll_breakpoint`, `enable_dll_breakpoint`
7. **Breakpoint References (3)**: `list_breakpoint_references`, `get_breakpoint_reference`, `set_breakpoint_reference_fields`
8. **Threads & Scheduling (11)**: `list_threads`, `switch_thread`, `suspend_thread`, `resume_thread`, `suspend_all_threads`, `resume_all_threads`, `kill_thread`, `set_thread_priority`, `set_thread_name`, `get_thread_priority`, `get_thread_name`
9. **Modules, Imports & Exports (6)**: `list_modules`, `list_module_sections`, `list_exports`, `list_imports`, `get_module_party`, `set_module_party`
10. **Symbols & Resolution (4)**: `list_symbols`, `resolve_symbol`, `symbol_autocomplete`, `get_symbol_status`
11. **Call Stack (2)**: `get_call_stack`, `get_thread_call_stack`
12. **Cross-References (2)**: `get_xrefs`, `analyze_xrefs`
13. **Address & Source Resolution (5)**: `get_address_info`, `find_source_address`, `get_source_location`, `file_offset_to_va`, `va_to_file_offset`
14. **Expressions & Calculations (1)**: `eval_expression`
15. **Pattern Searching (1)**: `find_pattern`
16. **Annotations, Labels & Bookmarks (13)**: `set_comment`, `get_comment`, `clear_comments`, `delete_comment`, `list_comments`, `set_label`, `get_label`, `clear_labels`, `delete_label`, `list_labels`, `set_bookmark`, `get_bookmark`, `list_bookmarks`, `clear_bookmarks`, `delete_bookmark`
17. **Functions & Loops (18)**: `add_function`, `delete_function`, `clear_functions`, `get_function_info`, `get_function_boundary`, `get_function_callers`, `get_function_callees`, `list_functions`, `add_loop`, `delete_loop`, `clear_loops`, `get_loop`, `list_loops`, `add_argument`, `delete_argument`, `clear_arguments`, `get_argument`, `list_arguments`
18. **Environment & System State (8)**: `get_peb_info`, `get_teb_info`, `list_handles`, `get_handle_info`, `list_windows`, `list_heaps`, `list_tcp_connections`, `list_processes`
19. **Patches (4)**: `list_patches`, `get_patch`, `restore_patch`, `restore_patches_range`
20. **Exceptions & SEH (7)**: `list_exceptions`, `get_exception_info`, `get_last_exception`, `get_seh_chain`, `set_exception_breakpoint`, `delete_exception_breakpoint`, `enable_exception_breakpoint`
21. **Live Debugger Tracing (14)**: `start_trace_recording`, `stop_trace_recording`, `get_trace_status`, `set_trace_log_file`, `set_trace_log`, `set_trace_command`, `set_trace_record_type`, `set_trace_step_filter`, `trace_into_conditional`, `trace_over_conditional`, `trace_into_trace_record`, `trace_over_trace_record`, `trace_into_beyond_trace_record`, `trace_over_beyond_trace_record`
22. **Offline Trace File Inspection (12)**: `open_trace_file`, `close_trace_file`, `get_trace_info`, `get_trace_record`, `get_trace_instruction`, `get_trace_instructions`, `get_trace_registers`, `get_trace_memory_accesses`, `read_trace_memory`, `search_trace_address`, `search_trace_memory`, `find_trace_calls`
23. **Watches (10)**: `add_watch`, `delete_watch`, `clear_watches`, `list_watches`, `get_watch`, `modify_watch`, `rename_watch`, `set_watch_type`, `set_watchdog`, `check_watchdogs`
24. **Data Encoding Maps & Type System (16)**: `get_data_map`, `set_data_type`, `get_data_type`, `get_data_size`, `clear_data_type_range`, `clear_data_type_segment`, `inspect_type`, `list_struct_types`, `list_structs`, `add_struct_type`, `add_struct_member`, `add_type`, `add_union_type`, `get_type_size`, `remove_type`, `clear_types`
25. **PE Metadata, Strings & Dumps (9)**: `get_pe_headers`, `list_pe_data_directories`, `list_tls_callbacks`, `get_runtime_function`, `list_runtime_functions`, `find_strings`, `dump_memory`, `dump_module`, `create_minidump`
26. **Database Operations (3)**: `save_database`, `load_database`, `clear_database`
27. **Scripts & Automation (3)**: `run_script`, `set_debuggee_init_script`, `get_debuggee_init_script`
28. **Debug Events & Session Control (12)**: `wait_for_debug_event`, `get_debug_events`, `clear_debug_events`, `get_event_status`, `get_debug_session_info`, `set_command_line`, `set_jit`, `set_jit_auto`, `get_jit_info`, `attach_process`, `detach_process`, `launch_debuggee`
29. **Advanced Code Analysis (7)**: `analyze_code`, `analyze_recursive`, `analyze_nukem`, `analyze_control_flow`, `analyze_exception_directory`, `analyze_advanced`, `get_control_flow_graph`
30. **Debugger Configuration & Constants (1)**: `dbg_config`
31. **Console I/O (2)**: `send_console_input`, `read_console_output`

---

## Offline Trace File Analysis

The server provides 12 specialized tools that directly parse x64dbg `.trace32` and `.trace64` binary files completely offline:

* Inspect recorded instructions, register snapshots, and memory accesses.
* Search for memory read/write patterns and executed addresses.
* Extract call trees and function paths without launching x64dbg.

```python
# Standalone CLI usage example
from mcp_server.trace_reader import TraceReader

reader = TraceReader("session.trace64")
print(f"Recorded instructions: {reader.header.inst_count}")
for instr in reader.iter_instructions(start=0, count=10):
    print(f"0x{instr.address:016X}: {instr.disasm}")
```

---

## Testing and Regression

The project includes an end-to-end regression test suite covering all 234 tools:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_regression_test.ps1 -Target "C:\path\to\any_test_binary.exe"
```

The test runner:
1. Recompiles and deploys the plugin with strict `/W4 /WX` warnings.
2. Computes the SHA-256 hash of the test fixture before execution.
3. Launches x64dbg with the test binary.
4. Executes `tests/test_mcp_client.py` exercising every tool and error boundary.
5. Terminates x64dbg and verifies the test fixture's SHA-256 hash remained untouched.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code standards, local development, build requirements, and pull requests.

---

## License

This project is licensed under the GNU General Public License v3.0: see the [LICENSE](LICENSE) file for details. Third-party dependencies and attributions are detailed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
