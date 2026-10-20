# Contributing to x64dbg-MCP

Thank you for your interest in contributing to x64dbg-MCP. This project provides a Model Context Protocol (MCP) server and native C++ plugin bridge for the x64dbg debugger.

Contributions that improve stability, expand tool capabilities, optimize performance, or enhance documentation are welcome.

---

## Architecture Overview

x64dbg-MCP operates across two primary components:

1. **Native C++ Plugin (`src/`)**: Compiles to `x64dbg_mcp.dp64`. Runs inside the 64-bit x64dbg process, interacts directly with x64dbg Bridge SDK APIs, and hosts a Win32 named pipe server (`\\.\pipe\x64dbg_mcp`).
2. **Python MCP Server (`mcp_server/`)**: FastMCP server that connects to the named pipe, validates arguments, formats responses, and exposes tools over standard I/O (stdio) to MCP clients (such as Claude Desktop, Cursor, and custom agents). Also includes `trace_reader.py` for standalone trace inspection.

---

## Prerequisites

To build and test the project, ensure your environment meets the following requirements:

* **Operating System**: Windows 10, Windows 11, or Windows Server (64-bit).
* **C++ Compiler**: Microsoft Visual Studio 2019, 2022, or 2026 with the "Desktop development with C++" workload installed (`vcvars64.bat`).
* **Python**: Python 3.10 or newer (tested on 3.10, 3.11, 3.12, 3.13).
* **x64dbg SDK**: An x64dbg installation or snapshot containing `release\x64\x64dbg.exe` and `pluginsdk\`.

---

## Development Setup

### 1. Clone Repository

```powershell
git clone https://github.com/cipherwire/x64dbg-mcp.git
cd x64dbg-mcp
```

### 2. Configure Environment

Set environment variables pointing to your local x64dbg installation:

```powershell
# Set root x64dbg directory
$env:X64DBG_DIR = "C:\path\to\x64dbg"

# Or configure explicit SDK and plugin directories
$env:X64DBG_SDK_DIR = "C:\path\to\x64dbg\pluginsdk"
$env:X64DBG_PLUGINS_DIR = "C:\path\to\x64dbg\release\x64\plugins"
```

### 3. Install Python Dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

---

## Building the Native Plugin

Build the plugin using the included build script:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

To compile and immediately deploy the binary into your x64dbg plugins folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Deploy
```

### Build Requirements:
* Must compile cleanly under MSVC with `/W4 /WX` (level 4 warnings treated as errors).
* Zero warnings and zero errors are required for all builds.

---

## Code Style and Quality Standards

### 1. Target-Agnostic Requirement
All production code in `src/` and `mcp_server/` must remain completely target-agnostic.
* Never hardcode executable names, crackme names, or process IDs.
* Never hardcode machine-specific file paths, usernames, or secrets.
* Never hardcode fixed memory addresses or target-specific control flow.
* Production logic must work uniformly across arbitrary binaries supported by x64dbg.

### 2. Native C++ Guidelines
* **Modular Structure**: Keep `plugin.cpp` minimal (plugin initialization and lifecycle hooks only). Place new functionality in dedicated, feature-based `.cpp` and `.h` pairs.
* **Resource Safety**: Use RAII wrappers for all Win32 handles, locks, memory allocations, and console attachments. Every failure path must cleanly release resources.
* **Thread Safety**: The named pipe worker operates on a dedicated thread. Synchronize shared debugger state using lightweight primitives such as SRW locks.
* **Error Handling**: Return structured JSON error objects with explicit failure codes and error messages rather than crashing or hanging the pipe server.

### 3. Python Server Guidelines
* **Input Validation**: Validate every parameter strictly before dispatching to the native named pipe.
* **Error Propagation**: Raise `ToolError` on invalid parameters or unexpected pipe responses.
* **Type Annotations**: Use Python type hints on all tool functions and utility methods.

### 4. Punctuation and Writing Style
* **No Em Dashes**: Do not use em dashes or en dashes in code comments, commit messages, or documentation files. Use standard hyphens `-` or colons `:` instead.
* Keep explanations concise, technical, and accurate.

---

## Testing and Verification

Before submitting code, run the verification tests:

### 1. Verify Tool Count and Definitions
Ensure any newly added tool is properly registered in both `mcp_server/server.py` and the test suite's `expected_tools` list:

```powershell
python -c "
import ast
with open('mcp_server/server.py', 'r', encoding='utf-8') as f:
    tree = ast.parse(f.read())
tools = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and any(getattr(d, 'attr', '') == 'tool' for d in n.decorator_list if isinstance(d, ast.Call))]
print(f'Total tools: {len(tools)}')
"
```

### 2. End-to-End Regression Suite
Execute the automated regression runner against a test binary:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_regression_test.ps1 -Target "path\to\target.exe"
```

The regression suite tests all 234 tools and verifies that the target fixture SHA-256 hash remains unaltered.

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   * `feat/feature-name`
   * `fix/bug-description`
   * `docs/documentation-update`
2. **Commit Messages**: Follow Conventional Commits format:
   * `feat: add memory pattern scanner options`
   * `fix: correct breakpoint reference field assignment`
   * `docs: update setup instructions in README`
3. **PR Checklist**:
   * [ ] Native code compiles with MSVC `/W4 /WX` with 0 warnings.
   * [ ] Production code is target-agnostic and contains no local machine paths.
   * [ ] Documentation contains no em dashes or en dashes.
   * [ ] Python tests pass without errors.
   * [ ] Tool count matches between `server.py` and `tests/test_mcp_client.py`.
