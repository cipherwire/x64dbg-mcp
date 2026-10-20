# Third-Party Notices & Attribution

This repository contains original code developed for the **x64dbg-MCP** project.

It does not distribute third-party source files or compiled binaries directly within the repository. It interacts with and links against the following external projects and libraries:

---

## 1. x64dbg & x64dbg Plugin SDK

* **Project**: x64dbg (an open-source x64/x86 debugger for Windows)
* **Website**: https://x64dbg.com
* **Repository**: https://github.com/x64dbg/x64dbg
* **License**: GNU General Public License v3.0 (GPLv3)
* **Usage**:
  * The native plugin (`src/`) compiles against the x64dbg Plugin SDK C/C++ interface headers (`_plugins.h`, `bridgemain.h`, `_scriptapi_*.h`, etc.) and links against `x64dbg.lib` and `x64bridge.lib` provided by the user's x64dbg installation.
  * The trace reader (`mcp_server/trace_reader.py`) implements a standalone Python parser conforming to the x64dbg binary trace file specification (`.trace32` / `.trace64`).

---

## 2. Model Context Protocol (MCP) Python SDK

* **Project**: Model Context Protocol Python SDK (`mcp`)
* **Website**: https://modelcontextprotocol.io
* **Repository**: https://github.com/modelcontextprotocol/python-sdk
* **License**: MIT License
* **Usage**: The Python server (`mcp_server/server.py`) and test client (`tests/test_mcp_client.py`) use the official MCP Python SDK (`mcp>=2.0.0,<3`) for JSON-RPC communication over stdio.

---

## 3. AnyIO

* **Project**: AnyIO (asynchronous networking and concurrency library)
* **Repository**: https://github.com/agronholm/anyio
* **License**: MIT License
* **Usage**: Used for async runtime orchestration and concurrency in Python.
