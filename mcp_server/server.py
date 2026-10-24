import os
import sys
import time
import json
import logging
import ctypes
from ctypes import wintypes
from typing import Union, Optional, List, Dict, Any
import atexit
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

try:
    from .trace_reader import trace_sessions, TraceError, X64_REG_NAMES, X86_REG_NAMES, disassemble_simple
except ImportError:
    from trace_reader import trace_sessions, TraceError, X64_REG_NAMES, X86_REG_NAMES, disassemble_simple

atexit.register(trace_sessions.close_all)

# Configure diagnostic logging to stderr only (stdout is reserved for MCP JSON-RPC)
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[x64dbg-MCP-Server] %(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("x64dbg-mcp")

DEFAULT_PIPE_NAMES = [r"\\.\pipe\x64dbg_mcp", r"\\.\pipe\x32dbg_mcp"]

def get_candidate_pipes() -> list[str]:
    custom = os.environ.get("X64DBG_PIPE_NAME")
    if custom:
        return [custom]
    return DEFAULT_PIPE_NAMES

# Win32 constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
CreateFileW.restype = wintypes.HANDLE

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
ReadFile.restype = wintypes.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
WriteFile.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL


def query_debugger_pipe(command: str, params: dict | None = None, timeout_sec: float = 2.0) -> dict:
    start_time = time.time()
    h_pipe = INVALID_HANDLE_VALUE
    pipes = get_candidate_pipes()

    # Connect to named pipe with bounded timeout across candidates
    while time.time() - start_time < timeout_sec:
        for p_name in pipes:
            h_pipe = CreateFileW(
                p_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )
            if h_pipe != INVALID_HANDLE_VALUE:
                break
        if h_pipe != INVALID_HANDLE_VALUE:
            break
        err = ctypes.get_last_error()
        if err in (2, 231):  # ERROR_FILE_NOT_FOUND or ERROR_PIPE_BUSY
            time.sleep(0.05)
            continue
        else:
            logger.error(f"Failed to open pipe, Win32 error: 0x{err:08X}")
            raise ToolError(f"Failed to open x64dbg/x32dbg pipe (error 0x{err:08X})")

    if h_pipe == INVALID_HANDLE_VALUE:
        logger.warning("Pipe connection timed out; x64dbg/x32dbg or plugin is not running.")
        raise ToolError("x64dbg/x32dbg is not running or the MCP plugin is not loaded.")

    try:
        # Build request payload
        req_obj = {"cmd": command}
        if params:
            req_obj.update(params)
        payload = f"{json.dumps(req_obj)}\n".encode('utf-8')

        bytes_written = wintypes.DWORD(0)
        ok = WriteFile(h_pipe, payload, len(payload), ctypes.byref(bytes_written), None)
        if not ok:
            err = ctypes.get_last_error()
            logger.error(f"WriteFile failed with error 0x{err:08X}")
            raise ToolError(f"Failed to send command to x64dbg (error 0x{err:08X})")

        # Read response into 64KB buffer to support memory read dumps
        read_buf = ctypes.create_string_buffer(65536)
        bytes_read = wintypes.DWORD(0)
        ok = ReadFile(h_pipe, read_buf, 65535, ctypes.byref(bytes_read), None)
        if not ok:
            err = ctypes.get_last_error()
            logger.error(f"ReadFile failed with error 0x{err:08X}")
            raise ToolError(f"Failed to read response from x64dbg (error 0x{err:08X})")

        raw_text = read_buf.raw[:bytes_read.value].decode('utf-8', errors='replace').strip()
        logger.debug(f"Received raw pipe response: {raw_text[:120]}")

        # Parse and validate JSON structure
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from pipe: {raw_text}")
            raise ToolError(f"Invalid JSON response from x64dbg: {e}")

        if "error" in data:
            raise ToolError(f"x64dbg returned error: {data['error']}")

        return data

    finally:
        CloseHandle(h_pipe)


# Initialize MCPServer
server = MCPServer(
    name="x64dbg-mcp-server",
    version="0.1.0",
    description="MCP integration server for x64dbg debugger"
)


@server.tool(
    name="get_debugger_state",
    description="Returns whether x64dbg is currently debugging a process and whether the debuggee is running or paused."
)
def get_debugger_state() -> dict:
    data = query_debugger_pipe("get_debugger_state")

    # Validate response schema
    if "is_debugging" not in data or not isinstance(data["is_debugging"], bool):
        raise ToolError(f"Malformed response from x64dbg: missing or invalid 'is_debugging' field")
    if "is_running" not in data or not isinstance(data["is_running"], bool):
        raise ToolError(f"Malformed response from x64dbg: missing or invalid 'is_running' field")

    return {
        "is_debugging": data["is_debugging"],
        "is_running": data["is_running"]
    }


@server.tool(
    name="get_bridge_status",
    description="Returns the current debugger and bridge state, distinguishing between unavailable (x64dbg/plugin not running), no_debuggee (x64dbg open without target), running (debuggee actively executing), and paused (debuggee suspended, including stop_address)."
)
def get_bridge_status() -> dict:
    try:
        data = query_debugger_pipe("get_bridge_status", timeout_sec=0.5)
        return {
            "connected": True,
            "state": data.get("state", "unknown"),
            "is_debugging": data.get("is_debugging", False),
            "is_running": data.get("is_running", False),
            "stop_address": data.get("stop_address"),
            "pid": data.get("pid"),
            "tid": data.get("tid")
        }
    except ToolError as e:
        err_msg = str(e)
        if "not running" in err_msg or "failed to open" in err_msg.lower():
            return {
                "connected": False,
                "state": "unavailable",
                "is_debugging": False,
                "is_running": False,
                "stop_address": None,
                "pid": None,
                "tid": None,
                "message": err_msg
            }
        raise


@server.tool(
    name="get_registers",
    description="Returns the current 64-bit general-purpose CPU registers (RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, RIP, R8-R15, EFLAGS) when the debuggee is paused."
)
def get_registers() -> dict:
    data = query_debugger_pipe("get_registers")

    # Validate essential general-purpose register fields exist
    required_regs = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rip"]
    for reg in required_regs:
        if reg not in data:
            raise ToolError(f"Malformed register response from x64dbg: missing '{reg}'")

    return data


@server.tool(
    name="read_memory",
    description="Reads a specified number of bytes (1-4096) from the debuggee process memory at the given virtual address (hex string e.g. '0x140000000' or register name 'RIP', 'RSP') when the debuggee is paused. Returns the address, byte count, and lowercase hex-encoded data."
)
def read_memory(address: str, size: int = 64) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140000000', 'RIP', 'RSP')")
    if not isinstance(size, int) or size <= 0 or size > 4096:
        raise ToolError("Invalid 'size': must be an integer between 1 and 4096 bytes")

    data = query_debugger_pipe("read_memory", {"address": address.strip(), "size": size})

    if "hex" not in data or "address" not in data or "size" not in data:
        raise ToolError("Malformed memory read response from x64dbg: missing required fields")

    return data


@server.tool(
    name="disassemble",
    description="Disassembles a sequential range of instructions (1-64) starting at a specified address (hex string e.g. '0x140001125', register name 'RIP', 'RSP', or module name 'app.exe') when the debuggee is paused. Defaults to 10 instructions starting at RIP if omitted. Returns structured instruction text, size, machine bytes, and type."
)
def disassemble(address: str = "RIP", count: int = 10) -> dict:
    if not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a string (e.g. 'RIP', '0x140001125', 'app.exe')")
    if not isinstance(count, int) or count <= 0 or count > 64:
        raise ToolError("Invalid 'count': must be an integer between 1 and 64")

    params = {"address": address.strip(), "count": count}
    data = query_debugger_pipe("disassemble", params)

    if "instructions" not in data or not isinstance(data["instructions"], list):
        raise ToolError("Malformed disassembly response from x64dbg: missing 'instructions' list")

    return data


@server.tool(
    name="set_breakpoint",
    description="Sets a standard software execution breakpoint at the specified address (hex string e.g. '0x140001125', register name 'RIP', or module name 'app.exe') when the debuggee is paused. Returns confirmation of the breakpoint address and type."
)
def set_breakpoint(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001125', 'RIP')")

    data = query_debugger_pipe("set_breakpoint", {"address": address.strip()})

    if "address" not in data or "success" not in data:
        raise ToolError("Malformed set_breakpoint response from x64dbg: missing required fields")

    return data


@server.tool(
    name="list_breakpoints",
    description="Lists all breakpoints currently set in the debuggee process, including address, status (enabled/active), hit count, type, and associated module."
)
def list_breakpoints() -> dict:
    data = query_debugger_pipe("list_breakpoints")

    if "count" not in data or "breakpoints" not in data or not isinstance(data["breakpoints"], list):
        raise ToolError("Malformed list_breakpoints response from x64dbg: missing required fields")

    return data


@server.tool(
    name="delete_breakpoint",
    description="Deletes an existing breakpoint at the specified address (hex string e.g. '0x140001125', register name 'RIP', or module name 'app.exe') when the debuggee is paused."
)
def delete_breakpoint(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001125', 'RIP')")

    data = query_debugger_pipe("delete_breakpoint", {"address": address.strip()})

    if "address" not in data or "deleted" not in data:
        raise ToolError("Malformed delete_breakpoint response from x64dbg: missing required fields")

    return data


@server.tool(
    name="step_into",
    description="Single-steps into the next instruction (following CALLs) when the debuggee is paused. Blocks until the step completes, a breakpoint is hit, an exception occurs, or timeout. Returns execution status, before and after RIP addresses, and the disassembled instruction at the new position."
)
def step_into(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 100 and 30000 ms")

    data = query_debugger_pipe("step_into", {"timeout_ms": timeout_ms}, timeout_sec=(timeout_ms / 1000.0) + 2.0)

    if "status" not in data:
        raise ToolError("Malformed step_into response from x64dbg: missing 'status' field")

    return data


@server.tool(
    name="resume",
    description="Resumes execution of the debuggee when paused. Returns after the transition to the running state is verified, or immediately if an initial breakpoint, exception, or termination occurs. Does not block indefinitely waiting for future stop events."
)
def resume(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 100 and 30000 ms")

    data = query_debugger_pipe("resume", {"timeout_ms": timeout_ms}, timeout_sec=(timeout_ms / 1000.0) + 2.0)

    if "status" not in data:
        raise ToolError("Malformed resume response from x64dbg: missing 'status' field")

    return data


@server.tool(
    name="pause",
    description="Pauses execution of a running debuggee. Returns after the transition to the paused state is verified, capturing the current RIP and instruction. If the debuggee is already paused, returns immediately with the current position."
)
def pause(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 100 and 30000 ms")

    data = query_debugger_pipe("pause", {"timeout_ms": timeout_ms}, timeout_sec=(timeout_ms / 1000.0) + 2.0)

    if "status" not in data:
        raise ToolError("Malformed pause response from x64dbg: missing 'status' field")

    return data


@server.tool(
    name="step_over",
    description="Steps over the next instruction (stepping over CALL subroutines) when the debuggee is paused. Blocks until the step completes, a breakpoint is hit, an exception occurs, or timeout. Returns execution status, before and after RIP addresses, and the disassembled instruction at the new position."
)
def step_over(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 100 and 30000 ms")

    data = query_debugger_pipe("step_over", {"timeout_ms": timeout_ms}, timeout_sec=(timeout_ms / 1000.0) + 2.0)

    if "status" not in data:
        raise ToolError("Malformed step_over response from x64dbg: missing 'status' field")

    return data


@server.tool(
    name="step_out",
    description="Executes instructions until the current function returns (Step Out / Run To Return) when the debuggee is paused. Unwinds call stacks based on frame stack pointer depth. Blocks until the return instruction is reached, a breakpoint is hit, an exception occurs, or timeout. Returns execution status, before and after RIP addresses, and the disassembled instruction at the return location."
)
def step_out(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms < 100 or timeout_ms > 30000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 100 and 30000 ms")

    data = query_debugger_pipe("step_out", {"timeout_ms": timeout_ms}, timeout_sec=(timeout_ms / 1000.0) + 2.0)

    if "status" not in data:
        raise ToolError("Malformed step_out response from x64dbg: missing 'status' field")

    return data


@server.tool(
    name="list_threads",
    description="Lists all threads in the debuggee process, including thread ID, start address, TEB address, instruction pointer (CIP/RIP), suspend count, priority, wait reason, last error, thread name, and active thread indicator."
)
def list_threads() -> dict:
    data = query_debugger_pipe("list_threads")

    if "count" not in data or "threads" not in data or not isinstance(data["threads"], list):
        raise ToolError("Malformed list_threads response from x64dbg: missing required fields")

    return data


@server.tool(
    name="switch_thread",
    description="Switches x64dbg's active debugging thread to the specified thread ID. Updates registers, disassembly, and stack context to target the newly selected active thread."
)
def switch_thread(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid thread_id parameter: must be a positive integer")

    data = query_debugger_pipe("switch_thread", {"thread_id": thread_id})
    return data


@server.tool(
    name="list_modules",
    description="Lists all loaded modules (executable and DLLs) in the debuggee process, including module name, filesystem path, base address, module size, entry point address, section count, and main executable identification."
)
def list_modules() -> dict:
    data = query_debugger_pipe("list_modules")

    if "count" not in data or "modules" not in data or not isinstance(data["modules"], list):
        raise ToolError("Malformed list_modules response from x64dbg: missing required fields")

    return data


@server.tool(
    name="list_module_sections",
    description="Lists the sections reported by x64dbg for a loaded module (identified by module name e.g. 'kernel32.dll' or base address e.g. '0x00007FF84BF40000'), including section name, absolute virtual address, and size in bytes."
)
def list_module_sections(module: str) -> dict:
    if not module or not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty string (e.g. 'kernel32.dll' or '0x00007FF84BF40000')")

    data = query_debugger_pipe("list_module_sections", {"module": module.strip()})

    if "count" not in data or "sections" not in data:
        raise ToolError("Malformed list_module_sections response from x64dbg: missing required fields")

    if not isinstance(data["sections"], list):
        raise ToolError("Malformed list_module_sections response from x64dbg: sections must be an array")

    return data


@server.tool(
    name="get_memory_region",
    description="Returns the Windows virtual-memory region containing a specified address in the debuggee process."
)
def get_memory_region(address: str) -> dict:
    if not address or not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x00007FF700001000')")

    data = query_debugger_pipe("get_memory_region", {"address": address.strip()})

    if "address" not in data or "region" not in data or not isinstance(data["region"], dict):
        raise ToolError("Malformed get_memory_region response from x64dbg: missing 'address' or 'region'")

    reg = data["region"]
    required_fields = ["base", "allocation_base", "size", "state", "protect", "type"]
    for f in required_fields:
        if f not in reg:
            raise ToolError(f"Malformed get_memory_region response: missing '{f}' in region")

    if not isinstance(reg["base"], str) or not reg["base"].startswith("0x"):
        raise ToolError("Malformed get_memory_region response: 'base' must be a hex string")

    if not isinstance(reg["size"], int) or reg["size"] < 0:
        raise ToolError("Malformed get_memory_region response: 'size' must be a non-negative integer")

    return data


@server.tool(
    name="list_memory_regions",
    description="Lists Windows virtual-memory regions of the debuggee process using bounded pagination."
)
def list_memory_regions(
    start_address: str | None = None,
    limit: int = 256,
    include_free: bool = False
) -> dict:
    if start_address is not None:
        if not isinstance(start_address, str) or not start_address.strip():
            raise ToolError("Invalid 'start_address': must be a non-empty string (e.g. '0x00007FF700001000') or None")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0 or limit > 1024:
        raise ToolError("Invalid 'limit': must be an integer between 1 and 1024")

    if not isinstance(include_free, bool):
        raise ToolError("Invalid 'include_free': must be a boolean")

    params = {
        "limit": limit,
        "include_free": include_free
    }
    if start_address is not None:
        params["start_address"] = start_address.strip()

    data = query_debugger_pipe("list_memory_regions", params)

    required_keys = ["start_address", "count", "has_more", "next_address", "regions"]
    for k in required_keys:
        if k not in data:
            raise ToolError(f"Malformed list_memory_regions response from x64dbg: missing '{k}'")

    if not isinstance(data["count"], int) or data["count"] < 0:
        raise ToolError("Malformed list_memory_regions response: 'count' must be a non-negative integer")

    if not isinstance(data["has_more"], bool):
        raise ToolError("Malformed list_memory_regions response: 'has_more' must be a boolean")

    if data["next_address"] is not None and not isinstance(data["next_address"], str):
        raise ToolError("Malformed list_memory_regions response: 'next_address' must be a hex string or null")

    if not isinstance(data["regions"], list):
        raise ToolError("Malformed list_memory_regions response: 'regions' must be an array")

    if data["count"] != len(data["regions"]):
        raise ToolError(f"Malformed list_memory_regions response: count ({data['count']}) != len(regions) ({len(data['regions'])})")

    for reg in data["regions"]:
        if not isinstance(reg, dict):
            raise ToolError("Malformed list_memory_regions response: region element must be an object")
        for f in ["base", "allocation_base", "size", "state", "state_raw", "allocation_protect", "allocation_protect_raw", "protect", "protect_raw", "type", "type_raw"]:
            if f not in reg:
                raise ToolError(f"Malformed list_memory_regions response: missing '{f}' in region")
        if not isinstance(reg["base"], str) or not reg["base"].startswith("0x"):
            raise ToolError("Malformed list_memory_regions response: 'base' must be a hex string")
        if not isinstance(reg["size"], int) or reg["size"] < 0:
            raise ToolError("Malformed list_memory_regions response: 'size' must be a non-negative integer")

    return data


@server.tool(
    name="get_xrefs",
    description="Returns cross-references recorded by x64dbg for a specified virtual address."
)
def get_xrefs(address: str) -> dict:
    if not address or not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x00007FF700001000' or 'RIP')")

    data = query_debugger_pipe("get_xrefs", {"address": address.strip()})

    required_keys = ["address", "count", "type", "type_raw", "references"]
    for k in required_keys:
        if k not in data:
            raise ToolError(f"Malformed get_xrefs response from x64dbg: missing '{k}'")

    if not isinstance(data["address"], str) or not data["address"].startswith("0x"):
        raise ToolError("Malformed get_xrefs response: 'address' must be a hex string")

    if not isinstance(data["count"], int) or data["count"] < 0:
        raise ToolError("Malformed get_xrefs response: 'count' must be a non-negative integer")

    if not isinstance(data["type"], str):
        raise ToolError("Malformed get_xrefs response: 'type' must be a string")

    if not isinstance(data["type_raw"], int):
        raise ToolError("Malformed get_xrefs response: 'type_raw' must be an integer")

    if not isinstance(data["references"], list):
        raise ToolError("Malformed get_xrefs response: 'references' must be an array")

    if data["count"] != len(data["references"]):
        raise ToolError(f"Malformed get_xrefs response: count ({data['count']}) != len(references) ({len(data['references'])})")

    for ref in data["references"]:
        if not isinstance(ref, dict):
            raise ToolError("Malformed get_xrefs response: reference element must be an object")
        for f in ["addr", "type", "type_raw"]:
            if f not in ref:
                raise ToolError(f"Malformed get_xrefs response: missing '{f}' in reference")
        if not isinstance(ref["addr"], str) or not ref["addr"].startswith("0x"):
            raise ToolError("Malformed get_xrefs response: reference 'addr' must be a hex string")
        if not isinstance(ref["type"], str):
            raise ToolError("Malformed get_xrefs response: reference 'type' must be a string")
        if not isinstance(ref["type_raw"], int):
            raise ToolError("Malformed get_xrefs response: reference 'type_raw' must be an integer")

    return data


@server.tool(
    name="get_address_info",
    description="Returns x64dbg module, exact-symbol, and function context for a specified virtual address."
)
def get_address_info(address: str) -> dict:
    if not address or not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x00007FF700001000' or 'RIP')")

    data = query_debugger_pipe("get_address_info", {"address": address.strip()})

    required_keys = ["address", "module", "symbol", "function"]
    for k in required_keys:
        if k not in data:
            raise ToolError(f"Malformed get_address_info response from x64dbg: missing '{k}'")

    if not isinstance(data["address"], str) or not data["address"].startswith("0x"):
        raise ToolError("Malformed get_address_info response: 'address' must be a hex string")

    for sec in ["module", "symbol", "function"]:
        if not isinstance(data[sec], dict):
            raise ToolError(f"Malformed get_address_info response: '{sec}' must be an object")
        if "found" not in data[sec] or not isinstance(data[sec]["found"], bool):
            raise ToolError(f"Malformed get_address_info response: '{sec}.found' must be a boolean")

    if data["module"]["found"]:
        for f in ["name", "base", "size", "entry", "section_count", "path", "offset"]:
            if f not in data["module"]:
                raise ToolError(f"Malformed get_address_info response: missing '{f}' in module")
        if not isinstance(data["module"]["name"], str):
            raise ToolError("Malformed get_address_info response: module 'name' must be a string")
        if not isinstance(data["module"]["base"], str) or not data["module"]["base"].startswith("0x"):
            raise ToolError("Malformed get_address_info response: module 'base' must be a hex string")
        if not isinstance(data["module"]["size"], int) or data["module"]["size"] < 0:
            raise ToolError("Malformed get_address_info response: module 'size' must be non-negative int")
        if not isinstance(data["module"]["entry"], str) or not data["module"]["entry"].startswith("0x"):
            raise ToolError("Malformed get_address_info response: module 'entry' must be a hex string")
        if not isinstance(data["module"]["section_count"], int) or data["module"]["section_count"] < 0:
            raise ToolError("Malformed get_address_info response: module 'section_count' must be non-negative int")
        if not isinstance(data["module"]["path"], str):
            raise ToolError("Malformed get_address_info response: module 'path' must be a string")
        if not isinstance(data["module"]["offset"], int) or data["module"]["offset"] < 0:
            raise ToolError("Malformed get_address_info response: module 'offset' must be non-negative int")

    if data["symbol"]["found"]:
        for f in ["address", "name", "decorated_name", "type", "type_raw", "ordinal", "displacement"]:
            if f not in data["symbol"]:
                raise ToolError(f"Malformed get_address_info response: missing '{f}' in symbol")
        if not isinstance(data["symbol"]["address"], str) or not data["symbol"]["address"].startswith("0x"):
            raise ToolError("Malformed get_address_info response: symbol 'address' must be a hex string")
        if not isinstance(data["symbol"]["name"], str) or not data["symbol"]["name"]:
            raise ToolError("Malformed get_address_info response: symbol 'name' must be a non-empty string")
        if data["symbol"]["decorated_name"] is not None and not isinstance(data["symbol"]["decorated_name"], str):
            raise ToolError("Malformed get_address_info response: symbol 'decorated_name' must be string or null")
        if not isinstance(data["symbol"]["type"], str):
            raise ToolError("Malformed get_address_info response: symbol 'type' must be a string")
        if not isinstance(data["symbol"]["type_raw"], int):
            raise ToolError("Malformed get_address_info response: symbol 'type_raw' must be an integer")
        if not isinstance(data["symbol"]["ordinal"], int) or data["symbol"]["ordinal"] < 0:
            raise ToolError("Malformed get_address_info response: symbol 'ordinal' must be a non-negative integer")
        if not isinstance(data["symbol"]["displacement"], int) or data["symbol"]["displacement"] < 0:
            raise ToolError("Malformed get_address_info response: symbol 'displacement' must be a non-negative int")

    if data["function"]["found"]:
        for f in ["start", "end", "displacement"]:
            if f not in data["function"]:
                raise ToolError(f"Malformed get_address_info response: missing '{f}' in function")
        if not isinstance(data["function"]["start"], str) or not data["function"]["start"].startswith("0x"):
            raise ToolError("Malformed get_address_info response: function 'start' must be a hex string")
        if not isinstance(data["function"]["end"], str) or not data["function"]["end"].startswith("0x"):
            raise ToolError("Malformed get_address_info response: function 'end' must be a hex string")
        if not isinstance(data["function"]["displacement"], int) or data["function"]["displacement"] < 0:
            raise ToolError("Malformed get_address_info response: function 'displacement' must be a non-negative int")

    return data


@server.tool(
    name="get_call_stack",
    description="Returns the structured call stack frames for the currently active x64dbg thread."
)
def get_call_stack() -> dict:
    data = query_debugger_pipe("get_call_stack")

    for k in ["thread_id", "count", "frames"]:
        if k not in data:
            raise ToolError(f"Malformed get_call_stack response from x64dbg: missing '{k}'")

    if not isinstance(data["thread_id"], int) or data["thread_id"] < 0:
        raise ToolError("Malformed get_call_stack response: 'thread_id' must be a non-negative integer")
    if not isinstance(data["count"], int) or data["count"] < 0:
        raise ToolError("Malformed get_call_stack response: 'count' must be a non-negative integer")
    if not isinstance(data["frames"], list):
        raise ToolError("Malformed get_call_stack response: 'frames' must be a list")
    if len(data["frames"]) != data["count"]:
        raise ToolError(f"Malformed get_call_stack response: frames count ({len(data['frames'])}) does not match 'count' ({data['count']})")

    for f in data["frames"]:
        if not isinstance(f, dict):
            raise ToolError("Malformed get_call_stack response: frame item must be an object")
        for k in ["index", "address", "from", "to", "comment"]:
            if k not in f:
                raise ToolError(f"Malformed get_call_stack response: missing '{k}' in frame")
        if not isinstance(f["index"], int) or f["index"] < 0:
            raise ToolError("Malformed get_call_stack response: frame 'index' must be a non-negative integer")
        for addr_k in ["address", "from", "to"]:
            if not isinstance(f[addr_k], str) or not f[addr_k].startswith("0x"):
                raise ToolError(f"Malformed get_call_stack response: frame '{addr_k}' must be a hex string")
        if not isinstance(f["comment"], str):
            raise ToolError("Malformed get_call_stack response: frame 'comment' must be a string")

    return data


@server.tool(
    name="eval_expression",
    description="Evaluates a mathematical, register, or memory expression using x64dbg's native expression parser."
)
def eval_expression(expression: str) -> dict:
    if not expression or not isinstance(expression, str) or not expression.strip():
        raise ToolError("Invalid 'expression': must be a non-empty string (e.g. 'rax + 0x20', '[rsp]', '1+2')")

    cleaned = expression.strip()
    if len(cleaned) > 512:
        raise ToolError("Expression string too long: maximum 512 characters allowed")

    data = query_debugger_pipe("eval_expression", {"expression": cleaned})

    for k in ["expression", "value", "decimal"]:
        if k not in data:
            raise ToolError(f"Malformed eval_expression response from x64dbg: missing '{k}'")

    if not isinstance(data["expression"], str):
        raise ToolError("Malformed eval_expression response: 'expression' must be a string")
    if not isinstance(data["value"], str) or not data["value"].startswith("0x"):
        raise ToolError("Malformed eval_expression response: 'value' must be a hex string")
    if not isinstance(data["decimal"], int) or data["decimal"] < 0:
        raise ToolError("Malformed eval_expression response: 'decimal' must be a non-negative integer")

    return data


@server.tool(
    name="find_pattern",
    description="Searches memory for a byte pattern with optional wildcards (e.g. '48 83 EC ??', '48 8D 0D ? ? ? ?') across a specified address range or module. Returns matching virtual addresses, match count, scanned bytes, and truncation status."
)
def find_pattern(
    pattern: str,
    start_address: str = None,
    size: int = None,
    max_matches: int = 20
) -> dict:
    if not pattern or not isinstance(pattern, str) or not pattern.strip():
        raise ToolError("Invalid 'pattern': must be a non-empty string of hex bytes with optional wildcards (e.g. '48 83 EC ??')")

    cleaned_pattern = pattern.strip()
    if len(cleaned_pattern) > 512:
        raise ToolError("Pattern string too long: maximum 512 characters allowed")

    params = {"pattern": cleaned_pattern}

    if start_address is not None:
        if not isinstance(start_address, str) or not start_address.strip():
            raise ToolError("Invalid 'start_address': must be a non-empty string (e.g. '0x140001000' or 'main.exe')")
        params["start_address"] = start_address.strip()

    if size is not None:
        if not isinstance(size, int) or size <= 0 or size > 67108864:
            raise ToolError("Invalid 'size': must be an integer between 1 and 67108864 bytes (64 MB)")
        params["size"] = size

    if max_matches is not None:
        if not isinstance(max_matches, int) or max_matches < 1 or max_matches > 100:
            raise ToolError("Invalid 'max_matches': must be an integer between 1 and 100")
        params["max_matches"] = max_matches

    data = query_debugger_pipe("find_pattern", params)

    required_keys = ["pattern", "start_address", "size", "scanned_bytes", "match_count", "truncated", "matches"]
    for k in required_keys:
        if k not in data:
            raise ToolError(f"Malformed find_pattern response from x64dbg: missing '{k}'")

    if not isinstance(data["pattern"], str):
        raise ToolError("Malformed find_pattern response: 'pattern' must be a string")
    if not isinstance(data["start_address"], str) or not data["start_address"].startswith("0x"):
        raise ToolError("Malformed find_pattern response: 'start_address' must be a hex string")
    if not isinstance(data["size"], int) or data["size"] < 0:
        raise ToolError("Malformed find_pattern response: 'size' must be a non-negative integer")
    if not isinstance(data["scanned_bytes"], int) or data["scanned_bytes"] < 0:
        raise ToolError("Malformed find_pattern response: 'scanned_bytes' must be a non-negative integer")
    if not isinstance(data["match_count"], int) or data["match_count"] < 0:
        raise ToolError("Malformed find_pattern response: 'match_count' must be a non-negative integer")
    if not isinstance(data["truncated"], bool):
        raise ToolError("Malformed find_pattern response: 'truncated' must be a boolean")
    if not isinstance(data["matches"], list):
        raise ToolError("Malformed find_pattern response: 'matches' must be a list")
    if len(data["matches"]) != data["match_count"]:
        raise ToolError(f"Malformed find_pattern response: matches count ({len(data['matches'])}) does not match 'match_count' ({data['match_count']})")

    for m in data["matches"]:
        if not isinstance(m, str) or not m.startswith("0x"):
            raise ToolError(f"Malformed find_pattern response: match item '{m}' must be a hex string starting with '0x'")

    return data


@server.tool(
    name="write_memory",
    description="Writes raw bytes (specified as a hex string e.g. '90 90 90' or '0x90, 0x90') to the debuggee process memory at the given virtual address (hex string e.g. '0x140001000' or register name 'RIP', 'RSP') when the debuggee is paused. By default, reads back the written memory to verify the write succeeded. Maximum 4096 bytes per call."
)
def write_memory(address: str, data: str, verify: bool = True) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000', 'RIP', 'RSP')")
    if not isinstance(data, str) or not data.strip():
        raise ToolError("Invalid 'data': must be a non-empty hex string (e.g. '90 90 90', 'CC')")
    if not isinstance(verify, bool):
        raise ToolError("Invalid 'verify': must be a boolean (True/False)")

    params = {
        "address": address.strip(),
        "data": data.strip(),
        "verify": verify
    }

    res = query_debugger_pipe("write_memory", params)

    required_keys = ["address", "bytes_written", "verified"]
    for k in required_keys:
        if k not in res:
            raise ToolError(f"Malformed write_memory response from x64dbg: missing '{k}'")

    if not isinstance(res["address"], str) or not res["address"].startswith("0x"):
        raise ToolError("Malformed write_memory response: 'address' must be a hex string")
    if not isinstance(res["bytes_written"], int) or res["bytes_written"] <= 0:
        raise ToolError("Malformed write_memory response: 'bytes_written' must be a positive integer")
    if not isinstance(res["verified"], bool):
        raise ToolError("Malformed write_memory response: 'verified' must be a boolean")

    return res


@server.tool(
    name="set_register",
    description="Sets the value of a CPU register (e.g. 'rax', 'rip', 'rsp', 'eflags', 'eax', etc.) when the debuggee is paused. Accepts integer or hex string values (e.g. 0x1234 or '0x1234' or 'rax+4'). Returns the register name, previous value, and confirmed new value."
)
def set_register(register: str, value: Union[str, int]) -> dict:
    if not isinstance(register, str) or not register.strip():
        raise ToolError("Invalid 'register': must be a non-empty string naming a CPU register (e.g. 'rax', 'rip', 'eflags')")
    if not isinstance(value, (str, int)):
        raise ToolError("Invalid 'value': must be an integer or a string expression (e.g. '0x1000', 'rax+8')")
    if isinstance(value, str) and not value.strip():
        raise ToolError("Invalid 'value': string value cannot be empty")

    params = {
        "register": register.strip(),
        "value": value if isinstance(value, int) else value.strip()
    }

    res = query_debugger_pipe("set_register", params)

    required_keys = ["register", "previous_value", "value"]
    for k in required_keys:
        if k not in res:
            raise ToolError(f"Malformed set_register response from x64dbg: missing '{k}'")

    if not isinstance(res["register"], str):
        raise ToolError("Malformed set_register response: 'register' must be a string")
    if not isinstance(res["previous_value"], str) or not res["previous_value"].startswith("0x"):
        raise ToolError("Malformed set_register response: 'previous_value' must be a hex string")
    if not isinstance(res["value"], str) or not res["value"].startswith("0x"):
        raise ToolError("Malformed set_register response: 'value' must be a hex string")

    return res


@server.tool(
    name="enable_breakpoint",
    description="Enables or disables an existing breakpoint at the given address without deleting it. By default enabled is True."
)
def enable_breakpoint(address: str, enabled: bool = True) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'main.exe')")
    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean (True/False)")

    params = {"address": address.strip(), "enabled": enabled}
    res = query_debugger_pipe("enable_breakpoint", params)

    if "address" not in res or "enabled" not in res:
        raise ToolError("Malformed enable_breakpoint response from x64dbg: missing required fields")

    return res


@server.tool(
    name="set_comment",
    description="Sets or clears an analysis comment at a specified virtual address in the debuggee process. Pass an empty string to clear the comment."
)
def set_comment(address: str, comment: str = "") -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")
    if not isinstance(comment, str):
        raise ToolError("Invalid 'comment': must be a string")

    params = {"address": address.strip(), "comment": comment}
    res = query_debugger_pipe("set_comment", params)

    if "address" not in res or "comment" not in res:
        raise ToolError("Malformed set_comment response from x64dbg: missing required fields")

    return res


@server.tool(
    name="get_comment",
    description="Retrieves the analysis comment at a specified virtual address if one exists."
)
def get_comment(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    params = {"address": address.strip()}
    res = query_debugger_pipe("get_comment", params)

    if "address" not in res or "found" not in res or "comment" not in res:
        raise ToolError("Malformed get_comment response from x64dbg: missing required fields")

    return res


@server.tool(
    name="set_label",
    description="Assigns a user-defined symbolic label to a specified virtual address in the debuggee process. Pass an empty string to clear the label."
)
def set_label(address: str, label: str = "") -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")
    if not isinstance(label, str):
        raise ToolError("Invalid 'label': must be a string")

    params = {"address": address.strip(), "label": label}
    res = query_debugger_pipe("set_label", params)

    if "address" not in res or "label" not in res:
        raise ToolError("Malformed set_label response from x64dbg: missing required fields")

    return res


@server.tool(
    name="get_label",
    description="Retrieves the user-defined symbolic label at a specified virtual address if one exists."
)
def get_label(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    params = {"address": address.strip()}
    res = query_debugger_pipe("get_label", params)

    if "address" not in res or "found" not in res or "label" not in res:
        raise ToolError("Malformed get_label response from x64dbg: missing required fields")

    return res


@server.tool(
    name="set_bookmark",
    description="Sets or clears a navigation bookmark at a specified virtual address in the debuggee."
)
def set_bookmark(address: str, bookmarked: bool = True) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")
    if not isinstance(bookmarked, bool):
        raise ToolError("Invalid 'bookmarked': must be a boolean (True/False)")

    params = {"address": address.strip(), "bookmarked": bookmarked}
    res = query_debugger_pipe("set_bookmark", params)

    if "address" not in res or "bookmarked" not in res:
        raise ToolError("Malformed set_bookmark response from x64dbg: missing required fields")

    return res


@server.tool(
    name="get_bookmark",
    description="Checks whether a navigation bookmark is set at a specified virtual address."
)
def get_bookmark(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    params = {"address": address.strip()}
    res = query_debugger_pipe("get_bookmark", params)

    if "address" not in res or "bookmarked" not in res:
        raise ToolError("Malformed get_bookmark response from x64dbg: missing required fields")

    return res


@server.tool(
    name="get_function_boundary",
    description="Identifies the start address, end address, total byte size, and instruction count of the function enclosing the given address."
)
def get_function_boundary(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    params = {"address": address.strip()}
    res = query_debugger_pipe("get_function_boundary", params)

    if "address" not in res or "found" not in res:
        raise ToolError("Malformed get_function_boundary response from x64dbg: missing required fields")

    return res


@server.tool(
    name="assemble",
    description="Assembles an x86/x64 instruction string into machine code bytes at a target address. Optionally writes the assembled machine code directly into debuggee memory when paused."
)
def assemble(instruction: str, address: str = "RIP", write_to_memory: bool = False) -> dict:
    if not isinstance(instruction, str) or not instruction.strip():
        raise ToolError("Invalid 'instruction': must be a non-empty assembly string (e.g. 'nop', 'mov rax, 1', 'jmp 0x140001000')")
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. 'RIP', '0x140001000')")
    if not isinstance(write_to_memory, bool):
        raise ToolError("Invalid 'write_to_memory': must be a boolean (True/False)")

    params = {
        "instruction": instruction.strip(),
        "address": address.strip(),
        "write_to_memory": write_to_memory
    }
    res = query_debugger_pipe("assemble", params)

    required_keys = ["address", "instruction", "hex", "size", "written"]
    for k in required_keys:
        if k not in res:
            raise ToolError(f"Malformed assemble response from x64dbg: missing '{k}'")

    return res


@server.tool(
    name="list_imports",
    description="Enumerates imported functions for a specified module with pagination. Supports module name (e.g. 'kernel32.dll') or base address. Returns total count and paginated list with IAT RVAs/VAs and ordinals."
)
def list_imports(module: str, offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty string (e.g. 'kernel32.dll' or '0x7ff...')")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params = {
        "module": module.strip(),
        "offset": offset,
        "limit": min(limit, 500)
    }
    res = query_debugger_pipe("list_imports", params)

    if "imports" not in res or "total_count" not in res:
        raise ToolError("Malformed list_imports response from x64dbg: missing 'imports' or 'total_count'")

    return res


@server.tool(
    name="list_exports",
    description="Enumerates exported functions/symbols for a specified module with pagination. Supports module name (e.g. 'ntdll.dll') or base address. Returns total count and paginated list with RVAs/VAs, ordinals, and forwarded symbols."
)
def list_exports(module: str, offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty string (e.g. 'ntdll.dll' or '0x7ff...')")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params = {
        "module": module.strip(),
        "offset": offset,
        "limit": min(limit, 500)
    }
    res = query_debugger_pipe("list_exports", params)

    if "exports" not in res or "total_count" not in res:
        raise ToolError("Malformed list_exports response from x64dbg: missing 'exports' or 'total_count'")

    return res


@server.tool(
    name="get_peb_info",
    description="Inspects the Process Environment Block (PEB) of the current debuggee process when paused. Extracts observed fields: PID, PEB address, BeingDebugged flag, NtGlobalFlag, ProcessHeap pointer, and ImageBaseAddress."
)
def get_peb_info() -> dict:
    res = query_debugger_pipe("get_peb_info")

    required_keys = ["process_id", "peb_address", "being_debugged", "nt_global_flag", "process_heap", "image_base_address"]
    for k in required_keys:
        if k not in res:
            raise ToolError(f"Malformed get_peb_info response from x64dbg: missing '{k}'")

    return res


@server.tool(
    name="get_teb_info",
    description="Inspects the Thread Environment Block (TEB) and NT_TIB structure when paused. If thread_id is omitted, defaults to the currently active thread; otherwise inspects the specified thread ID. Extracts TEB address, StackBase, StackLimit, and Self pointer."
)
def get_teb_info(thread_id: int | None = None) -> dict:
    params = {}
    if thread_id is not None:
        if not isinstance(thread_id, int) or thread_id <= 0:
            raise ToolError("Invalid 'thread_id': must be a positive integer")
        params["thread_id"] = thread_id

    res = query_debugger_pipe("get_teb_info", params)

    required_keys = ["thread_id", "teb_address", "stack_base", "stack_limit", "self"]
    for k in required_keys:
        if k not in res:
            raise ToolError(f"Malformed get_teb_info response from x64dbg: missing '{k}'")

    return res


@server.tool(
    name="get_command_line",
    description="Retrieves the command line string passed to the debugged process using the official debugger API."
)
def get_command_line() -> dict:
    res = query_debugger_pipe("get_command_line")
    if "command_line" not in res:
        raise ToolError("Malformed get_command_line response from x64dbg: missing 'command_line'")
    return res


@server.tool(
    name="get_seh_chain",
    description="Enumerates the Structured Exception Handling (SEH) chain records for the current debuggee context when paused. Returns handler and frame addresses with resolved symbol/module names."
)
def get_seh_chain() -> dict:
    res = query_debugger_pipe("get_seh_chain")
    if "count" not in res or "records" not in res:
        raise ToolError("Malformed get_seh_chain response from x64dbg: missing 'count' or 'records'")
    return res


@server.tool(
    name="get_page_rights",
    description="Returns x64dbg's textual page-rights representation (e.g. 'ExecuteRead', 'ReadWrite') for a virtual memory address, alongside Windows memory protection attributes."
)
def get_page_rights(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")
    res = query_debugger_pipe("get_page_rights", {"address": address.strip()})
    if "address" not in res or "found" not in res:
        raise ToolError("Malformed get_page_rights response from x64dbg: missing required fields")
    return res


@server.tool(
    name="list_heaps",
    description="Enumerates memory heaps allocated for the current debuggee process when paused. Returns base address, size, and flags for each heap."
)
def list_heaps() -> dict:
    res = query_debugger_pipe("list_heaps")
    if "count" not in res or "heaps" not in res:
        raise ToolError("Malformed list_heaps response from x64dbg: missing 'count' or 'heaps'")
    return res


@server.tool(
    name="list_handles",
    description="Enumerates open handles owned by the debuggee process when paused, with pagination. Returns handle value, type number, type name, granted access mask, and resolved object name."
)
def list_handles(offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    params = {
        "offset": offset,
        "limit": min(limit, 200)
    }
    res = query_debugger_pipe("list_handles", params)
    if "total_count" not in res or "handles" not in res:
        raise ToolError("Malformed list_handles response from x64dbg: missing 'total_count' or 'handles'")
    return res


@server.tool(
    name="get_handle_info",
    description="Inspects a specific debuggee handle value when paused. Returns whether the handle exists, its type name, and resolved object name."
)
def get_handle_info(handle: str) -> dict:
    if not isinstance(handle, str) or not handle.strip():
        raise ToolError("Invalid 'handle': must be a non-empty handle string (e.g. '0x124' or '124')")
    res = query_debugger_pipe("get_handle_info", {"handle": handle.strip()})
    if "handle" not in res or "found" not in res:
        raise ToolError("Malformed get_handle_info response from x64dbg: missing required fields")
    return res


@server.tool(
    name="list_tcp_connections",
    description="Enumerates active TCP connections associated with the debugged process (filtered by PID in x64dbg engine). Returns local/remote IP addresses and ports, state text, and state code."
)
def list_tcp_connections() -> dict:
    res = query_debugger_pipe("list_tcp_connections")
    if "count" not in res or "connections" not in res:
        raise ToolError("Malformed list_tcp_connections response from x64dbg: missing 'count' or 'connections'")
    return res


@server.tool(
    name="list_windows",
    description="Enumerates window handles owned by threads in the debugged process. Returns window handle, parent handle, thread ID, styles, window procedure address, enabled status, title, and window class."
)
def list_windows() -> dict:
    res = query_debugger_pipe("list_windows")
    if "count" not in res or "windows" not in res:
        raise ToolError("Malformed list_windows response from x64dbg: missing 'count' or 'windows'")
    return res


@server.tool(
    name="patch_memory",
    description="Applies a tracked memory patch to the debuggee process when paused. Uses x64dbg's patch engine so modifications participate in the debugger's patch table, can be enumerated, queried, and restored."
)
def patch_memory(address: str, data: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")
    if not isinstance(data, str) or not data.strip():
        raise ToolError("Invalid 'data': must be a non-empty string of hex bytes (e.g. '90 90' or 'EB FE')")

    res = query_debugger_pipe("patch_memory", {"address": address.strip(), "data": data.strip()})
    for k in ["address", "bytes_patched", "old_bytes", "new_bytes", "patched"]:
        if k not in res:
            raise ToolError(f"Malformed patch_memory response: missing '{k}'")
    return res


@server.tool(
    name="list_patches",
    description="Enumerates tracked memory patches currently registered in x64dbg's patch system with pagination. Returns total count, original bytes, and modified bytes with absolute virtual addresses."
)
def list_patches(offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params = {"offset": offset, "limit": min(limit, 500)}
    res = query_debugger_pipe("list_patches", params)
    for k in ["total_count", "offset", "limit", "patches"]:
        if k not in res:
            raise ToolError(f"Malformed list_patches response: missing '{k}'")
    return res


@server.tool(
    name="get_patch",
    description="Queries x64dbg's tracked patch system for a specific virtual address. Returns whether a tracked patch exists at the address, its module, old byte, and new byte."
)
def get_patch(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    res = query_debugger_pipe("get_patch", {"address": address.strip()})
    if "address" not in res or "found" not in res:
        raise ToolError("Malformed get_patch response: missing 'address' or 'found'")
    return res


@server.tool(
    name="restore_patch",
    description="Restores the original byte at a specified patched address and removes the patch from x64dbg's tracked patch table when paused."
)
def restore_patch(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string (e.g. '0x140001000' or 'RIP')")

    res = query_debugger_pipe("restore_patch", {"address": address.strip()})
    if "address" not in res or "found" not in res or "restored" not in res:
        raise ToolError("Malformed restore_patch response: missing required fields")
    return res


@server.tool(
    name="restore_patches_range",
    description="Restores original bytes for all tracked patches within an address range [start_address, end_address] when paused. The address span must not exceed 65,536 bytes."
)
def restore_patches_range(start_address: str, end_address: str) -> dict:
    if not isinstance(start_address, str) or not start_address.strip():
        raise ToolError("Invalid 'start_address': must be a non-empty string")
    if not isinstance(end_address, str) or not end_address.strip():
        raise ToolError("Invalid 'end_address': must be a non-empty string")

    res = query_debugger_pipe("restore_patches_range", {
        "start_address": start_address.strip(),
        "end_address": end_address.strip()
    })
    for k in ["start_address", "end_address", "patches_restored"]:
        if k not in res:
            raise ToolError(f"Malformed restore_patches_range response: missing '{k}'")
    return res


@server.tool(
    name="va_to_file_offset",
    description="Translates a virtual memory address (VA) into the corresponding physical file offset in the backing PE file on disk."
)
def va_to_file_offset(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")

    res = query_debugger_pipe("va_to_file_offset", {"address": address.strip()})
    if "address" not in res or "found" not in res:
        raise ToolError("Malformed va_to_file_offset response: missing required fields")
    return res


@server.tool(
    name="file_offset_to_va",
    description="Translates a physical file offset within a specified module into the corresponding virtual memory address (VA) in the loaded debuggee."
)
def file_offset_to_va(module: str, offset: int) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")

    res = query_debugger_pipe("file_offset_to_va", {"module": module.strip(), "offset": offset})
    if "module" not in res or "found" not in res:
        raise ToolError("Malformed file_offset_to_va response: missing required fields")
    return res


@server.tool(
    name="get_relocation",
    description="Queries PE base relocation table information for a specific virtual address. Returns whether a relocation covers the address, its RVA, type, and size."
)
def get_relocation(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")

    res = query_debugger_pipe("get_relocation", {"address": address.strip()})
    if "address" not in res or "found" not in res:
        raise ToolError("Malformed get_relocation response: missing required fields")
    return res


@server.tool(
    name="list_relocations",
    description="Enumerates PE base relocations within a specified address range [address, address + size) with pagination. Returns total count, absolute addresses, RVAs, relocation types, and sizes."
)
def list_relocations(address: str, size: int, offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params = {
        "address": address.strip(),
        "size": size,
        "offset": offset,
        "limit": min(limit, 500)
    }
    res = query_debugger_pipe("list_relocations", params)
    for k in ["address", "size", "total_count", "offset", "limit", "relocations"]:
        if k not in res:
            raise ToolError(f"Malformed list_relocations response: missing '{k}'")
    return res


@server.tool(
    name="resolve_symbol",
    description="Resolves a symbol name, API expression, or module-qualified symbol (e.g. 'ExitProcess', 'kernel32.ExitProcess', 'main') to its virtual address. Clearly distinguishes exact symbol matches from user labels or unresolved names."
)
def resolve_symbol(symbol: str) -> dict:
    if not isinstance(symbol, str) or not symbol.strip():
        raise ToolError("Invalid 'symbol': must be a non-empty string (e.g. 'ExitProcess', 'kernel32.CreateFileW', 'main')")

    res = query_debugger_pipe("resolve_symbol", {"symbol": symbol.strip()})
    if "input" not in res or "resolved" not in res:
        raise ToolError("Malformed resolve_symbol response: missing required fields")
    return res


@server.tool(
    name="list_symbols",
    description="Enumerates symbols for a specified module with optional RVA/address range filtering, symbol type masking ('all', 'symbol', 'export', 'import'), and pagination. Each entry includes address, RVA, name, demangled name, and symbol type."
)
def list_symbols(
    module: str,
    start_rva: str | int | None = None,
    end_rva: str | int | None = None,
    symbol_mask: str = "all",
    offset: int = 0,
    limit: int = 100
) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name or base address (e.g. 'ntdll.dll' or '0x7FF...')")
    if not isinstance(symbol_mask, str) or symbol_mask.lower() not in ["all", "symbol", "export", "import"]:
        raise ToolError("Invalid 'symbol_mask': must be 'all', 'symbol', 'export', or 'import'")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params: dict = {
        "module": module.strip(),
        "symbol_mask": symbol_mask.lower(),
        "offset": offset,
        "limit": min(limit, 500)
    }
    if start_rva is not None:
        params["start_rva"] = str(start_rva).strip()
    if end_rva is not None:
        params["end_rva"] = str(end_rva).strip()

    res = query_debugger_pipe("list_symbols", params)
    for k in ["module", "base", "offset", "limit", "count", "has_more", "symbols"]:
        if k not in res:
            raise ToolError(f"Malformed list_symbols response: missing '{k}'")
    return res


@server.tool(
    name="get_symbol_status",
    description="Queries the symbol loading status for a specified module ('unloaded', 'loading', 'loaded')."
)
def get_symbol_status(module: str) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name or base address (e.g. 'kernel32.dll')")

    res = query_debugger_pipe("get_symbol_status", {"module": module.strip()})
    for k in ["module", "base", "status", "status_string"]:
        if k not in res:
            raise ToolError(f"Malformed get_symbol_status response: missing '{k}'")
    return res


@server.tool(
    name="get_source_location",
    description="Resolves a code virtual address to its source file name and line number if debug symbol source information is available."
)
def get_source_location(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string (e.g. '0x140001000' or 'RIP')")

    res = query_debugger_pipe("get_source_location", {"address": address.strip()})
    if "found" not in res or "address" not in res:
        raise ToolError("Malformed get_source_location response: missing required fields")
    return res


@server.tool(
    name="find_source_address",
    description="Resolves a source file path and line number within a module to its code virtual address."
)
def find_source_address(module: str, source_file: str, line: int) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name or base address")
    if not isinstance(source_file, str) or not source_file.strip():
        raise ToolError("Invalid 'source_file': must be a non-empty source file path")
    if not isinstance(line, int) or line <= 0:
        raise ToolError("Invalid 'line': must be a positive integer")

    params = {
        "module": module.strip(),
        "source_file": source_file.strip(),
        "line": line
    }
    res = query_debugger_pipe("find_source_address", params)
    if "found" not in res or "module" not in res or "source_file" not in res or "line" not in res:
        raise ToolError("Malformed find_source_address response: missing required fields")
    return res


@server.tool(
    name="symbol_autocomplete",
    description="Provides symbol name autocompletion suggestions matching a given prefix across module exports, PDB symbols, and user labels."
)
def symbol_autocomplete(prefix: str = "", max_results: int = 20) -> dict:
    if not isinstance(prefix, str):
        raise ToolError("Invalid 'prefix': must be a string")
    if not isinstance(max_results, int) or max_results <= 0:
        raise ToolError("Invalid 'max_results': must be a positive integer")

    params = {
        "prefix": prefix,
        "max_results": min(max_results, 100)
    }
    res = query_debugger_pipe("symbol_autocomplete", params)
    if "prefix" not in res or "count" not in res or "symbols" not in res:
        raise ToolError("Malformed symbol_autocomplete response: missing required fields")
    return res


@server.tool(
    name="list_exceptions",
    description="Lists Windows exceptions and NTSTATUS definitions from x64dbg's exception database with pagination and optional filter."
)
def list_exceptions(offset: int = 0, limit: int = 100, filter: str = "") -> dict:
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be a string")

    params = {
        "offset": offset,
        "limit": min(limit, 200),
        "filter": filter.strip()
    }
    res = query_debugger_pipe("list_exceptions", params)
    for k in ["total", "offset", "limit", "exceptions"]:
        if k not in res:
            raise ToolError(f"Malformed list_exceptions response: missing '{k}'")
    return res


@server.tool(
    name="get_exception_info",
    description="Looks up structured information, symbolic name, aliases, and breakpoint status for an exception code or name."
)
def get_exception_info(exception: Union[str, int]) -> dict:
    if isinstance(exception, int):
        ex_str = f"0x{exception:X}"
    elif isinstance(exception, str) and exception.strip():
        ex_str = exception.strip()
    else:
        raise ToolError("Invalid 'exception': must be a non-empty string or integer exception code/name")

    res = query_debugger_pipe("get_exception_info", {"exception": ex_str})
    for k in ["code", "name", "breakpoint_set", "breakpoint_enabled", "aliases"]:
        if k not in res:
            raise ToolError(f"Malformed get_exception_info response: missing '{k}'")
    return res


@server.tool(
    name="set_exception_breakpoint",
    description="Sets a breakpoint on a specific exception code or symbolic name (e.g. 0xC0000005, 'STATUS_ACCESS_VIOLATION')."
)
def set_exception_breakpoint(code: Union[str, int], chance: str = "first") -> dict:
    if isinstance(code, int):
        code_str = f"0x{code:X}"
    elif isinstance(code, str) and code.strip():
        code_str = code.strip()
    else:
        raise ToolError("Invalid 'code': must be a non-empty string or integer exception code/name")

    if not isinstance(chance, str) or chance.lower() not in ("first", "second", "all"):
        raise ToolError("Invalid 'chance': must be 'first', 'second', or 'all'")

    params = {
        "code": code_str,
        "chance": chance.lower()
    }
    res = query_debugger_pipe("set_exception_breakpoint", params)
    for k in ["code", "chance", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_exception_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="delete_exception_breakpoint",
    description="Deletes an existing exception breakpoint for a given exception code or symbolic name."
)
def delete_exception_breakpoint(code: Union[str, int]) -> dict:
    if isinstance(code, int):
        code_str = f"0x{code:X}"
    elif isinstance(code, str) and code.strip():
        code_str = code.strip()
    else:
        raise ToolError("Invalid 'code': must be a non-empty string or integer exception code/name")

    res = query_debugger_pipe("delete_exception_breakpoint", {"code": code_str})
    for k in ["code", "deleted"]:
        if k not in res:
            raise ToolError(f"Malformed delete_exception_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="enable_exception_breakpoint",
    description="Enables or disables an existing exception breakpoint."
)
def enable_exception_breakpoint(code: Union[str, int], enabled: bool = True) -> dict:
    if isinstance(code, int):
        code_str = f"0x{code:X}"
    elif isinstance(code, str) and code.strip():
        code_str = code.strip()
    else:
        raise ToolError("Invalid 'code': must be a non-empty string or integer exception code/name")

    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean")

    params = {
        "code": code_str,
        "enabled": enabled
    }
    res = query_debugger_pipe("enable_exception_breakpoint", params)
    for k in ["code", "enabled"]:
        if k not in res:
            raise ToolError(f"Malformed enable_exception_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="get_last_exception",
    description="Returns details of the most recent exception event captured by the debugger (code, address, first chance, thread ID, parameters)."
)
def get_last_exception() -> dict:
    res = query_debugger_pipe("get_last_exception")
    if "has_exception" not in res:
        raise ToolError("Malformed get_last_exception response: missing 'has_exception'")
    return res


@server.tool(
    name="get_trace_record",
    description="Retrieves trace execution record details (hit count, byte execution classification, page record type) for a specific virtual address."
)
def get_trace_record(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string (e.g. '0x140001000' or 'RIP')")

    res = query_debugger_pipe("get_trace_record", {"address": address.strip()})
    for k in ["address", "page_address", "page_record_type", "hit_count", "byte_type"]:
        if k not in res:
            raise ToolError(f"Malformed get_trace_record response: missing '{k}'")
    return res


@server.tool(
    name="set_trace_record_type",
    description="Configures trace recording data type for a memory page containing the specified virtual address ('none', 'bit', 'byte', 'word')."
)
def set_trace_record_type(address: str, type: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string (e.g. '0x140001000')")
    if not isinstance(type, str) or type.lower() not in ("none", "bit", "byte", "word"):
        raise ToolError("Invalid 'type': must be 'none', 'bit', 'byte', or 'word'")

    params = {
        "address": address.strip(),
        "type": type.lower()
    }
    res = query_debugger_pipe("set_trace_record_type", params)
    for k in ["page_address", "type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_trace_record_type response: missing '{k}'")
    return res


@server.tool(
    name="get_trace_status",
    description="Returns global trace execution status including file recording state, active trace file path, conditional trace status, and optional page record type."
)
def get_trace_status(address: str = "") -> dict:
    params = {}
    if isinstance(address, str) and address.strip():
        params["address"] = address.strip()

    res = query_debugger_pipe("get_trace_status", params)
    for k in ["is_debugging", "is_running", "trace_recording_active", "trace_file", "conditional_trace_active"]:
        if k not in res:
            raise ToolError(f"Malformed get_trace_status response: missing '{k}'")
    return res


@server.tool(
    name="set_hardware_breakpoint",
    description="Sets a hardware execution, write, or access breakpoint at the specified address using CPU debug registers (DR0-DR3)."
)
def set_hardware_breakpoint(address: str, type: str = "execute", size: int = 1) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string (e.g. '0x140001000' or 'RIP')")
    if not isinstance(type, str) or type.lower() not in ("execute", "x", "write", "w", "access", "readwrite", "r"):
        raise ToolError("Invalid 'type': must be 'execute', 'write', or 'access'")
    if not isinstance(size, int) or size not in (1, 2, 4, 8):
        raise ToolError("Invalid 'size': must be 1, 2, 4, or 8")

    params = {
        "address": address.strip(),
        "type": type.lower(),
        "size": size
    }
    res = query_debugger_pipe("set_hardware_breakpoint", params)
    for k in ["address", "type", "hw_type", "size", "slot", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_hardware_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="delete_hardware_breakpoint",
    description="Deletes a hardware breakpoint at the specified address, releasing the assigned hardware debug register."
)
def delete_hardware_breakpoint(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string (e.g. '0x140001000')")

    res = query_debugger_pipe("delete_hardware_breakpoint", {"address": address.strip()})
    for k in ["address", "deleted"]:
        if k not in res:
            raise ToolError(f"Malformed delete_hardware_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="enable_hardware_breakpoint",
    description="Enables or disables an existing hardware breakpoint at the specified virtual address."
)
def enable_hardware_breakpoint(address: str, enabled: bool = True) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string")
    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean")

    params = {
        "address": address.strip(),
        "enabled": enabled
    }
    res = query_debugger_pipe("enable_hardware_breakpoint", params)
    for k in ["address", "enabled", "success"]:
        if k not in res:
            raise ToolError(f"Malformed enable_hardware_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="set_memory_breakpoint",
    description="Sets a memory breakpoint on the memory page containing the specified virtual address ('access', 'read', 'write', 'execute')."
)
def set_memory_breakpoint(address: str, type: str = "access", singleshoot: bool = False) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string")
    if not isinstance(type, str) or type.lower() not in ("access", "a", "read", "r", "write", "w", "execute", "x"):
        raise ToolError("Invalid 'type': must be 'access', 'read', 'write', or 'execute'")
    if not isinstance(singleshoot, bool):
        raise ToolError("Invalid 'singleshoot': must be a boolean")

    params = {
        "address": address.strip(),
        "type": type.lower(),
        "singleshoot": singleshoot
    }
    res = query_debugger_pipe("set_memory_breakpoint", params)
    for k in ["address", "base", "size", "type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_memory_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="set_memory_range_breakpoint",
    description="Sets a memory breakpoint over an arbitrary address range starting at the specified virtual address with explicit byte size."
)
def set_memory_range_breakpoint(address: str, size: int, type: str = "access", singleshoot: bool = False) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer byte length")
    if not isinstance(type, str) or type.lower() not in ("access", "a", "read", "r", "write", "w", "execute", "x"):
        raise ToolError("Invalid 'type': must be 'access', 'read', 'write', or 'execute'")
    if not isinstance(singleshoot, bool):
        raise ToolError("Invalid 'singleshoot': must be a boolean")

    params = {
        "address": address.strip(),
        "size": size,
        "type": type.lower(),
        "singleshoot": singleshoot
    }
    res = query_debugger_pipe("set_memory_range_breakpoint", params)
    for k in ["address", "size", "type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_memory_range_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="delete_memory_breakpoint",
    description="Deletes an existing memory breakpoint at the specified virtual address or memory region base."
)
def delete_memory_breakpoint(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string")

    res = query_debugger_pipe("delete_memory_breakpoint", {"address": address.strip()})
    for k in ["address", "deleted"]:
        if k not in res:
            raise ToolError(f"Malformed delete_memory_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="enable_memory_breakpoint",
    description="Enables or disables an existing memory breakpoint at the specified virtual address or region base."
)
def enable_memory_breakpoint(address: str, enabled: bool = True) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty address string")
    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean")

    params = {
        "address": address.strip(),
        "enabled": enabled
    }
    res = query_debugger_pipe("enable_memory_breakpoint", params)
    for k in ["address", "enabled", "success"]:
        if k not in res:
            raise ToolError(f"Malformed enable_memory_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="set_dll_breakpoint",
    description="Sets a module load or unload breakpoint for the specified DLL name ('all', 'load', 'unload')."
)
def set_dll_breakpoint(module: str, type: str = "all", singleshoot: bool = False) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name string (e.g. 'kernel32.dll')")
    if not isinstance(type, str) or type.lower() not in ("all", "a", "load", "l", "unload", "u"):
        raise ToolError("Invalid 'type': must be 'all', 'load', or 'unload'")
    if not isinstance(singleshoot, bool):
        raise ToolError("Invalid 'singleshoot': must be a boolean")

    params = {
        "module": module.strip(),
        "type": type.lower(),
        "singleshoot": singleshoot
    }
    res = query_debugger_pipe("set_dll_breakpoint", params)
    for k in ["module", "type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_dll_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="delete_dll_breakpoint",
    description="Removes an existing module load/unload breakpoint for the specified DLL module."
)
def delete_dll_breakpoint(module: str) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name string")

    res = query_debugger_pipe("delete_dll_breakpoint", {"module": module.strip()})
    for k in ["module", "deleted"]:
        if k not in res:
            raise ToolError(f"Malformed delete_dll_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="enable_dll_breakpoint",
    description="Enables or disables an existing module load/unload breakpoint for the specified DLL module."
)
def enable_dll_breakpoint(module: str, enabled: bool = True) -> dict:
    if not isinstance(module, str) or not module.strip():
        raise ToolError("Invalid 'module': must be a non-empty module name string")
    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean")

    params = {
        "module": module.strip(),
        "enabled": enabled
    }
    res = query_debugger_pipe("enable_dll_breakpoint", params)
    for k in ["module", "enabled", "success"]:
        if k not in res:
            raise ToolError(f"Malformed enable_dll_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="get_breakpoint_details",
    description="Retrieves complete structured configuration and status for a breakpoint (software, hardware, memory, dll, exception) including hit counts, condition expressions, command text, and type-specific attributes."
)
def get_breakpoint_details(address: str = "", module: str = "", type: str = "") -> dict:
    params = {}
    if isinstance(address, str) and address.strip():
        params["address"] = address.strip()
    if isinstance(module, str) and module.strip():
        params["module"] = module.strip()
    if isinstance(type, str) and type.strip():
        params["type"] = type.strip()

    if not params.get("address") and not params.get("module"):
        raise ToolError("Must provide at least 'address' or 'module' to identify the breakpoint")

    res = query_debugger_pipe("get_breakpoint_details", params)
    for k in ["type", "enabled", "active", "hit_count", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_breakpoint_details response: missing '{k}'")
    return res


@server.tool(
    name="configure_breakpoint",
    description="Configures properties on an existing breakpoint (name, singleshoot, silent, fast_resume, break_condition, log_text, log_condition, command_text, command_condition, log_file)."
)
def configure_breakpoint(
    address: str = "",
    module: str = "",
    type: str = "",
    name: str = "",
    singleshoot: Optional[bool] = None,
    silent: Optional[bool] = None,
    fast_resume: Optional[bool] = None,
    break_condition: str = "",
    log_text: str = "",
    log_condition: str = "",
    command_text: str = "",
    command_condition: str = "",
    log_file: str = ""
) -> dict:
    params = {}
    if isinstance(address, str) and address.strip():
        params["address"] = address.strip()
    if isinstance(module, str) and module.strip():
        params["module"] = module.strip()
    if isinstance(type, str) and type.strip():
        params["type"] = type.strip()

    if not params.get("address") and not params.get("module"):
        raise ToolError("Must provide at least 'address' or 'module' to identify the target breakpoint")

    if name:
        params["name"] = name
    if singleshoot is not None:
        params["singleshoot"] = singleshoot
    if silent is not None:
        params["silent"] = silent
    if fast_resume is not None:
        params["fast_resume"] = fast_resume
    if break_condition:
        params["break_condition"] = break_condition
    if log_text:
        params["log_text"] = log_text
    if log_condition:
        params["log_condition"] = log_condition
    if command_text:
        params["command_text"] = command_text
    if command_condition:
        params["command_condition"] = command_condition
    if log_file:
        params["log_file"] = log_file

    res = query_debugger_pipe("configure_breakpoint", params)
    for k in ["target", "configured", "success"]:
        if k not in res:
            raise ToolError(f"Malformed configure_breakpoint response: missing '{k}'")
    return res


@server.tool(
    name="reset_breakpoint_hit_count",
    description="Resets the execution hit count of an existing breakpoint (software, hardware, memory, dll, exception) back to zero."
)
def reset_breakpoint_hit_count(address: str = "", module: str = "", type: str = "") -> dict:
    params = {}
    if isinstance(address, str) and address.strip():
        params["address"] = address.strip()
    if isinstance(module, str) and module.strip():
        params["module"] = module.strip()
    if isinstance(type, str) and type.strip():
        params["type"] = type.strip()

    if not params.get("address") and not params.get("module"):
        raise ToolError("Must provide at least 'address' or 'module' to identify the breakpoint")

    res = query_debugger_pipe("reset_breakpoint_hit_count", params)
    for k in ["target", "hit_count", "success"]:
        if k not in res:
            raise ToolError(f"Malformed reset_breakpoint_hit_count response: missing '{k}'")
    return res


# ---------------------------------------------------------------------------
# Phase 20: Debug Session, Process & Thread Control
# ---------------------------------------------------------------------------

@server.tool(
    name="list_processes",
    description="Enumerates available Windows processes matching the debugger architecture (x64) for choosing an attach target, with optional filtering by name, PID, command line, or window title."
)
def list_processes(
    name: str = "",
    pid: int = 0,
    cmdline: str = "",
    window_title: str = "",
    offset: int = 0,
    limit: int = 50
) -> dict:
    if not isinstance(name, str):
        raise ToolError("Invalid 'name': must be a string")
    if not isinstance(pid, int) or pid < 0:
        raise ToolError("Invalid 'pid': must be a non-negative integer")
    if not isinstance(cmdline, str):
        raise ToolError("Invalid 'cmdline': must be a string")
    if not isinstance(window_title, str):
        raise ToolError("Invalid 'window_title': must be a string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")

    params = {
        "name": name.strip(),
        "pid": pid,
        "cmdline": cmdline.strip(),
        "window_title": window_title.strip(),
        "offset": offset,
        "limit": min(limit, 200)
    }
    res = query_debugger_pipe("list_processes", params)
    for k in ["total_matching", "offset", "limit", "processes"]:
        if k not in res:
            raise ToolError(f"Malformed list_processes response: missing '{k}'")
    return res


@server.tool(
    name="launch_debuggee",
    description="Initializes and launches an executable target into a new x64dbg debugging session with optional command-line arguments and working directory."
)
def launch_debuggee(path: str, command_line: str = "", working_directory: str = "") -> dict:
    if not isinstance(path, str) or not path.strip():
        raise ToolError("Invalid 'path': must be a non-empty file path string")
    if not isinstance(command_line, str):
        raise ToolError("Invalid 'command_line': must be a string")
    if not isinstance(working_directory, str):
        raise ToolError("Invalid 'working_directory': must be a string")

    params = {
        "path": path.strip(),
        "command_line": command_line.strip(),
        "working_directory": working_directory.strip()
    }
    res = query_debugger_pipe("launch_debuggee", params)
    for k in ["path", "pid", "is_debugging", "is_running", "success"]:
        if k not in res:
            raise ToolError(f"Malformed launch_debuggee response: missing '{k}'")
    return res


@server.tool(
    name="send_console_input",
    description="Sends keyboard input to the console input buffer of the active debuggee (or specified PID). Supports sending plain text and optional trailing enter/return key event to unblock console reads (e.g. fgets, ReadConsoleW)."
)
def send_console_input(text: str, send_enter: bool = True, pid: Optional[int] = None) -> dict:
    if not isinstance(text, str):
        raise ToolError("Invalid 'text': must be a string")
    if not isinstance(send_enter, bool):
        raise ToolError("Invalid 'send_enter': must be a boolean")
    if pid is not None and (not isinstance(pid, int) or pid <= 0):
        raise ToolError("Invalid 'pid': must be a positive integer or None")

    params = {
        "text": text,
        "send_enter": send_enter
    }
    if pid is not None and pid > 0:
        params["pid"] = pid

    res = query_debugger_pipe("send_console_input", params)
    for k in ["success", "pid", "characters_sent", "records_written"]:
        if k not in res:
            raise ToolError(f"Malformed send_console_input response: missing '{k}'")
    return res


@server.tool(
    name="read_console_output",
    description="Reads recent output lines and buffer status from the console screen buffer of the active debuggee (or specified PID)."
)
def read_console_output(
    max_lines: int = 50,
    visible_only: bool = False,
    include_empty: bool = False,
    pid: Optional[int] = None
) -> dict:
    if not isinstance(max_lines, int) or max_lines < 1 or max_lines > 1000:
        raise ToolError("Invalid 'max_lines': must be an integer between 1 and 1000")
    if not isinstance(visible_only, bool):
        raise ToolError("Invalid 'visible_only': must be a boolean")
    if not isinstance(include_empty, bool):
        raise ToolError("Invalid 'include_empty': must be a boolean")
    if pid is not None and (not isinstance(pid, int) or pid <= 0):
        raise ToolError("Invalid 'pid': must be a positive integer or None")

    params = {
        "max_lines": max_lines,
        "visible_only": visible_only,
        "include_empty": include_empty
    }
    if pid is not None and pid > 0:
        params["pid"] = pid

    res = query_debugger_pipe("read_console_output", params)
    for k in ["success", "pid", "cursor_position", "buffer_size", "window_rect", "line_count", "lines", "text"]:
        if k not in res:
            raise ToolError(f"Malformed read_console_output response: missing '{k}'")
    return res


@server.tool(
    name="attach_process",
    description="Attaches x64dbg to an active Windows process by PID using native debugger attachment."
)
def attach_process(pid: int) -> dict:
    if not isinstance(pid, int) or pid <= 0:
        raise ToolError("Invalid 'pid': must be a positive integer PID")

    res = query_debugger_pipe("attach_process", {"pid": pid})
    for k in ["pid", "attached", "is_debugging", "is_running", "success"]:
        if k not in res:
            raise ToolError(f"Malformed attach_process response: missing '{k}'")
    return res


@server.tool(
    name="detach_process",
    description="Detaches x64dbg from the current debuggee, removing all debugger breakpoints and leaving the target process running."
)
def detach_process() -> dict:
    res = query_debugger_pipe("detach_process", {})
    for k in ["pid", "detached", "is_debugging", "breakpoints_cleared", "success"]:
        if k not in res:
            raise ToolError(f"Malformed detach_process response: missing '{k}'")
    return res


@server.tool(
    name="stop_debuggee",
    description="Stops the current debugging session. Terminates the debuggee process if it does not exit within the debugger shutdown timeout."
)
def stop_debuggee() -> dict:
    res = query_debugger_pipe("stop_debuggee", {})
    for k in ["pid", "stopped", "is_debugging", "termination_note", "success"]:
        if k not in res:
            raise ToolError(f"Malformed stop_debuggee response: missing '{k}'")
    return res


@server.tool(
    name="suspend_thread",
    description="Suspends execution of a specific thread in the debuggee by thread ID."
)
def suspend_thread(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer thread ID")

    res = query_debugger_pipe("suspend_thread", {"thread_id": thread_id})
    for k in ["thread_id", "suspended", "success"]:
        if k not in res:
            raise ToolError(f"Malformed suspend_thread response: missing '{k}'")
    return res


@server.tool(
    name="resume_thread",
    description="Resumes execution of a previously suspended thread in the debuggee by thread ID."
)
def resume_thread(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer thread ID")

    res = query_debugger_pipe("resume_thread", {"thread_id": thread_id})
    for k in ["thread_id", "resumed", "success"]:
        if k not in res:
            raise ToolError(f"Malformed resume_thread response: missing '{k}'")
    return res


@server.tool(
    name="suspend_all_threads",
    description="Suspends all threads in the active debuggee simultaneously."
)
def suspend_all_threads() -> dict:
    res = query_debugger_pipe("suspend_all_threads", {})
    for k in ["total_threads", "operation", "success"]:
        if k not in res:
            raise ToolError(f"Malformed suspend_all_threads response: missing '{k}'")
    return res


@server.tool(
    name="resume_all_threads",
    description="Resumes all threads in the active debuggee simultaneously."
)
def resume_all_threads() -> dict:
    res = query_debugger_pipe("resume_all_threads", {})
    for k in ["total_threads", "operation", "success"]:
        if k not in res:
            raise ToolError(f"Malformed resume_all_threads response: missing '{k}'")
    return res


@server.tool(
    name="kill_thread",
    description="Forcibly terminates a specific thread in the debuggee by thread ID. Destructive operation requiring confirm: true."
)
def kill_thread(thread_id: int, confirm: bool = False) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer thread ID")
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Destructive operation: you must set 'confirm': true to terminate a thread.")

    res = query_debugger_pipe("kill_thread", {"thread_id": thread_id, "confirm": confirm})
    for k in ["thread_id", "killed", "success"]:
        if k not in res:
            raise ToolError(f"Malformed kill_thread response: missing '{k}'")
    return res


@server.tool(
    name="get_debug_session_info",
    description="Returns a consolidated high-value snapshot of the current debug session, process state, main module, and active thread."
)
def get_debug_session_info() -> dict:
    res = query_debugger_pipe("get_debug_session_info", {})
    for k in ["is_debugging", "is_running", "session_type", "pid", "thread_count", "architecture", "cached", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_debug_session_info response: missing '{k}'")
    return res


# ==============================================================================
# Phase 21 - PE Runtime Metadata, Strings & Controlled Extraction
# ==============================================================================

@server.tool(
    name="get_pe_headers",
    description="Inspects verified PE header metadata (DOS, COFF, Optional Header, entry point, alignment, subsystem) of a loaded module in the debuggee."
)
def get_pe_headers(module: Optional[str] = None, address: Optional[str] = None) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string module name or hex base")
        params["module"] = module.strip()
    if address is not None:
        if not isinstance(address, str):
            raise ToolError("Invalid 'address': must be a string address expression")
        params["address"] = address.strip()

    res = query_debugger_pipe("get_pe_headers", params)
    for k in ["module", "base", "architecture", "entry_point_rva", "entry_point_va", "size_of_image", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_pe_headers response: missing '{k}'")
    return res


@server.tool(
    name="list_pe_data_directories",
    description="Lists standard PE optional-header data directories (export, import, resource, exception, security, relocations, debug, TLS, load config, etc.) with RVA, size, absolute VA, and presence flag."
)
def list_pe_data_directories(module: Optional[str] = None, address: Optional[str] = None) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string module name or hex base")
        params["module"] = module.strip()
    if address is not None:
        if not isinstance(address, str):
            raise ToolError("Invalid 'address': must be a string address expression")
        params["address"] = address.strip()

    res = query_debugger_pipe("list_pe_data_directories", params)
    for k in ["module", "base", "directories"]:
        if k not in res:
            raise ToolError(f"Malformed list_pe_data_directories response: missing '{k}'")
    return res


@server.tool(
    name="list_tls_callbacks",
    description="Enumerates Thread Local Storage (TLS) callback addresses from the PE TLS directory for a loaded module, validating memory bounds and resolving symbols."
)
def list_tls_callbacks(module: Optional[str] = None, address: Optional[str] = None) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string module name or hex base")
        params["module"] = module.strip()
    if address is not None:
        if not isinstance(address, str):
            raise ToolError("Invalid 'address': must be a string address expression")
        params["address"] = address.strip()

    res = query_debugger_pipe("list_tls_callbacks", params)
    for k in ["module", "base", "callback_count", "callbacks"]:
        if k not in res:
            raise ToolError(f"Malformed list_tls_callbacks response: missing '{k}'")
    return res


@server.tool(
    name="get_runtime_function",
    description="Finds the x64 PE exception directory RUNTIME_FUNCTION entry (begin/end RVA & VA, unwind info RVA/VA, and chained status) covering the specified address."
)
def get_runtime_function(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address expression")

    res = query_debugger_pipe("get_runtime_function", {"address": address.strip()})
    for k in ["module", "address", "found"]:
        if k not in res:
            raise ToolError(f"Malformed get_runtime_function response: missing '{k}'")
    return res


@server.tool(
    name="list_runtime_functions",
    description="Enumerates and paginates PE exception directory RUNTIME_FUNCTION entries for an x64 module, returning begin/end RVAs/VAs, unwind info, and chained unwind relations."
)
def list_runtime_functions(module: Optional[str] = None, offset: int = 0, limit: int = 50) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string module name")
        params["module"] = module.strip()
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0 or limit > 500:
        raise ToolError("Invalid 'limit': must be an integer between 1 and 500")

    params["offset"] = offset
    params["limit"] = limit

    res = query_debugger_pipe("list_runtime_functions", params)
    for k in ["module", "base", "total_count", "functions"]:
        if k not in res:
            raise ToolError(f"Malformed list_runtime_functions response: missing '{k}'")
    return res


@server.tool(
    name="get_module_party",
    description="Retrieves the x64dbg party classification for a loaded module, distinguishing user modules from system modules (mod_user vs mod_system)."
)
def get_module_party(module: Optional[str] = None, address: Optional[str] = None) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string module name or hex base")
        params["module"] = module.strip()
    if address is not None:
        if not isinstance(address, str):
            raise ToolError("Invalid 'address': must be a string address expression")
        params["address"] = address.strip()

    res = query_debugger_pipe("get_module_party", params)
    for k in ["module", "base", "party", "party_code", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_module_party response: missing '{k}'")
    return res


@server.tool(
    name="find_strings",
    description="Performs bounded memory string scanning across a memory range for ASCII and/or UTF-16LE strings with minimum length and count limits."
)
def find_strings(start_address: str, size: Optional[int] = None, end_address: Optional[str] = None, encoding: str = "all", min_length: int = 4, limit: int = 100) -> dict:
    if not start_address or not isinstance(start_address, str):
        raise ToolError("Invalid 'start_address': must be a non-empty string address expression")
    if size is None and end_address is None:
        raise ToolError("Must provide either 'size' (integer) or 'end_address' (string)")
    if size is not None and (not isinstance(size, int) or size <= 0):
        raise ToolError("Invalid 'size': must be a positive integer byte length")
    if end_address is not None and (not isinstance(end_address, str) or not end_address.strip()):
        raise ToolError("Invalid 'end_address': must be a non-empty string address expression")
    if encoding not in ["ascii", "utf16", "all"]:
        raise ToolError("Invalid 'encoding': must be 'ascii', 'utf16', or 'all'")
    if not isinstance(min_length, int) or min_length < 2 or min_length > 256:
        raise ToolError("Invalid 'min_length': must be an integer between 2 and 256")
    if not isinstance(limit, int) or limit <= 0 or limit > 1000:
        raise ToolError("Invalid 'limit': must be an integer between 1 and 1000")

    params = {
        "start_address": start_address.strip(),
        "encoding": encoding,
        "min_length": min_length,
        "limit": limit
    }
    if size is not None:
        params["size"] = size
    if end_address is not None:
        params["end_address"] = end_address.strip()

    res = query_debugger_pipe("find_strings", params)
    for k in ["start_address", "size", "encoding", "min_length", "total_found", "strings"]:
        if k not in res:
            raise ToolError(f"Malformed find_strings response: missing '{k}'")
    return res


@server.tool(
    name="dump_memory",
    description="Extracts a bounded contiguous memory region from the paused debuggee directly to a file on disk with strict size caps and optional file verification."
)
def dump_memory(address: str, size: int, output_path: str, verify: bool = True) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address expression")
    if not isinstance(size, int) or size <= 0 or size > 32 * 1024 * 1024:
        raise ToolError("Invalid 'size': must be an integer between 1 and 33554432 (32MB)")
    if not output_path or not isinstance(output_path, str):
        raise ToolError("Invalid 'output_path': must be a non-empty string file path")
    if not isinstance(verify, bool):
        raise ToolError("Invalid 'verify': must be a boolean")

    params = {
        "address": address.strip(),
        "size": size,
        "output_path": output_path.strip(),
        "verify": verify
    }

    res = query_debugger_pipe("dump_memory", params)
    for k in ["address", "size", "output_path", "bytes_written", "verified", "success"]:
        if k not in res:
            raise ToolError(f"Malformed dump_memory response: missing '{k}'")
    return res


@server.tool(
    name="dump_module",
    description="Dumps the runtime loaded memory image of a module to disk with section layout preserved (unreadable holes zero-filled), returning bytes written and verification status."
)
def dump_module(module: Optional[str] = None, output_path: str = "", verify: bool = True) -> dict:
    if not output_path or not isinstance(output_path, str):
        raise ToolError("Invalid 'output_path': must be a non-empty string destination file path")
    if not isinstance(verify, bool):
        raise ToolError("Invalid 'verify': must be a boolean")

    params = {
        "output_path": output_path.strip(),
        "verify": verify
    }
    if module is not None:
        if not isinstance(module, str) or not module.strip():
            raise ToolError("Invalid 'module': must be a non-empty string module name or hex base")
        params["module"] = module.strip()

    res = query_debugger_pipe("dump_module", params)
    for k in ["module", "base", "size", "output_path", "bytes_written", "verified", "success"]:
        if k not in res:
            raise ToolError(f"Malformed dump_module response: missing '{k}'")
    return res


@server.tool(
    name="create_minidump",
    description="Creates a standard Windows user-mode minidump (.dmp) of the debuggee process for offline crash analysis. Requires confirm: true."
)
def create_minidump(output_path: str, confirm: bool = False) -> dict:
    if not output_path or not isinstance(output_path, str):
        raise ToolError("Invalid 'output_path': must be a non-empty string file path")
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Destructive / large file operation: you must set 'confirm': true to create a process minidump.")

    params = {
        "output_path": output_path.strip(),
        "confirm": confirm
    }

    res = query_debugger_pipe("create_minidump", params)
    for k in ["pid", "output_path", "file_size", "dump_type", "verified", "success"]:
        if k not in res:
            raise ToolError(f"Malformed create_minidump response: missing '{k}'")
    return res


# ---------------------------------------------------------------------------
# Phase 22 Tools - Runtime Intelligence, Scripting & Debug Database
# ---------------------------------------------------------------------------


@server.tool(
    name="get_security_mitigations",
    description="Returns structured factual OS/runtime security and architecture information for the active debuggee (DEP status, elevation, ARM64 emulation, NT build number, architecture)."
)
def get_security_mitigations() -> dict:
    res = query_debugger_pipe("get_security_mitigations", {})
    for k in ["dep_enabled", "process_elevated", "arm64_emulated", "nt_build_number", "architecture", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_security_mitigations response: missing '{k}'")
    return res


@server.tool(
    name="get_thread_call_stack",
    description="Retrieves the call stack for an explicitly selected thread ID (TID) while preserving the debugger's active thread state."
)
def get_thread_call_stack(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer TID")
    res = query_debugger_pipe("get_thread_call_stack", {"thread_id": thread_id})
    for k in ["thread_id", "count", "frames", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_thread_call_stack response: missing '{k}'")
    return res


@server.tool(
    name="list_structs",
    description="Enumerates defined structures known to x64dbg with optional substring filtering and pagination."
)
def list_structs(filter: str = "", offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be a string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    params = {"filter": filter.strip(), "offset": offset, "limit": limit}
    res = query_debugger_pipe("list_structs", params)
    for k in ["count", "total", "structs", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_structs response: missing '{k}'")
    return res


@server.tool(
    name="list_constants",
    description="Enumerates standard Windows constants defined in x64dbg with optional filtering and pagination."
)
def list_constants(filter: str = "", offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be a string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    params = {"filter": filter.strip(), "offset": offset, "limit": limit}
    res = query_debugger_pipe("list_constants", params)
    for k in ["count", "total", "constants", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_constants response: missing '{k}'")
    return res


@server.tool(
    name="list_error_codes",
    description="Enumerates Win32 and NT error code definitions known to x64dbg with optional filtering and pagination."
)
def list_error_codes(filter: str = "", offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be a string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    params = {"filter": filter.strip(), "offset": offset, "limit": limit}
    res = query_debugger_pipe("list_error_codes", params)
    for k in ["count", "total", "error_codes", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_error_codes response: missing '{k}'")
    return res


@server.tool(
    name="format_inline_string",
    description="Formats a string using x64dbg's native inline string formatting engine (e.g. '{x:rip}', '{d:rax}', '{mem;4@addr}')."
)
def format_inline_string(format: str) -> dict:
    if not format or not isinstance(format, str):
        raise ToolError("Invalid 'format': must be a non-empty format string")
    res = query_debugger_pipe("format_inline_string", {"format": format})
    for k in ["formatted", "original", "success"]:
        if k not in res:
            raise ToolError(f"Malformed format_inline_string response: missing '{k}'")
    return res


@server.tool(
    name="run_script",
    description="Executes an x64dbg script file synchronously using the native scriptexec command."
)
def run_script(path: str) -> dict:
    if not path or not isinstance(path, str):
        raise ToolError("Invalid 'path': must be a non-empty script file path")
    res = query_debugger_pipe("run_script", {"path": path.strip()})
    for k in ["path", "message", "success"]:
        if k not in res:
            raise ToolError(f"Malformed run_script response: missing '{k}'")
    return res


@server.tool(
    name="get_loop",
    description="Queries loop information at a given virtual address and nesting depth from the x64dbg database."
)
def get_loop(address: str, depth: int = 0) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(depth, int) or depth < 0:
        raise ToolError("Invalid 'depth': must be a non-negative integer")
    res = query_debugger_pipe("get_loop", {"address": address.strip(), "depth": depth})
    for k in ["found", "address", "depth", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_loop response: missing '{k}'")
    return res


@server.tool(
    name="list_loops",
    description="Enumerates user and auto-detected loop ranges stored in the x64dbg database."
)
def list_loops() -> dict:
    res = query_debugger_pipe("list_loops", {})
    for k in ["count", "loops", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_loops response: missing '{k}'")
    return res


@server.tool(
    name="add_loop",
    description="Adds a loop range (start address to end address) to the x64dbg database."
)
def add_loop(start: str, end: str) -> dict:
    if not start or not isinstance(start, str):
        raise ToolError("Invalid 'start': must be a non-empty string address")
    if not end or not isinstance(end, str):
        raise ToolError("Invalid 'end': must be a non-empty string address")
    res = query_debugger_pipe("add_loop", {"start": start.strip(), "end": end.strip()})
    for k in ["added", "start", "end", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_loop response: missing '{k}'")
    return res


@server.tool(
    name="delete_loop",
    description="Deletes a loop range at the given virtual address and nesting depth from the x64dbg database."
)
def delete_loop(address: str, depth: int = 0) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(depth, int) or depth < 0:
        raise ToolError("Invalid 'depth': must be a non-negative integer")
    res = query_debugger_pipe("delete_loop", {"address": address.strip(), "depth": depth})
    for k in ["deleted", "address", "depth", "success"]:
        if k not in res:
            raise ToolError(f"Malformed delete_loop response: missing '{k}'")
    return res


@server.tool(
    name="clear_loops",
    description="Clears all loop ranges from the x64dbg database."
)
def clear_loops() -> dict:
    res = query_debugger_pipe("clear_loops", {})
    for k in ["cleared", "message", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_loops response: missing '{k}'")
    return res


@server.tool(
    name="get_argument",
    description="Queries function argument range information at a given virtual address from the x64dbg database."
)
def get_argument(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("get_argument", {"address": address.strip()})
    for k in ["found", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_argument response: missing '{k}'")
    return res


@server.tool(
    name="list_arguments",
    description="Enumerates function argument ranges stored in the x64dbg database."
)
def list_arguments() -> dict:
    res = query_debugger_pipe("list_arguments", {})
    for k in ["count", "arguments", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_arguments response: missing '{k}'")
    return res


@server.tool(
    name="add_argument",
    description="Adds a function argument range (start address to end address) to the x64dbg database."
)
def add_argument(start: str, end: str) -> dict:
    if not start or not isinstance(start, str):
        raise ToolError("Invalid 'start': must be a non-empty string address")
    if not end or not isinstance(end, str):
        raise ToolError("Invalid 'end': must be a non-empty string address")
    res = query_debugger_pipe("add_argument", {"start": start.strip(), "end": end.strip()})
    for k in ["added", "start", "end", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_argument response: missing '{k}'")
    return res


@server.tool(
    name="delete_argument",
    description="Deletes a function argument range at the given virtual address from the x64dbg database."
)
def delete_argument(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("delete_argument", {"address": address.strip()})
    for k in ["deleted", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed delete_argument response: missing '{k}'")
    return res


@server.tool(
    name="clear_arguments",
    description="Clears all function argument ranges from the x64dbg database."
)
def clear_arguments() -> dict:
    res = query_debugger_pipe("clear_arguments", {})
    for k in ["cleared", "message", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_arguments response: missing '{k}'")
    return res


@server.tool(
    name="run_to_address",
    description="Resumes execution until the specified virtual address is reached, utilizing a temporary breakpoint with timeout and status reporting."
)
def run_to_address(address: str, timeout_ms: int = 5000) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("run_to_address", {"address": address.strip(), "timeout_ms": timeout_ms})
    for k in ["status", "target_reached", "success"]:
        if k not in res:
            raise ToolError(f"Malformed run_to_address response: missing '{k}'")
    return res


@server.tool(
    name="restart_debuggee",
    description="Restarts the current debug session using x64dbg native InitDebug, resetting target process state while retaining breakpoints."
)
def restart_debuggee() -> dict:
    res = query_debugger_pipe("restart_debuggee", {})
    for k in ["restarted", "pid", "success"]:
        if k not in res:
            raise ToolError(f"Malformed restart_debuggee response: missing '{k}'")
    return res


@server.tool(
    name="run_to_user_code",
    description="Runs the debuggee until execution reaches a module marked as user code (party == 0)."
)
def run_to_user_code(timeout_ms: int = 10000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("run_to_user_code", {"timeout_ms": timeout_ms})
    for k in ["status", "user_code_reached", "success"]:
        if k not in res:
            raise ToolError(f"Malformed run_to_user_code response: missing '{k}'")
    return res


@server.tool(
    name="step_user",
    description="Steps debuggee execution until control enters or returns to user code."
)
def step_user(timeout_ms: int = 10000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("step_user", {"timeout_ms": timeout_ms})
    for k in ["status", "target_party_reached", "success"]:
        if k not in res:
            raise ToolError(f"Malformed step_user response: missing '{k}'")
    return res


@server.tool(
    name="step_system",
    description="Steps debuggee execution until control enters system code (system module or runtime DLL)."
)
def step_system(timeout_ms: int = 10000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("step_system", {"timeout_ms": timeout_ms})
    for k in ["status", "target_party_reached", "success"]:
        if k not in res:
            raise ToolError(f"Malformed step_system response: missing '{k}'")
    return res


@server.tool(
    name="skip_instruction",
    description="Skips the current instruction(s) by advancing CIP without executing instructions."
)
def skip_instruction(count: int = 1) -> dict:
    if not isinstance(count, int) or count <= 0:
        raise ToolError("Invalid 'count': must be a positive integer")
    res = query_debugger_pipe("skip_instruction", {"count": count})
    for k in ["old_rip", "new_rip", "instruction_size", "success"]:
        if k not in res:
            raise ToolError(f"Malformed skip_instruction response: missing '{k}'")
    return res


@server.tool(
    name="step_over_pass_exceptions",
    description="Steps over the current instruction while passing any encountered first-chance exceptions to the debuggee."
)
def step_over_pass_exceptions(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("step_over_pass_exceptions", {"timeout_ms": timeout_ms})
    for k in ["status", "success"]:
        if k not in res:
            raise ToolError(f"Malformed step_over_pass_exceptions response: missing '{k}'")
    return res


@server.tool(
    name="step_out_pass_exceptions",
    description="Steps out of the current function while passing any encountered first-chance exceptions to the debuggee."
)
def step_out_pass_exceptions(timeout_ms: int = 5000) -> dict:
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    res = query_debugger_pipe("step_out_pass_exceptions", {"timeout_ms": timeout_ms})
    for k in ["status", "success"]:
        if k not in res:
            raise ToolError(f"Malformed step_out_pass_exceptions response: missing '{k}'")
    return res


@server.tool(
    name="allocate_memory",
    description="Allocates remote virtual memory in the debuggee process with specified byte size and optional base address."
)
def allocate_memory(size: int = 4096, address: str = "") -> dict:
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer")
    if address is not None and not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a string")
    res = query_debugger_pipe("allocate_memory", {"size": size, "address": address.strip() if address else ""})
    for k in ["address", "size", "success"]:
        if k not in res:
            raise ToolError(f"Malformed allocate_memory response: missing '{k}'")
    return res


@server.tool(
    name="free_memory",
    description="Frees previously allocated remote virtual memory at the specified address in the debuggee process."
)
def free_memory(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("free_memory", {"address": address.strip()})
    for k in ["address", "freed", "success"]:
        if k not in res:
            raise ToolError(f"Malformed free_memory response: missing '{k}'")
    return res


@server.tool(
    name="fill_memory",
    description="Fills a committed memory region with a specified byte value and verifies written bytes."
)
def fill_memory(address: str, value: int, size: int) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(value, int) or value < 0 or value > 255:
        raise ToolError("Invalid 'value': must be a byte integer between 0 and 255")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer byte length")
    res = query_debugger_pipe("fill_memory", {"address": address.strip(), "value": value, "size": size})
    for k in ["address", "size", "value", "bytes_written", "verified", "success"]:
        if k not in res:
            raise ToolError(f"Malformed fill_memory response: missing '{k}'")
    return res


@server.tool(
    name="copy_memory",
    description="Copies a block of memory from a source virtual address to a destination virtual address within the debuggee."
)
def copy_memory(destination: str, source: str, size: int) -> dict:
    if not destination or not isinstance(destination, str):
        raise ToolError("Invalid 'destination': must be a non-empty string address")
    if not source or not isinstance(source, str):
        raise ToolError("Invalid 'source': must be a non-empty string address")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer byte length")
    res = query_debugger_pipe("copy_memory", {"destination": destination.strip(), "source": source.strip(), "size": size})
    for k in ["destination", "source", "size", "bytes_copied", "verified", "success"]:
        if k not in res:
            raise ToolError(f"Malformed copy_memory response: missing '{k}'")
    return res


@server.tool(
    name="set_page_rights",
    description="Sets the memory protection rights for the memory page containing the specified virtual address."
)
def set_page_rights(address: str, rights: str, guard: bool = False) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not rights or not isinstance(rights, str):
        raise ToolError("Invalid 'rights': must be a non-empty rights string (e.g. 'ExecuteReadWrite', 'ReadOnly', etc.)")
    if not isinstance(guard, bool):
        raise ToolError("Invalid 'guard': must be a boolean")
    res = query_debugger_pipe("set_page_rights", {"address": address.strip(), "rights": rights.strip(), "guard": guard})
    for k in ["address", "page_base", "previous_rights", "new_rights", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_page_rights response: missing '{k}'")
    return res



# ---------------------------------------------------------------------------
# Phase 24 - Analysis Engine & Function Intelligence
# ---------------------------------------------------------------------------

@server.tool(
    name="analyze_code",
    description="Runs linear code analysis on a given function or memory region in the debuggee."
)
def analyze_code(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("analyze_code", {"address": address.strip()})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_code response: missing '{k}'")
    return res


@server.tool(
    name="analyze_control_flow",
    description="Runs control flow analysis from the specified address, optionally using the module exception directory."
)
def analyze_control_flow(address: str, use_exception_directory: bool = False) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(use_exception_directory, bool):
        raise ToolError("Invalid 'use_exception_directory': must be a boolean")
    res = query_debugger_pipe("analyze_control_flow", {"address": address.strip(), "use_exception_directory": use_exception_directory})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_control_flow response: missing '{k}'")
    return res


@server.tool(
    name="analyze_exception_directory",
    description="Analyzes the PE exception directory (.pdata) starting from the specified function/module address."
)
def analyze_exception_directory(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("analyze_exception_directory", {"address": address.strip()})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_exception_directory response: missing '{k}'")
    return res


@server.tool(
    name="analyze_recursive",
    description="Performs recursive descent analysis from the specified function entry address."
)
def analyze_recursive(entry: str) -> dict:
    if not entry or not isinstance(entry, str):
        raise ToolError("Invalid 'entry': must be a non-empty string entry address")
    res = query_debugger_pipe("analyze_recursive", {"entry": entry.strip()})
    for k in ["tool", "entry", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_recursive response: missing '{k}'")
    return res


@server.tool(
    name="analyze_advanced",
    description="Executes advanced analysis (analadv) from the specified address."
)
def analyze_advanced(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("analyze_advanced", {"address": address.strip()})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_advanced response: missing '{k}'")
    return res


@server.tool(
    name="analyze_xrefs",
    description="Analyzes cross-references (analxrefs) for the specified address or function."
)
def analyze_xrefs(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("analyze_xrefs", {"address": address.strip()})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_xrefs response: missing '{k}'")
    return res


@server.tool(
    name="analyze_nukem",
    description="Executes alternate/nukem analysis (analyse_nukem) starting at the specified address."
)
def analyze_nukem(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("analyze_nukem", {"address": address.strip()})
    for k in ["tool", "address", "success"]:
        if k not in res:
            raise ToolError(f"Malformed analyze_nukem response: missing '{k}'")
    return res


@server.tool(
    name="list_functions",
    description="Lists recognized functions in the debuggee, with optional module filtering and pagination."
)
def list_functions(module: Optional[str] = None, offset: int = 0, limit: int = 100) -> dict:
    if module is not None and not isinstance(module, str):
        raise ToolError("Invalid 'module': must be a string or omitted")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    params = {"offset": offset, "limit": limit}
    if module:
        params["module"] = module.strip()
    res = query_debugger_pipe("list_functions", params)
    for k in ["total", "count", "offset", "limit", "functions", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_functions response: missing '{k}'")
    return res


@server.tool(
    name="get_function_info",
    description="Retrieves structured metadata, boundaries, instruction count, and RVA ranges for a function at or containing the specified address."
)
def get_function_info(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("get_function_info", {"address": address.strip()})
    for k in ["address", "found", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_function_info response: missing '{k}'")
    return res


@server.tool(
    name="get_control_flow_graph",
    description="Retrieves the structured control flow graph (basic blocks and jump/branch edges) for the function at the specified address."
)
def get_control_flow_graph(address: str, max_blocks: int = 256) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(max_blocks, int) or max_blocks <= 0:
        raise ToolError("Invalid 'max_blocks': must be a positive integer")
    res = query_debugger_pipe("get_control_flow_graph", {"address": address.strip(), "max_blocks": max_blocks})
    for k in ["entry", "method", "block_count", "blocks", "edges", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_control_flow_graph response: missing '{k}'")
    return res


@server.tool(
    name="get_function_callers",
    description="Discovers all call sites and caller functions invoking the function at the specified address."
)
def get_function_callers(address: str) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    res = query_debugger_pipe("get_function_callers", {"address": address.strip()})
    for k in ["target_address", "caller_count", "callers", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_function_callers response: missing '{k}'")
    return res


@server.tool(
    name="get_function_callees",
    description="Discovers all target functions and APIs called from within the specified function."
)
def get_function_callees(address: str, max_callees: int = 100) -> dict:
    if not address or not isinstance(address, str):
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(max_callees, int) or max_callees <= 0:
        raise ToolError("Invalid 'max_callees': must be a positive integer")
    res = query_debugger_pipe("get_function_callees", {"address": address.strip(), "max_callees": max_callees})
    for k in ["function_start", "function_end", "callee_count", "callees", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_function_callees response: missing '{k}'")
    return res



# ---------------------------------------------------------------------------
# Phase 25 - Debugger Event Queue & Asynchronous Event Delivery
# ---------------------------------------------------------------------------

@server.tool(
    name="get_debug_events",
    description="Retrieves queued debugger events since an optional sequence number, with optional type filtering and pagination."
)
def get_debug_events(after_sequence: Optional[int] = None, limit: int = 50, types: Optional[list[str]] = None) -> dict:
    if after_sequence is not None and (not isinstance(after_sequence, int) or after_sequence < 0):
        raise ToolError("Invalid 'after_sequence': must be a non-negative integer or omitted")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    if types is not None:
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise ToolError("Invalid 'types': must be a list of event type strings or omitted")
    params = {"limit": limit}
    if after_sequence is not None:
        params["after_sequence"] = after_sequence
    if types is not None:
        params["types"] = types
    res = query_debugger_pipe("get_debug_events", params)
    for k in ["events", "count", "next_sequence", "earliest_retained_sequence", "dropped_before_sequence", "dropped_count", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_debug_events response: missing '{k}'")
    return res


@server.tool(
    name="wait_for_debug_event",
    description="Waits efficiently until a matching debugger event arrives or the timeout expires, without busy-spinning."
)
def wait_for_debug_event(after_sequence: Optional[int] = None, timeout_ms: int = 10000, types: Optional[list[str]] = None) -> dict:
    if after_sequence is not None and (not isinstance(after_sequence, int) or after_sequence < 0):
        raise ToolError("Invalid 'after_sequence': must be a non-negative integer or omitted")
    if not isinstance(timeout_ms, int) or timeout_ms < 0 or timeout_ms > 60000:
        raise ToolError("Invalid 'timeout_ms': must be an integer between 0 and 60000 milliseconds")
    if types is not None:
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise ToolError("Invalid 'types': must be a list of event type strings or omitted")
    params = {"timeout_ms": timeout_ms}
    if after_sequence is not None:
        params["after_sequence"] = after_sequence
    if types is not None:
        params["types"] = types
    pipe_timeout = (timeout_ms / 1000.0) + 5.0
    res = query_debugger_pipe("wait_for_debug_event", params, timeout_sec=pipe_timeout)
    for k in ["timed_out", "success"]:
        if k not in res:
            raise ToolError(f"Malformed wait_for_debug_event response: missing '{k}'")
    return res


@server.tool(
    name="clear_debug_events",
    description="Clears all currently queued debugger events and updates earliest retained sequence."
)
def clear_debug_events() -> dict:
    res = query_debugger_pipe("clear_debug_events")
    for k in ["removed_count", "earliest_retained_sequence", "current_sequence", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_debug_events response: missing '{k}'")
    return res


@server.tool(
    name="get_event_status",
    description="Returns queue diagnostic and health status: current sequence, capacity, queued count, and dropped count."
)
def get_event_status() -> dict:
    res = query_debugger_pipe("get_event_status")
    for k in ["current_sequence", "earliest_retained_sequence", "queued_count", "max_capacity", "dropped_count", "session_id", "is_shutting_down", "last_event_type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_event_status response: missing '{k}'")
    return res


# ===========================================================================
# Phase 26 - User Database Persistence & Complete Annotation Management
# ===========================================================================

# --- Group A - Database Persistence ---

@server.tool(
    name="save_database",
    description="Saves the current x64dbg user database (comments, labels, bookmarks, functions, etc.) to disk."
)
def save_database(path: Optional[str] = None, compression: bool = True) -> dict:
    params = {}
    if path is not None:
        if not isinstance(path, str) or not path.strip():
            raise ToolError("Invalid 'path': must be a non-empty string or omitted")
        params["path"] = path.strip()
    if not isinstance(compression, bool):
        raise ToolError("Invalid 'compression': must be a boolean")
    params["compression"] = compression
    res = query_debugger_pipe("save_database", params)
    for k in ["status", "saved", "path"]:
        if k not in res:
            raise ToolError(f"Malformed save_database response: missing '{k}'")
    return res


@server.tool(
    name="load_database",
    description="Loads or merges an x64dbg user database from disk into the current session."
)
def load_database(path: Optional[str] = None) -> dict:
    params = {}
    if path is not None:
        if not isinstance(path, str) or not path.strip():
            raise ToolError("Invalid 'path': must be a non-empty string or omitted")
        params["path"] = path.strip()
    res = query_debugger_pipe("load_database", params)
    for k in ["status", "loaded", "path"]:
        if k not in res:
            raise ToolError(f"Malformed load_database response: missing '{k}'")
    return res


@server.tool(
    name="clear_database",
    description="Clears all user database annotations from memory for the current session. Requires explicit confirm=True."
)
def clear_database(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear the database")
    res = query_debugger_pipe("clear_database", {"confirm": True})
    for k in ["status", "cleared"]:
        if k not in res:
            raise ToolError(f"Malformed clear_database response: missing '{k}'")
    return res


# --- Group B - Comments Management ---

@server.tool(
    name="list_comments",
    description="Lists user comments in the current debuggee, optionally filtered by module with pagination."
)
def list_comments(module: Optional[str] = None, page: int = 1, page_size: int = 100) -> dict:
    if not isinstance(page, int) or page < 1:
        raise ToolError("Invalid 'page': must be a positive integer")
    if not isinstance(page_size, int) or page_size < 1 or page_size > 1000:
        raise ToolError("Invalid 'page_size': must be an integer between 1 and 1000")
    params = {"page": page, "page_size": page_size}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string or omitted")
        params["module"] = module.strip()
    res = query_debugger_pipe("list_comments", params)
    for k in ["status", "total_count", "count", "page", "page_size", "comments"]:
        if k not in res:
            raise ToolError(f"Malformed list_comments response: missing '{k}'")
    return res


@server.tool(
    name="delete_comment",
    description="Deletes a user comment at a specified address."
)
def delete_comment(address: Union[int, str]) -> dict:
    if isinstance(address, int):
        addr_str = hex(address)
    elif isinstance(address, str) and address.strip():
        addr_str = address.strip()
    else:
        raise ToolError("Invalid 'address': must be an integer or non-empty string")
    res = query_debugger_pipe("delete_comment", {"address": addr_str})
    for k in ["status", "deleted", "address"]:
        if k not in res:
            raise ToolError(f"Malformed delete_comment response: missing '{k}'")
    return res


@server.tool(
    name="clear_comments",
    description="Clears all user comments from the current debuggee. Requires explicit confirm=True."
)
def clear_comments(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear comments")
    res = query_debugger_pipe("clear_comments", {"confirm": True})
    for k in ["status", "cleared"]:
        if k not in res:
            raise ToolError(f"Malformed clear_comments response: missing '{k}'")
    return res


# --- Group C - Labels Management ---

@server.tool(
    name="list_labels",
    description="Lists user labels in the current debuggee, optionally filtered by module or temporary flag with pagination."
)
def list_labels(module: Optional[str] = None, temporary: Optional[bool] = None, page: int = 1, page_size: int = 100) -> dict:
    if not isinstance(page, int) or page < 1:
        raise ToolError("Invalid 'page': must be a positive integer")
    if not isinstance(page_size, int) or page_size < 1 or page_size > 1000:
        raise ToolError("Invalid 'page_size': must be an integer between 1 and 1000")
    params = {"page": page, "page_size": page_size}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string or omitted")
        params["module"] = module.strip()
    if temporary is not None:
        if not isinstance(temporary, bool):
            raise ToolError("Invalid 'temporary': must be a boolean or omitted")
        params["temporary"] = temporary
    res = query_debugger_pipe("list_labels", params)
    for k in ["status", "total_count", "count", "page", "page_size", "labels"]:
        if k not in res:
            raise ToolError(f"Malformed list_labels response: missing '{k}'")
    return res


@server.tool(
    name="delete_label",
    description="Deletes a user label at a specified address."
)
def delete_label(address: Union[int, str]) -> dict:
    if isinstance(address, int):
        addr_str = hex(address)
    elif isinstance(address, str) and address.strip():
        addr_str = address.strip()
    else:
        raise ToolError("Invalid 'address': must be an integer or non-empty string")
    res = query_debugger_pipe("delete_label", {"address": addr_str})
    for k in ["status", "deleted", "address"]:
        if k not in res:
            raise ToolError(f"Malformed delete_label response: missing '{k}'")
    return res


@server.tool(
    name="clear_labels",
    description="Clears all user labels from the current debuggee. Requires explicit confirm=True."
)
def clear_labels(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear labels")
    res = query_debugger_pipe("clear_labels", {"confirm": True})
    for k in ["status", "cleared"]:
        if k not in res:
            raise ToolError(f"Malformed clear_labels response: missing '{k}'")
    return res


# --- Group D - Bookmarks Management ---

@server.tool(
    name="list_bookmarks",
    description="Lists bookmarks in the current debuggee, optionally filtered by module with pagination."
)
def list_bookmarks(module: Optional[str] = None, page: int = 1, page_size: int = 100) -> dict:
    if not isinstance(page, int) or page < 1:
        raise ToolError("Invalid 'page': must be a positive integer")
    if not isinstance(page_size, int) or page_size < 1 or page_size > 1000:
        raise ToolError("Invalid 'page_size': must be an integer between 1 and 1000")
    params = {"page": page, "page_size": page_size}
    if module is not None:
        if not isinstance(module, str):
            raise ToolError("Invalid 'module': must be a string or omitted")
        params["module"] = module.strip()
    res = query_debugger_pipe("list_bookmarks", params)
    for k in ["status", "total_count", "count", "page", "page_size", "bookmarks"]:
        if k not in res:
            raise ToolError(f"Malformed list_bookmarks response: missing '{k}'")
    return res


@server.tool(
    name="delete_bookmark",
    description="Deletes a bookmark at a specified address."
)
def delete_bookmark(address: Union[int, str]) -> dict:
    if isinstance(address, int):
        addr_str = hex(address)
    elif isinstance(address, str) and address.strip():
        addr_str = address.strip()
    else:
        raise ToolError("Invalid 'address': must be an integer or non-empty string")
    res = query_debugger_pipe("delete_bookmark", {"address": addr_str})
    for k in ["status", "deleted", "address"]:
        if k not in res:
            raise ToolError(f"Malformed delete_bookmark response: missing '{k}'")
    return res


@server.tool(
    name="clear_bookmarks",
    description="Clears all bookmarks from the current debuggee. Requires explicit confirm=True."
)
def clear_bookmarks(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear bookmarks")
    res = query_debugger_pipe("clear_bookmarks", {"confirm": True})
    for k in ["status", "cleared"]:
        if k not in res:
            raise ToolError(f"Malformed clear_bookmarks response: missing '{k}'")
    return res


# --- Group E - Function Database Completion ---

@server.tool(
    name="add_function",
    description="Adds a user-defined function boundary with start and end addresses."
)
def add_function(start: Union[int, str], end: Union[int, str], manual: bool = True, instruction_count: int = 0) -> dict:
    if isinstance(start, int):
        start_str = hex(start)
    elif isinstance(start, str) and start.strip():
        start_str = start.strip()
    else:
        raise ToolError("Invalid 'start': must be an integer or non-empty string")

    if isinstance(end, int):
        end_str = hex(end)
    elif isinstance(end, str) and end.strip():
        end_str = end.strip()
    else:
        raise ToolError("Invalid 'end': must be an integer or non-empty string")

    if not isinstance(manual, bool):
        raise ToolError("Invalid 'manual': must be a boolean")
    if not isinstance(instruction_count, int) or instruction_count < 0:
        raise ToolError("Invalid 'instruction_count': must be a non-negative integer")

    params = {
        "start": start_str,
        "end": end_str,
        "manual": manual,
        "instruction_count": instruction_count
    }
    res = query_debugger_pipe("add_function", params)
    for k in ["status", "added", "start", "end"]:
        if k not in res:
            raise ToolError(f"Malformed add_function response: missing '{k}'")
    return res


@server.tool(
    name="delete_function",
    description="Deletes a function boundary at a specified address."
)
def delete_function(address: Union[int, str]) -> dict:
    if isinstance(address, int):
        addr_str = hex(address)
    elif isinstance(address, str) and address.strip():
        addr_str = address.strip()
    else:
        raise ToolError("Invalid 'address': must be an integer or non-empty string")
    res = query_debugger_pipe("delete_function", {"address": addr_str})
    for k in ["status", "deleted", "address"]:
        if k not in res:
            raise ToolError(f"Malformed delete_function response: missing '{k}'")
    return res


@server.tool(
    name="clear_functions",
    description="Clears all functions from the current debuggee database. Requires explicit confirm=True."
)
def clear_functions(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear functions")
    res = query_debugger_pipe("clear_functions", {"confirm": True})
    for k in ["status", "cleared"]:
        if k not in res:
            raise ToolError(f"Malformed clear_functions response: missing '{k}'")
    return res


# --- Group F - Command Line Control ---

@server.tool(
    name="set_command_line",
    description="Sets the debuggee launch command line arguments in x64dbg."
)
def set_command_line(command_line: str) -> dict:
    if not isinstance(command_line, str):
        raise ToolError("Invalid 'command_line': must be a string")
    res = query_debugger_pipe("set_command_line", {"command_line": command_line})
    for k in ["status", "command_line"]:
        if k not in res:
            raise ToolError(f"Malformed set_command_line response: missing '{k}'")
    return res


# ===========================================================================
# Phase 27 - Rich Tracing & Conditional Execution Control
# ===========================================================================

@server.tool(
    name="trace_into_conditional",
    description="Steps into instructions repeatedly until the specified condition evaluates to true or max_steps is reached."
)
def trace_into_conditional(condition: str, max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str) or not condition.strip():
        raise ToolError("Invalid 'condition': must be a non-empty string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_into_conditional", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="trace_over_conditional",
    description="Steps over instructions repeatedly until the specified condition evaluates to true or max_steps is reached."
)
def trace_over_conditional(condition: str, max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str) or not condition.strip():
        raise ToolError("Invalid 'condition': must be a non-empty string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_over_conditional", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="trace_into_beyond_trace_record",
    description="Steps into instructions until execution reaches code outside the recorded trace coverage (hit count == 0), condition is true, or max_steps is reached."
)
def trace_into_beyond_trace_record(condition: str = "", max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_into_beyond_trace_record", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="trace_over_beyond_trace_record",
    description="Steps over instructions until execution reaches code outside the recorded trace coverage (hit count == 0), condition is true, or max_steps is reached."
)
def trace_over_beyond_trace_record(condition: str = "", max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_over_beyond_trace_record", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="trace_into_trace_record",
    description="Steps into instructions until execution reaches code inside existing recorded trace coverage (hit count > 0), condition is true, or max_steps is reached."
)
def trace_into_trace_record(condition: str = "", max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_into_trace_record", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="trace_over_trace_record",
    description="Steps over instructions until execution reaches code inside existing recorded trace coverage (hit count > 0), condition is true, or max_steps is reached."
)
def trace_over_trace_record(condition: str = "", max_steps: int = 0, timeout_ms: int = 10000) -> dict:
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string expression")
    if not isinstance(max_steps, int) or max_steps < 0:
        raise ToolError("Invalid 'max_steps': must be a non-negative integer")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"condition": condition.strip(), "max_steps": max_steps, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("trace_over_trace_record", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="run_to_party",
    description="Executes the target until execution enters a module of the specified party ('user' or 0, 'system' or 1)."
)
def run_to_party(party: str = "user", timeout_ms: int = 10000) -> dict:
    if isinstance(party, int):
        if party not in (0, 1):
            raise ToolError("Invalid 'party': must be 0 ('user') or 1 ('system')")
        party_str = "user" if party == 0 else "system"
    elif isinstance(party, str):
        party_lower = party.strip().lower()
        if party_lower in ("0", "user"):
            party_str = "user"
        elif party_lower in ("1", "system"):
            party_str = "system"
        else:
            raise ToolError("Invalid 'party': must be 'user' (0) or 'system' (1)")
    else:
        raise ToolError("Invalid 'party': must be 'user' (0) or 'system' (1)")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        raise ToolError("Invalid 'timeout_ms': must be a positive integer")
    params = {"party": party_str, "timeout_ms": timeout_ms}
    res = query_debugger_pipe("run_to_party", params, timeout_sec=max(15.0, timeout_ms / 1000.0 + 5.0))
    return res


@server.tool(
    name="set_trace_log",
    description="Sets or clears the trace log format string and optional logging condition."
)
def set_trace_log(text: str = "", condition: str = "") -> dict:
    if not isinstance(text, str):
        raise ToolError("Invalid 'text': must be a string")
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string")
    res = query_debugger_pipe("set_trace_log", {"text": text, "condition": condition.strip()})
    for k in ["status", "configured"]:
        if k not in res:
            raise ToolError(f"Malformed set_trace_log response: missing '{k}'")
    return res


@server.tool(
    name="set_trace_command",
    description="Sets or clears a command to execute on each trace step meeting the condition."
)
def set_trace_command(command: str = "", condition: str = "") -> dict:
    if not isinstance(command, str):
        raise ToolError("Invalid 'command': must be a string")
    if not isinstance(condition, str):
        raise ToolError("Invalid 'condition': must be a string")
    res = query_debugger_pipe("set_trace_command", {"command": command, "condition": condition.strip()})
    for k in ["status", "configured"]:
        if k not in res:
            raise ToolError(f"Malformed set_trace_command response: missing '{k}'")
    return res


@server.tool(
    name="set_trace_log_file",
    description="Sets or clears the file destination path for trace logging."
)
def set_trace_log_file(path: str = "") -> dict:
    if not isinstance(path, str):
        raise ToolError("Invalid 'path': must be a string")
    res = query_debugger_pipe("set_trace_log_file", {"path": path.strip()})
    for k in ["status", "configured"]:
        if k not in res:
            raise ToolError(f"Malformed set_trace_log_file response: missing '{k}'")
    return res


@server.tool(
    name="set_trace_step_filter",
    description="Configures the trace step party filter ('none', 'user', or 'system')."
)
def set_trace_step_filter(filter: str = "none") -> dict:
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be 'none', 'user', or 'system'")
    f_lower = filter.strip().lower()
    if f_lower not in ("none", "user", "system"):
        raise ToolError("Invalid 'filter': must be 'none', 'user', or 'system'")
    res = query_debugger_pipe("set_trace_step_filter", {"filter": f_lower})
    for k in ["status", "configured", "filter"]:
        if k not in res:
            raise ToolError(f"Malformed set_trace_step_filter response: missing '{k}'")
    return res


@server.tool(
    name="start_trace_recording",
    description="Starts recording execution trace to a file on disk (does not resume execution)."
)
def start_trace_recording(path: str) -> dict:
    if not isinstance(path, str) or not path.strip():
        raise ToolError("Invalid 'path': must be a non-empty string path")
    res = query_debugger_pipe("start_trace_recording", {"path": path.strip()})
    for k in ["status", "recording", "path"]:
        if k not in res:
            raise ToolError(f"Malformed start_trace_recording response: missing '{k}'")
    return res


@server.tool(
    name="stop_trace_recording",
    description="Stops active execution trace recording and flushes the trace file."
)
def stop_trace_recording() -> dict:
    res = query_debugger_pipe("stop_trace_recording", {})
    for k in ["status", "recording", "stopped"]:
        if k not in res:
            raise ToolError(f"Malformed stop_trace_recording response: missing '{k}'")
    return res


# =============================================================================
# Phase 28: Watch Expressions & Runtime Value Tracking (10 Tools)
# =============================================================================

@server.tool(
    name="list_watches",
    description="Lists all configured watch expressions in x64dbg with their IDs, names, expressions, types, cached values, and watchdog states."
)
def list_watches() -> dict:
    res = query_debugger_pipe("list_watches")
    for k in ["status", "count", "watches"]:
        if k not in res:
            raise ToolError(f"Malformed list_watches response: missing '{k}'")
    return res


@server.tool(
    name="get_watch",
    description="Retrieves details for a specific watch expression by its integer ID, with optional live expression re-evaluation."
)
def get_watch(id: Union[int, str], evaluate: bool = False) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    if not isinstance(evaluate, bool):
        raise ToolError("Invalid 'evaluate': must be a boolean")

    res = query_debugger_pipe("get_watch", {"id": watch_id, "evaluate": evaluate})
    for k in ["status", "id", "name", "expression", "type", "value", "watchdog_mode", "watchdog_triggered"]:
        if k not in res:
            raise ToolError(f"Malformed get_watch response: missing '{k}'")
    return res


@server.tool(
    name="add_watch",
    description="Adds a new watch expression to x64dbg with an optional display type ('uint', 'int', 'float', 'ascii', 'unicode')."
)
def add_watch(expression: str, type: str = "uint") -> dict:
    if not isinstance(expression, str) or not expression.strip():
        raise ToolError("Invalid 'expression': must be a non-empty string expression")
    if not isinstance(type, str):
        raise ToolError("Invalid 'type': must be a string ('uint', 'int', 'float', 'ascii', 'unicode')")
    type_clean = type.strip().lower()
    valid_types = ("uint", "int", "float", "ascii", "unicode")
    if type_clean not in valid_types:
        raise ToolError(f"Invalid 'type': must be one of {valid_types}")

    res = query_debugger_pipe("add_watch", {"expression": expression.strip(), "type": type_clean})
    for k in ["status", "id", "name", "expression", "type", "value", "watchdog_mode", "watchdog_triggered"]:
        if k not in res:
            raise ToolError(f"Malformed add_watch response: missing '{k}'")
    return res


@server.tool(
    name="modify_watch",
    description="Modifies the expression and optional data type of an existing watch item by ID."
)
def modify_watch(id: Union[int, str], expression: str, type: Optional[str] = None) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    if not isinstance(expression, str) or not expression.strip():
        raise ToolError("Invalid 'expression': must be a non-empty string expression")

    params = {"id": watch_id, "expression": expression.strip()}
    if type is not None:
        if not isinstance(type, str):
            raise ToolError("Invalid 'type': must be a string")
        type_clean = type.strip().lower()
        valid_types = ("uint", "int", "float", "ascii", "unicode")
        if type_clean not in valid_types:
            raise ToolError(f"Invalid 'type': must be one of {valid_types}")
        params["type"] = type_clean

    res = query_debugger_pipe("modify_watch", params)
    for k in ["status", "id", "name", "expression", "type", "value", "watchdog_mode", "watchdog_triggered"]:
        if k not in res:
            raise ToolError(f"Malformed modify_watch response: missing '{k}'")
    return res


@server.tool(
    name="rename_watch",
    description="Renames an existing watch expression item by its ID."
)
def rename_watch(id: Union[int, str], name: str) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty string")
    if len(name.strip()) >= 64:
        raise ToolError("Invalid 'name': exceeds maximum length of 63 characters")

    res = query_debugger_pipe("rename_watch", {"id": watch_id, "name": name.strip()})
    for k in ["status", "id", "name", "previous_name", "expression"]:
        if k not in res:
            raise ToolError(f"Malformed rename_watch response: missing '{k}'")
    return res


@server.tool(
    name="set_watch_type",
    description="Changes the data interpretation type of an existing watch item ('uint', 'int', 'float', 'ascii', 'unicode')."
)
def set_watch_type(id: Union[int, str], type: str) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    if not isinstance(type, str):
        raise ToolError("Invalid 'type': must be a string")
    type_clean = type.strip().lower()
    valid_types = ("uint", "int", "float", "ascii", "unicode")
    if type_clean not in valid_types:
        raise ToolError(f"Invalid 'type': must be one of {valid_types}")

    res = query_debugger_pipe("set_watch_type", {"id": watch_id, "type": type_clean})
    for k in ["status", "id", "previous_type", "type"]:
        if k not in res:
            raise ToolError(f"Malformed set_watch_type response: missing '{k}'")
    return res


@server.tool(
    name="delete_watch",
    description="Deletes a watch item by its ID."
)
def delete_watch(id: Union[int, str]) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    res = query_debugger_pipe("delete_watch", {"id": watch_id})
    for k in ["status", "deleted", "id"]:
        if k not in res:
            raise ToolError(f"Malformed delete_watch response: missing '{k}'")
    return res


@server.tool(
    name="clear_watches",
    description="Deletes all watch expression items from x64dbg. Requires explicit confirmation."
)
def clear_watches(confirm: bool = False) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Confirmation required: set confirm to True to clear all watch expressions")

    res = query_debugger_pipe("clear_watches", {"confirm": True})
    for k in ["status", "cleared", "deleted_count"]:
        if k not in res:
            raise ToolError(f"Malformed clear_watches response: missing '{k}'")
    return res


@server.tool(
    name="set_watchdog",
    description="Configures or toggles the watchdog trigger mode of a watch item ('disabled', 'changed', 'unchanged', 'istrue', 'isfalse'). When mode is omitted, toggles between 'disabled' and 'changed'."
)
def set_watchdog(id: Union[int, str], mode: Optional[str] = None) -> dict:
    if isinstance(id, int):
        if id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
        watch_id = id
    elif isinstance(id, str) and id.strip().isdigit():
        watch_id = int(id.strip())
        if watch_id <= 0:
            raise ToolError("Invalid 'id': must be a positive integer")
    else:
        raise ToolError("Invalid 'id': must be a positive integer or numeric string")

    params = {"id": watch_id}
    if mode is not None:
        if not isinstance(mode, str):
            raise ToolError("Invalid 'mode': must be a string")
        mode_clean = mode.strip().lower()
        valid_modes = ("disabled", "changed", "unchanged", "istrue", "isfalse")
        if mode_clean not in valid_modes:
            raise ToolError(f"Invalid 'mode': must be one of {valid_modes}")
        params["mode"] = mode_clean

    res = query_debugger_pipe("set_watchdog", params)
    for k in ["status", "id", "previous_mode", "mode", "watchdog_triggered"]:
        if k not in res:
            raise ToolError(f"Malformed set_watchdog response: missing '{k}'")
    return res


@server.tool(
    name="check_watchdogs",
    description="Evaluates all watch items in x64dbg, updates their watchdog triggered state, and returns triggered watches."
)
def check_watchdogs() -> dict:
    res = query_debugger_pipe("check_watchdogs")
    for k in ["status", "triggered", "triggered_count", "total_watches", "triggered_watches"]:
        if k not in res:
            raise ToolError(f"Malformed check_watchdogs response: missing '{k}'")
    return res


def _parse_trace_address(val: Union[int, str], name: str = "address") -> int:
    if isinstance(val, int):
        if val < 0:
            raise ToolError(f"Invalid '{name}': must be non-negative")
        return val
    elif isinstance(val, str):
        v = val.strip()
        try:
            if v.startswith(("0x", "0X")):
                return int(v, 16)
            return int(v)
        except ValueError:
            try:
                return int(v, 16)
            except ValueError:
                raise ToolError(f"Invalid '{name}': '{val}' is not a valid integer or hex address")
    else:
        raise ToolError(f"Invalid '{name}': expected int or hex string")


@server.tool(
    name="open_trace_file",
    description="Opens and indexes an x64dbg .trace32 / .trace64 execution trace file, returning a session handle and metadata."
)
def open_trace_file(path: str) -> dict:
    if not isinstance(path, str) or not path.strip():
        raise ToolError("Invalid 'path': must be a non-empty string path")
    clean_path = path.strip().strip('"').strip("'")
    try:
        tid, trace = trace_sessions.open_trace(clean_path)
    except (TraceError, OSError) as e:
        raise ToolError(f"Failed to open trace file: {e}")

    return {
        "status": "success",
        "trace_id": tid,
        "path": trace.file_path,
        "file_size": trace.file_size,
        "version": trace.header.version,
        "architecture": trace.header.arch,
        "hash_algorithm": trace.header.hash_algorithm,
        "hash": trace.header.hash,
        "executable_path": trace.header.executable_path,
        "instruction_count": trace.length,
        "is_valid": trace.is_valid
    }


@server.tool(
    name="close_trace_file",
    description="Closes an open trace file session and releases cached resources."
)
def close_trace_file(trace_id: str) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    tid = trace_id.strip()
    closed = trace_sessions.close_trace(tid)
    if closed:
        return {"status": "success", "trace_id": tid, "closed": True}
    else:
        return {"status": "not_found", "trace_id": tid, "closed": False, "message": "Trace session not found or already closed"}


@server.tool(
    name="get_trace_info",
    description="Returns metadata for an open trace session (architecture, file size, version, instruction count, hash, path)."
)
def get_trace_info(trace_id: str) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
    except TraceError as e:
        raise ToolError(str(e))

    return {
        "status": "success",
        "trace_id": tid,
        "path": trace.file_path,
        "file_size": trace.file_size,
        "version": trace.header.version,
        "architecture": trace.header.arch,
        "executable_path": trace.header.executable_path,
        "executable_hash": trace.header.hash,
        "hash_algorithm": trace.header.hash_algorithm,
        "compression": trace.header.compression,
        "instruction_count": trace.length,
        "is_valid": trace.is_valid
    }


@server.tool(
    name="get_trace_instruction",
    description="Returns detailed execution information for a single historical instruction by trace index."
)
def get_trace_instruction(trace_id: str, index: int) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    if not isinstance(index, int) or index < 0:
        raise ToolError("Invalid 'index': must be a non-negative integer")

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        inst = trace.get_instruction(index)
    except TraceError as e:
        raise ToolError(str(e))

    arch = trace.header.arch
    if arch == "x64":
        reg_summary = {
            "rax": hex(inst.regwords[0]),
            "rcx": hex(inst.regwords[1]),
            "rdx": hex(inst.regwords[2]),
            "rbx": hex(inst.regwords[3]),
            "rsp": hex(inst.regwords[4]),
            "rbp": hex(inst.regwords[5]),
            "rsi": hex(inst.regwords[6]),
            "rdi": hex(inst.regwords[7]),
            "rip": hex(inst.regwords[16]),
            "rflags": hex(inst.regwords[17]),
        }
    else:
        reg_summary = {
            "eax": hex(inst.regwords[0]),
            "ecx": hex(inst.regwords[1]),
            "edx": hex(inst.regwords[2]),
            "ebx": hex(inst.regwords[3]),
            "esp": hex(inst.regwords[4]),
            "ebp": hex(inst.regwords[5]),
            "esi": hex(inst.regwords[6]),
            "edi": hex(inst.regwords[7]),
            "eip": hex(inst.regwords[8]),
            "eflags": hex(inst.regwords[9]),
        }

    return {
        "status": "success",
        "trace_id": tid,
        "index": inst.index,
        "address": hex(inst.cip),
        "thread_id": inst.thread_id,
        "opcode": inst.opcode.hex(),
        "opcode_size": len(inst.opcode),
        "disassembly": disassemble_simple(inst.opcode, inst.cip, arch),
        "register_summary": reg_summary,
        "memory_access_count": len(inst.mem_accesses)
    }


@server.tool(
    name="get_trace_instructions",
    description="Returns a paginated list of historical trace instructions starting from start_index."
)
def get_trace_instructions(trace_id: str, start_index: int, count: Optional[int] = 50) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    if not isinstance(start_index, int) or start_index < 0:
        raise ToolError("Invalid 'start_index': must be a non-negative integer")

    req_count = 50
    if count is not None:
        if not isinstance(count, int) or count <= 0:
            raise ToolError("Invalid 'count': must be a positive integer")
        req_count = min(count, 500)

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
    except TraceError as e:
        raise ToolError(str(e))

    end_index = min(start_index + req_count, trace.length)
    items = []
    arch = trace.header.arch
    for idx in range(start_index, end_index):
        try:
            inst = trace.get_instruction(idx)
            items.append({
                "index": inst.index,
                "address": hex(inst.cip),
                "thread_id": inst.thread_id,
                "opcode": inst.opcode.hex(),
                "disassembly": disassemble_simple(inst.opcode, inst.cip, arch),
                "memory_access_count": len(inst.mem_accesses)
            })
        except TraceError as e:
            raise ToolError(f"Error fetching instruction {idx}: {e}")

    next_idx = end_index if end_index < trace.length else None

    return {
        "status": "success",
        "trace_id": tid,
        "start_index": start_index,
        "count": len(items),
        "total_instructions": trace.length,
        "next_index": next_idx,
        "instructions": items
    }


@server.tool(
    name="get_trace_registers",
    description="Reconstructs and returns the full historical register context at the specified trace index."
)
def get_trace_registers(trace_id: str, index: int) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    if not isinstance(index, int) or index < 0:
        raise ToolError("Invalid 'index': must be a non-negative integer")

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        inst = trace.get_instruction(index)
    except TraceError as e:
        raise ToolError(str(e))

    arch = trace.header.arch
    name_map = X64_REG_NAMES if arch == "x64" else X86_REG_NAMES
    regs = {}
    for r_idx, r_name in name_map.items():
        if r_idx < len(inst.regwords):
            regs[r_name] = hex(inst.regwords[r_idx])

    return {
        "status": "success",
        "trace_id": tid,
        "index": inst.index,
        "architecture": arch,
        "registers": regs
    }


@server.tool(
    name="get_trace_memory_accesses",
    description="Returns the memory operands and accesses recorded for the specified historical instruction."
)
def get_trace_memory_accesses(trace_id: str, index: int) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    if not isinstance(index, int) or index < 0:
        raise ToolError("Invalid 'index': must be a non-negative integer")

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        inst = trace.get_instruction(index)
    except TraceError as e:
        raise ToolError(str(e))

    accesses = []
    for addr, old_v, new_v, flag in inst.mem_accesses:
        accesses.append({
            "address": hex(addr),
            "old_value": hex(old_v),
            "new_value": hex(new_v),
            "changed": bool((flag & 1) == 0),
            "flag": flag,
            "is_valid": True
        })

    return {
        "status": "success",
        "trace_id": tid,
        "index": inst.index,
        "count": len(accesses),
        "accesses": accesses
    }


@server.tool(
    name="read_trace_memory",
    description="Reconstructs historical memory bytes at a specific trace index using TraceFileDump semantics."
)
def read_trace_memory(trace_id: str, address: Union[int, str], size: int, index: int) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    addr_val = _parse_trace_address(address, "address")
    if not isinstance(size, int) or size <= 0 or size > 65536:
        raise ToolError("Invalid 'size': must be an integer between 1 and 65536")
    if not isinstance(index, int) or index < 0:
        raise ToolError("Invalid 'index': must be a non-negative integer")

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        mem_bytes, known, unknown = trace.read_memory(addr_val, size, index)
    except TraceError as e:
        raise ToolError(str(e))

    return {
        "status": "success",
        "trace_id": tid,
        "address": hex(addr_val),
        "size": size,
        "index": index,
        "bytes": mem_bytes.hex(),
        "known_bytes": known,
        "unknown_bytes": unknown
    }


@server.tool(
    name="search_trace_address",
    description="Searches historical trace execution for instructions at a specific address or address range."
)
def search_trace_address(trace_id: str, address: Union[int, str], end_address: Optional[Union[int, str]] = None, max_results: Optional[int] = 100) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    start_addr = _parse_trace_address(address, "address")
    end_addr = _parse_trace_address(end_address, "end_address") if end_address is not None else start_addr

    limit = 100
    if max_results is not None:
        if not isinstance(max_results, int) or max_results <= 0:
            raise ToolError("Invalid 'max_results': must be a positive integer")
        limit = min(max_results, 5000)

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        insts = trace.search_address(start_addr, end_addr, limit)
    except TraceError as e:
        raise ToolError(str(e))

    arch = trace.header.arch
    results = []
    for inst in insts:
        results.append({
            "index": inst.index,
            "address": hex(inst.cip),
            "thread_id": inst.thread_id,
            "opcode": inst.opcode.hex(),
            "disassembly": disassemble_simple(inst.opcode, inst.cip, arch)
        })

    return {
        "status": "success",
        "trace_id": tid,
        "address": hex(start_addr),
        "end_address": hex(end_addr),
        "count": len(results),
        "results": results
    }


@server.tool(
    name="search_trace_memory",
    description="Searches historical memory across the execution trace for a byte pattern with wildcards (e.g. '48 89 ?? 55')."
)
def search_trace_memory(trace_id: str, pattern: str, max_results: Optional[int] = 100) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    if not isinstance(pattern, str) or not pattern.strip():
        raise ToolError("Invalid 'pattern': must be a non-empty hex pattern string")

    limit = 100
    if max_results is not None:
        if not isinstance(max_results, int) or max_results <= 0:
            raise ToolError("Invalid 'max_results': must be a positive integer")
        limit = min(max_results, 5000)

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        matches = trace.search_memory(pattern, limit)
    except TraceError as e:
        raise ToolError(str(e))

    return {
        "status": "success",
        "trace_id": tid,
        "pattern": pattern,
        "count": len(matches),
        "results": matches
    }


@server.tool(
    name="get_trace_references",
    description="Finds historical instruction executions that referenced memory in the specified address range."
)
def get_trace_references(trace_id: str, start_address: Union[int, str], end_address: Optional[Union[int, str]] = None, max_results: Optional[int] = 100) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")
    start_addr = _parse_trace_address(start_address, "start_address")
    end_addr = _parse_trace_address(end_address, "end_address") if end_address is not None else start_addr

    limit = 100
    if max_results is not None:
        if not isinstance(max_results, int) or max_results <= 0:
            raise ToolError("Invalid 'max_results': must be a positive integer")
        limit = min(max_results, 5000)

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        indices = trace.get_references(start_addr, end_addr, limit)
        results = []
        for idx in indices:
            inst = trace.get_instruction(idx)
            results.append({
                "index": inst.index,
                "address": hex(inst.cip),
                "thread_id": inst.thread_id,
                "memory_accesses": len(inst.mem_accesses)
            })
    except TraceError as e:
        raise ToolError(str(e))

    return {
        "status": "success",
        "trace_id": tid,
        "start_address": hex(start_addr),
        "end_address": hex(end_addr),
        "count": len(results),
        "results": results
    }


@server.tool(
    name="find_trace_calls",
    description="Identifies CALL instructions in the historical trace, resolving destinations and direct/indirect types."
)
def find_trace_calls(trace_id: str, max_results: Optional[int] = 100, intermodular: Optional[bool] = False) -> dict:
    if not isinstance(trace_id, str) or not trace_id.strip():
        raise ToolError("Invalid 'trace_id': must be a non-empty string")

    limit = 100
    if max_results is not None:
        if not isinstance(max_results, int) or max_results <= 0:
            raise ToolError("Invalid 'max_results': must be a positive integer")
        limit = min(max_results, 5000)

    tid = trace_id.strip()
    try:
        trace = trace_sessions.get_trace(tid)
        calls = trace.find_calls(limit, intermodular=bool(intermodular))
    except TraceError as e:
        raise ToolError(str(e))

    return {
        "status": "success",
        "trace_id": tid,
        "count": len(calls),
        "calls": calls
    }


# -----------------------------------------------------------------------------
# Phase 30: Data Encoding Maps & Structured Type Inspection
# -----------------------------------------------------------------------------

@server.tool(
    name="get_data_type",
    description="Queries x64dbg's native byte encoding classification (e.g. 'byte', 'dword', 'code', 'ascii') at a given address."
)
def get_data_type(address: str, size: int = 1) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer")

    res = query_debugger_pipe("get_data_type", {"address": address.strip(), "size": size})
    for k in ["address", "size", "type", "type_name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_data_type response: missing '{k}'")
    return res


@server.tool(
    name="get_data_size",
    description="Returns the effective data/instruction size at an address using x64dbg's native encoding map rules."
)
def get_data_size(address: str, code_size: int = 16) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")
    if not isinstance(code_size, int) or code_size <= 0:
        raise ToolError("Invalid 'code_size': must be a positive integer")

    res = query_debugger_pipe("get_data_size", {"address": address.strip(), "code_size": code_size})
    for k in ["address", "code_size", "data_size", "type", "type_name", "has_map_entry", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_data_size response: missing '{k}'")
    return res


@server.tool(
    name="get_data_map",
    description="Reads a bounded segment of the native x64dbg encoding map, returning run-length encoded classification spans."
)
def get_data_map(address: str, max_bytes: int = 256) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ToolError("Invalid 'max_bytes': must be a positive integer")
    if max_bytes > 4096:
        raise ToolError("Invalid 'max_bytes': exceeds maximum limit of 4096")

    res = query_debugger_pipe("get_data_map", {"address": address.strip(), "max_bytes": max_bytes})
    for k in ["address", "segment_base", "segment_size", "map_size", "has_map", "spans", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_data_map response: missing '{k}'")
    return res


@server.tool(
    name="set_data_type",
    description="Sets the byte encoding classification (e.g. 'byte', 'dword', 'qword', 'ascii', 'unicode', 'code') for a memory range."
)
def set_data_type(address: str, size: int = 1, type: str = "byte") -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")
    if not isinstance(size, int) or size <= 0:
        raise ToolError("Invalid 'size': must be a positive integer")
    if not isinstance(type, (str, int)):
        raise ToolError("Invalid 'type': must be a string encoding name or numeric enum")

    params = {"address": address.strip(), "size": size}
    if isinstance(type, str):
        if not type.strip():
            raise ToolError("Invalid 'type': must be non-empty")
        params["type"] = type.strip().lower()
    else:
        params["type"] = type

    res = query_debugger_pipe("set_data_type", params)
    for k in ["address", "requested_size", "effective_size", "type", "type_name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_data_type response: missing '{k}'")
    return res


@server.tool(
    name="clear_data_type_range",
    description="Clears the byte encoding classification back to 'unknown' for an inclusive memory range [start_address, end_address]."
)
def clear_data_type_range(start_address: str, end_address: str) -> dict:
    if not isinstance(start_address, str) or not start_address.strip():
        raise ToolError("Invalid 'start_address': must be a non-empty string")
    if not isinstance(end_address, str) or not end_address.strip():
        raise ToolError("Invalid 'end_address': must be a non-empty string")

    res = query_debugger_pipe("clear_data_type_range", {"start_address": start_address.strip(), "end_address": end_address.strip()})
    for k in ["start_address", "end_address", "cleared_bytes", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_data_type_range response: missing '{k}'")
    return res


@server.tool(
    name="clear_data_type_segment",
    description="Clears and releases the entire encoding map for the memory segment/module containing the specified address."
)
def clear_data_type_segment(address: str) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string")

    res = query_debugger_pipe("clear_data_type_segment", {"address": address.strip()})
    for k in ["address", "segment_base", "segment_size", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_data_type_segment response: missing '{k}'")
    return res


@server.tool(
    name="inspect_type",
    description="Recursively visits and inspects a structured C/C++ type definition using x64dbg's native type visitor (DbgTypeVisit)."
)
def inspect_type(type_name: str, address: Optional[str] = "", decl_name: Optional[str] = "", max_ptr_depth: int = 2, max_expand_depth: int = 10, max_expand_array: int = 5) -> dict:
    if not isinstance(type_name, str) or not type_name.strip():
        raise ToolError("Invalid 'type_name': must be a non-empty string")
    if not isinstance(max_ptr_depth, int) or max_ptr_depth < 0 or max_ptr_depth > 5:
        raise ToolError("Invalid 'max_ptr_depth': must be an integer between 0 and 5")
    if not isinstance(max_expand_depth, int) or max_expand_depth < 0 or max_expand_depth > 20:
        raise ToolError("Invalid 'max_expand_depth': must be an integer between 0 and 20")
    if not isinstance(max_expand_array, int) or max_expand_array < 0 or max_expand_array > 50:
        raise ToolError("Invalid 'max_expand_array': must be an integer between 0 and 50")

    params = {
        "type_name": type_name.strip(),
        "address": address.strip() if isinstance(address, str) else "",
        "decl_name": decl_name.strip() if isinstance(decl_name, str) else "",
        "max_ptr_depth": max_ptr_depth,
        "max_expand_depth": max_expand_depth,
        "max_expand_array": max_expand_array
    }
    res = query_debugger_pipe("inspect_type", params)
    for k in ["type_name", "total_nodes", "truncated", "roots", "success"]:
        if k not in res:
            raise ToolError(f"Malformed inspect_type response: missing '{k}'")
    return res


@server.tool(
    name="get_type_size",
    description="Queries the size in bytes and underlying type of a registered type using x64dbg's native type database (SizeofType)."
)
def get_type_size(type_name: str) -> dict:
    if not isinstance(type_name, str) or not type_name.strip():
        raise ToolError("Invalid 'type_name': must be a non-empty string")

    res = query_debugger_pipe("get_type_size", {"type_name": type_name.strip()})
    for k in ["type_name", "size", "underlying_type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_type_size response: missing '{k}'")
    return res


@server.tool(
    name="list_struct_types",
    description="Enumerates registered structured types (structs, unions, classes) with category and size information."
)
def list_struct_types(filter: str = "", offset: int = 0, limit: int = 100) -> dict:
    if not isinstance(filter, str):
        raise ToolError("Invalid 'filter': must be a string")
    if not isinstance(offset, int) or offset < 0:
        raise ToolError("Invalid 'offset': must be a non-negative integer")
    if not isinstance(limit, int) or limit <= 0:
        raise ToolError("Invalid 'limit': must be a positive integer")
    if limit > 500:
        limit = 500

    params = {"filter": filter.strip(), "offset": offset, "limit": limit}
    res = query_debugger_pipe("list_struct_types", params)
    for k in ["count", "total", "types", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_struct_types response: missing '{k}'")
    return res


@server.tool(
    name="add_type",
    description="Defines a new type alias/typedef in x64dbg's type database (AddType command)."
)
def add_type(name: str, type: str, owner: Optional[str] = "") -> dict:
    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty identifier string")
    if not isinstance(type, str) or not type.strip():
        raise ToolError("Invalid 'type': must be a non-empty existing type string")

    params = {"name": name.strip(), "type": type.strip()}
    if owner and isinstance(owner, str) and owner.strip():
        params["owner"] = owner.strip()

    res = query_debugger_pipe("add_type", params)
    for k in ["name", "type", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_type response: missing '{k}'")
    return res


@server.tool(
    name="add_struct_type",
    description="Registers a new empty struct definition in x64dbg's type database (AddStruct command)."
)
def add_struct_type(name: str) -> dict:
    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty struct name")

    res = query_debugger_pipe("add_struct_type", {"name": name.strip()})
    for k in ["name", "category", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_struct_type response: missing '{k}'")
    return res


@server.tool(
    name="add_union_type",
    description="Registers a new empty union definition in x64dbg's type database (AddUnion command)."
)
def add_union_type(name: str) -> dict:
    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty union name")

    res = query_debugger_pipe("add_union_type", {"name": name.strip()})
    for k in ["name", "category", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_union_type response: missing '{k}'")
    return res


@server.tool(
    name="add_struct_member",
    description="Adds a member field to an existing struct or union type definition in x64dbg (AddMember command)."
)
def add_struct_member(parent_type: str, member_type: str, name: str, array_size: int = 0, offset: int = -1) -> dict:
    if not isinstance(parent_type, str) or not parent_type.strip():
        raise ToolError("Invalid 'parent_type': must be a non-empty string")
    if not isinstance(member_type, str) or not member_type.strip():
        raise ToolError("Invalid 'member_type': must be a non-empty string")
    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty member name")
    if not isinstance(array_size, int) or array_size < 0:
        raise ToolError("Invalid 'array_size': must be a non-negative integer")
    if not isinstance(offset, int):
        raise ToolError("Invalid 'offset': must be an integer (-1 for auto-layout)")

    params = {
        "parent_type": parent_type.strip(),
        "member_type": member_type.strip(),
        "name": name.strip(),
        "array_size": array_size,
        "offset": offset
    }
    res = query_debugger_pipe("add_struct_member", params)
    for k in ["parent_type", "member_type", "name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed add_struct_member response: missing '{k}'")
    return res


@server.tool(
    name="remove_type",
    description="Removes a user-defined type, struct, or union from x64dbg's type database (RemoveType command)."
)
def remove_type(name: str) -> dict:
    if not isinstance(name, str) or not name.strip():
        raise ToolError("Invalid 'name': must be a non-empty type name")

    res = query_debugger_pipe("remove_type", {"name": name.strip()})
    for k in ["name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed remove_type response: missing '{k}'")
    return res


@server.tool(
    name="clear_types",
    description="Clears user-defined types from x64dbg's type database (ClearTypes command). Destructive operation requiring confirm=True."
)
def clear_types(confirm: bool, owner: Optional[str] = "") -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Destructive operation: 'confirm' must be explicitly set to True")

    params = {"confirm": True}
    if owner and isinstance(owner, str) and owner.strip():
        params["owner"] = owner.strip()

    res = query_debugger_pipe("clear_types", params)
    for k in ["owner", "success"]:
        if k not in res:
            raise ToolError(f"Malformed clear_types response: missing '{k}'")
    return res


# =============================================================================
# Phase 31: Breakpoint References, Debugger Metadata & Configuration
# =============================================================================

@server.tool(
    name="list_breakpoint_references",
    description="Enumerates all active and inactive breakpoint references in x64dbg (BpRefList). Returns normalized identities (type, module, offset) and readable fields without exposing native pointers."
)
def list_breakpoint_references() -> dict:
    res = query_debugger_pipe("list_breakpoint_references", {})
    for k in ["count", "references", "success"]:
        if k not in res:
            raise ToolError(f"Malformed list_breakpoint_references response: missing '{k}'")
    return res


@server.tool(
    name="get_breakpoint_reference",
    description="Queries a specific breakpoint reference by address (VA), type, module, and offset (BpRefVa/BpRefDll/BpRefException/BpRefExists). Returns normalized reference identity and all readable fields."
)
def get_breakpoint_reference(
    address: Optional[str] = None,
    type: Optional[str] = None,
    module: Optional[str] = None,
    offset: Optional[Union[str, int]] = None,
    module_name: Optional[str] = None,
    exception_code: Optional[int] = None
) -> dict:
    params = {}
    if address is not None:
        if not isinstance(address, str) or not address.strip():
            raise ToolError("Invalid 'address': must be a non-empty string address")
        params["address"] = address.strip()
    if type is not None:
        if not isinstance(type, (str, int)):
            raise ToolError("Invalid 'type': must be a string (normal, hardware, memory, dll, exception) or integer")
        params["type"] = type
    if module is not None:
        params["module"] = str(module).strip()
    if offset is not None:
        params["offset"] = offset
    if module_name is not None:
        params["module_name"] = str(module_name).strip()
    if exception_code is not None:
        params["exception_code"] = int(exception_code)

    res = query_debugger_pipe("get_breakpoint_reference", params)
    for k in ["reference", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_breakpoint_reference response: missing '{k}'")
    return res


@server.tool(
    name="set_breakpoint_reference_fields",
    description="Mutates supported fields on a breakpoint reference (singleshoot, silent, fastresume, hitcount, name, breakcondition, logtext, logcondition, commandtext, commandcondition, logfile). Rejects read-only fields and 'enabled' (use enable_breakpoint/disable_breakpoint)."
)
def set_breakpoint_reference_fields(
    address: Optional[str] = None,
    type: Optional[str] = None,
    module: Optional[str] = None,
    offset: Optional[Union[str, int]] = None,
    module_name: Optional[str] = None,
    exception_code: Optional[int] = None,
    singleshoot: Optional[bool] = None,
    silent: Optional[bool] = None,
    fastresume: Optional[bool] = None,
    hitcount: Optional[int] = None,
    name: Optional[str] = None,
    breakcondition: Optional[str] = None,
    logtext: Optional[str] = None,
    logcondition: Optional[str] = None,
    commandtext: Optional[str] = None,
    commandcondition: Optional[str] = None,
    logfile: Optional[str] = None,
    enabled: Optional[bool] = None,
    active: Optional[bool] = None,
    oldbytes: Optional[int] = None,
    typeex: Optional[int] = None,
    hwsize: Optional[int] = None,
    hwslot: Optional[int] = None
) -> dict:
    if enabled is not None:
        raise ToolError("'enabled' cannot be modified via breakpoint references; use enable_breakpoint / disable_breakpoint tools instead")

    for rof_name, rof_val in [("active", active), ("oldbytes", oldbytes), ("typeex", typeex),
                              ("hwsize", hwsize), ("hwslot", hwslot)]:
        if rof_val is not None:
            raise ToolError(f"Field '{rof_name}' is read-only and cannot be modified")

    params = {}
    if address is not None:
        if not isinstance(address, str) or not address.strip():
            raise ToolError("Invalid 'address': must be a non-empty string address")
        params["address"] = address.strip()
    if type is not None:
        params["type"] = type
    if module is not None:
        params["module"] = str(module).strip()
    if offset is not None:
        params["offset"] = offset
    if module_name is not None:
        params["module_name"] = str(module_name).strip()
    if exception_code is not None:
        params["exception_code"] = int(exception_code)

    if singleshoot is not None:
        params["singleshoot"] = bool(singleshoot)
    if silent is not None:
        params["silent"] = bool(silent)
    if fastresume is not None:
        params["fastresume"] = bool(fastresume)
    if hitcount is not None:
        if not isinstance(hitcount, int) or hitcount < 0:
            raise ToolError("Invalid 'hitcount': must be a non-negative integer")
        params["hitcount"] = hitcount
    if name is not None:
        params["name"] = str(name)
    if breakcondition is not None:
        params["breakcondition"] = str(breakcondition)
    if logtext is not None:
        params["logtext"] = str(logtext)
    if logcondition is not None:
        params["logcondition"] = str(logcondition)
    if commandtext is not None:
        params["commandtext"] = str(commandtext)
    if commandcondition is not None:
        params["commandcondition"] = str(commandcondition)
    if logfile is not None:
        params["logfile"] = str(logfile)

    res = query_debugger_pipe("set_breakpoint_reference_fields", params)
    for k in ["updated_fields", "updated_count", "reference", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_breakpoint_reference_fields response: missing '{k}'")
    return res


@server.tool(
    name="get_thread_name",
    description="Retrieves the debugger-side metadata name for a thread by thread ID (ThreadGetName). Does not query OS-level thread names."
)
def get_thread_name(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer TID")

    res = query_debugger_pipe("get_thread_name", {"thread_id": thread_id})
    for k in ["thread_id", "name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_thread_name response: missing '{k}'")
    return res


@server.tool(
    name="set_thread_name",
    description="Sets or clears the debugger-side metadata name for a thread by thread ID (setthreadname command). Pass empty string to clear."
)
def set_thread_name(thread_id: int, name: str = "") -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer TID")
    if not isinstance(name, str):
        raise ToolError("Invalid 'name': must be a string")

    res = query_debugger_pipe("set_thread_name", {"thread_id": thread_id, "name": name})
    for k in ["thread_id", "name", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_thread_name response: missing '{k}'")
    return res


@server.tool(
    name="set_thread_priority",
    description="Sets the execution priority of a thread by thread ID (setthreadpriority command). Accepts documented priority names ('Normal', 'AboveNormal', 'TimeCritical', 'Idle', 'BelowNormal', 'Highest', 'Lowest') or integer values (-15, -2, -1, 0, 1, 2, 15)."
)
def set_thread_priority(thread_id: int, priority: Union[str, int]) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer TID")
    if not isinstance(priority, (str, int)):
        raise ToolError("Invalid 'priority': must be a string or integer priority")

    res = query_debugger_pipe("set_thread_priority", {"thread_id": thread_id, "priority": priority})
    for k in ["thread_id", "priority", "priority_value", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_thread_priority response: missing '{k}'")
    return res


@server.tool(
    name="get_thread_priority",
    description="Retrieves the current execution priority of a thread by thread ID from the debugger's thread snapshot."
)
def get_thread_priority(thread_id: int) -> dict:
    if not isinstance(thread_id, int) or thread_id <= 0:
        raise ToolError("Invalid 'thread_id': must be a positive integer TID")

    res = query_debugger_pipe("get_thread_priority", {"thread_id": thread_id})
    for k in ["thread_id", "priority", "priority_value", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_thread_priority response: missing '{k}'")
    return res


@server.tool(
    name="set_module_party",
    description="Sets the party classification for a module (user vs system) using ModSetParty. Setting non-default party persists in x64dbg database cache."
)
def set_module_party(
    party: Union[str, int],
    module: Optional[str] = None,
    address: Optional[str] = None
) -> dict:
    params = {}
    if module is not None:
        if not isinstance(module, str) or not module.strip():
            raise ToolError("Invalid 'module': must be a string module name")
        params["module"] = module.strip()
    if address is not None:
        if not isinstance(address, str) or not address.strip():
            raise ToolError("Invalid 'address': must be a string address expression")
        params["address"] = address.strip()

    if not isinstance(party, (str, int)):
        raise ToolError("Invalid 'party': must be 'user' (0) or 'system' (1)")
    params["party"] = party

    res = query_debugger_pipe("set_module_party", params)
    for k in ["module", "base", "party", "party_code", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_module_party response: missing '{k}'")
    return res


@server.tool(
    name="is_code_page",
    description="Determines whether a memory page is executable code (MemIsCodePage). Supports optional cache refresh/skip-cache parameter."
)
def is_code_page(address: str, skip_cache: bool = False) -> dict:
    if not isinstance(address, str) or not address.strip():
        raise ToolError("Invalid 'address': must be a non-empty string address")
    if not isinstance(skip_cache, bool):
        raise ToolError("Invalid 'skip_cache': must be a boolean")

    res = query_debugger_pipe("is_code_page", {"address": address.strip(), "skip_cache": skip_cache})
    for k in ["address", "is_code_page", "skip_cache", "success"]:
        if k not in res:
            raise ToolError(f"Malformed is_code_page response: missing '{k}'")
    return res


@server.tool(
    name="get_mnemonic_brief",
    description="Retrieves a brief description for an x86/x64 instruction mnemonic (GetMnemonicBrief)."
)
def get_mnemonic_brief(mnemonic: str) -> dict:
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ToolError("Invalid 'mnemonic': must be a non-empty string mnemonic (e.g. 'mov', 'nop')")

    res = query_debugger_pipe("get_mnemonic_brief", {"mnemonic": mnemonic.strip()})
    for k in ["mnemonic", "brief", "found", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_mnemonic_brief response: missing '{k}'")
    return res


@server.tool(
    name="get_debuggee_init_script",
    description="Retrieves the currently configured debuggee initialization script path (dbggetdebuggeeinitscript). Persisted in x64dbg database."
)
def get_debuggee_init_script() -> dict:
    res = query_debugger_pipe("get_debuggee_init_script", {})
    for k in ["script_path", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_debuggee_init_script response: missing '{k}'")
    return res


@server.tool(
    name="set_debuggee_init_script",
    description="Sets or clears the debuggee initialization script path (dbgsetdebuggeeinitscript). Pass empty string to clear. Persisted in x64dbg database."
)
def set_debuggee_init_script(script_path: str = "") -> dict:
    if not isinstance(script_path, str):
        raise ToolError("Invalid 'script_path': must be a string path")

    res = query_debugger_pipe("set_debuggee_init_script", {"script_path": script_path})
    for k in ["script_path", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_debuggee_init_script response: missing '{k}'")
    return res


@server.tool(
    name="get_jit_info",
    description="Consolidates system Just-In-Time (JIT) debugger configuration (GetJit, GetDefJit, GetJitAuto). Returns elevation status, x64/x32 entries, default entry, old entry, and auto-JIT flag."
)
def get_jit_info() -> dict:
    res = query_debugger_pipe("get_jit_info", {})
    for k in ["is_elevated", "x64", "x32", "default_entry", "old_entry", "has_old_entry", "jit_auto", "success"]:
        if k not in res:
            raise ToolError(f"Malformed get_jit_info response: missing '{k}'")
    return res


@server.tool(
    name="set_jit",
    description="Configures system Just-In-Time (JIT) debugger entry (setjit command). Mutating global system state; requires confirm=True and process elevation."
)
def set_jit(
    confirm: bool,
    mode: Optional[str] = "default",
    command: Optional[str] = None,
    arch: Optional[str] = None
) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Destructive/global operation: 'confirm' must be explicitly set to True to modify JIT settings")

    params = {"confirm": True}
    if mode is not None:
        params["mode"] = str(mode)
    if command is not None:
        params["command"] = str(command)
    if arch is not None:
        if str(arch).lower() not in ["x64", "x32", "both"]:
            raise ToolError("Invalid 'arch': must be 'x64', 'x32', or 'both'")
        params["arch"] = str(arch).lower()

    res = query_debugger_pipe("set_jit", params)
    for k in ["entry", "arch", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_jit response: missing '{k}'")
    return res


@server.tool(
    name="set_jit_auto",
    description="Configures system Just-In-Time (JIT) auto-start setting (setjitauto command). Mutating global system state; requires confirm=True and process elevation."
)
def set_jit_auto(
    confirm: bool,
    enabled: bool,
    arch: Optional[str] = None
) -> dict:
    if not isinstance(confirm, bool) or not confirm:
        raise ToolError("Destructive/global operation: 'confirm' must be explicitly set to True to modify JIT auto settings")
    if not isinstance(enabled, bool):
        raise ToolError("Invalid 'enabled': must be a boolean")

    params = {"confirm": True, "enabled": enabled}
    if arch is not None:
        if str(arch).lower() not in ["x64", "x32"]:
            raise ToolError("Invalid 'arch': must be 'x64' or 'x32'")
        params["arch"] = str(arch).lower()

    res = query_debugger_pipe("set_jit_auto", params)
    for k in ["jit_auto", "success"]:
        if k not in res:
            raise ToolError(f"Malformed set_jit_auto response: missing '{k}'")
    return res


def main():


    logger.info("Starting x64dbg MCP server on stdio transport...")
    server.run(transport="stdio")


if __name__ == "__main__":
    main()



