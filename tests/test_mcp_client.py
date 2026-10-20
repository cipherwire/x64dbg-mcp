import sys
import os
import tempfile
import json
import struct
import anyio
import ctypes
from ctypes import wintypes
from mcp import ClientSession, stdio_client
from mcp.client.stdio import StdioServerParameters


def dismiss_x64dbg_dialogs():
    user32 = ctypes.windll.user32
    def enum_cb(hwnd, extra):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if buf.value in ["Question", "Warning", "Information"]:
                    user32.PostMessageW(hwnd, 0x0100, 0x0D, 0)
                    user32.PostMessageW(hwnd, 0x0101, 0x0D, 0)
        return True
    WNDENUM = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(WNDENUM(enum_cb), 0)


_curr_dir = os.path.dirname(os.path.abspath(__file__))
_repo_root = _curr_dir if os.path.exists(os.path.join(_curr_dir, "mcp_server", "server.py")) else os.path.dirname(_curr_dir)
SERVER_PARAMS = StdioServerParameters(
    command=sys.executable,
    args=["-u", os.path.join(_repo_root, "mcp_server", "server.py")]
)


async def run_mcp_test() -> int:
    print("[MCP-TEST] Launching MCP stdio server...")
    async with stdio_client(SERVER_PARAMS) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # 1. Initialize MCP session
            init_res = await session.initialize()
            print(f"[MCP-TEST] Initialized: server={init_res.server_info.name} v{init_res.server_info.version}")
            print(f"[MCP-TEST] Protocol version: {init_res.protocol_version}")

            # 2. List tools
            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            print(f"[MCP-TEST] Tools discovered: {tool_names}")

            expected_tools = [
                "add_argument", "add_function", "add_loop", "add_struct_member", "add_struct_type", "add_type", "add_union_type", "add_watch", "allocate_memory", "analyze_advanced", "analyze_code",
                "analyze_control_flow", "analyze_exception_directory", "analyze_nukem", "analyze_recursive", "analyze_xrefs",
                "assemble", "attach_process",
                "check_watchdogs", "clear_arguments", "clear_bookmarks", "clear_comments", "clear_data_type_range", "clear_data_type_segment", "clear_database", "clear_debug_events", "clear_functions", "clear_labels", "clear_loops", "clear_types", "clear_watches", "close_trace_file",
                "configure_breakpoint", "copy_memory", "create_minidump",
                "delete_argument", "delete_bookmark", "delete_breakpoint", "delete_comment", "delete_dll_breakpoint",
                "delete_exception_breakpoint", "delete_function", "delete_hardware_breakpoint", "delete_label", "delete_loop", "delete_memory_breakpoint", "delete_watch",
                "detach_process", "disassemble", "dump_memory", "dump_module",
                "enable_breakpoint", "enable_dll_breakpoint",
                "enable_exception_breakpoint", "enable_hardware_breakpoint", "enable_memory_breakpoint",
                "eval_expression", "file_offset_to_va", "fill_memory", "find_pattern", "find_source_address", "find_strings", "find_trace_calls",
                "format_inline_string", "free_memory",
                "get_address_info", "get_argument", "get_bookmark", "get_breakpoint_details", "get_breakpoint_reference", "get_bridge_status", "get_call_stack",
                "get_command_line", "get_comment", "get_control_flow_graph", "get_data_map", "get_data_size", "get_data_type", "get_debug_events", "get_debug_session_info", "get_debuggee_init_script", "get_debugger_state",
                "get_event_status", "get_exception_info", "get_function_boundary", "get_function_callees", "get_function_callers", "get_function_info", "get_handle_info", "get_jit_info", "get_label",
                "get_last_exception", "get_loop", "get_memory_region", "get_mnemonic_brief", "get_module_party", "get_page_rights", "get_patch", "get_pe_headers", "get_peb_info",
                "get_registers", "get_relocation", "get_runtime_function", "get_security_mitigations", "get_seh_chain", "get_source_location", "get_symbol_status",
                "get_teb_info", "get_thread_call_stack", "get_thread_name", "get_thread_priority", "get_trace_info", "get_trace_instruction", "get_trace_instructions", "get_trace_memory_accesses", "get_trace_record", "get_trace_references", "get_trace_registers", "get_trace_status", "get_type_size", "get_watch", "get_xrefs", "inspect_type", "is_code_page", "kill_thread",
                "launch_debuggee", "list_arguments", "list_bookmarks", "list_breakpoint_references", "list_breakpoints", "list_comments", "list_constants", "list_error_codes", "list_exceptions", "list_exports", "list_functions", "list_handles",
                "list_heaps", "list_imports", "list_labels", "list_loops", "list_memory_regions", "list_module_sections", "list_modules",
                "list_patches", "list_pe_data_directories", "list_processes", "list_relocations", "list_runtime_functions", "list_struct_types", "list_structs",
                "list_symbols", "list_tcp_connections", "list_threads", "list_tls_callbacks", "list_watches", "list_windows",
                "load_database", "modify_watch", "open_trace_file", "patch_memory", "pause", "read_console_output", "read_memory", "read_trace_memory",
                "remove_type", "rename_watch", "reset_breakpoint_hit_count", "resolve_symbol", "restart_debuggee", "restore_patch", "restore_patches_range",
                "resume", "resume_all_threads", "resume_thread", "run_script", "run_to_address", "run_to_party", "run_to_user_code",
                "save_database", "search_trace_address", "search_trace_memory", "send_console_input", "set_bookmark", "set_breakpoint", "set_breakpoint_reference_fields", "set_command_line",
                "set_comment", "set_data_type", "set_debuggee_init_script", "set_dll_breakpoint", "set_exception_breakpoint", "set_hardware_breakpoint",
                "set_jit", "set_jit_auto", "set_label", "set_memory_breakpoint", "set_memory_range_breakpoint", "set_module_party", "set_page_rights", "set_register",
                "set_thread_name", "set_thread_priority", "set_trace_command", "set_trace_log", "set_trace_log_file", "set_trace_record_type", "set_trace_step_filter",
                "set_watch_type", "set_watchdog",
                "skip_instruction", "start_trace_recording", "step_into", "step_out", "step_out_pass_exceptions", "step_over", "step_over_pass_exceptions", "step_system", "step_user", "stop_debuggee", "stop_trace_recording",
                "suspend_all_threads", "suspend_thread", "switch_thread", "symbol_autocomplete",
                "trace_into_beyond_trace_record", "trace_into_conditional", "trace_into_trace_record",
                "trace_over_beyond_trace_record", "trace_over_conditional", "trace_over_trace_record",
                "va_to_file_offset", "wait_for_debug_event", "write_memory"
            ]

            if sorted(tool_names) != sorted(expected_tools):
                print(f"ERROR: Expected {expected_tools}, got {tool_names}", file=sys.stderr)
                return 1

            # 3. Call get_debugger_state tool (Regression check)
            print("[MCP-TEST] Invoking tool get_debugger_state...")
            state_result = await session.call_tool("get_debugger_state", {})
            print(f"[MCP-TEST] get_debugger_state is_error: {state_result.is_error}")
            for content in state_result.content:
                print(f"[MCP-TEST] State content: {content.text}")

            # Wait for debugger to settle into paused state with an active debuggee
            dismiss_x64dbg_dialogs()
            state_data = {}
            for i in range(100):
                state_result = await session.call_tool("get_debugger_state", {})
                state_data = json.loads(state_result.content[0].text)
                if state_data.get("is_debugging") is True and state_data.get("is_running") is False:
                    break
                elif state_data.get("is_debugging") is True and state_data.get("is_running") is True:
                    await session.call_tool("pause", {})
                elif state_data.get("is_debugging") is False and i % 5 == 0:
                    dismiss_x64dbg_dialogs()
                await anyio.sleep(0.2)
            assert state_data.get("is_debugging") is True, f"Debugger failed to attach/pause: {state_data}"

            # Verify get_bridge_status in paused state
            bridge_status_res = await session.call_tool("get_bridge_status", {})
            assert not bridge_status_res.is_error, f"get_bridge_status failed: {bridge_status_res.content}"
            bridge_status = json.loads(bridge_status_res.content[0].text)
            print(f"[MCP-TEST] get_bridge_status (paused): {bridge_status}")
            assert bridge_status.get("connected") is True
            assert bridge_status.get("state") == "paused"
            assert bridge_status.get("is_debugging") is True
            assert bridge_status.get("is_running") is False
            assert bridge_status.get("stop_address", "").startswith("0x")
            assert bridge_status.get("pid") is not None and bridge_status.get("pid") > 0
            assert bridge_status.get("tid") is not None and bridge_status.get("tid") > 0

            # 4. Call get_registers tool (Regression check)
            print("[MCP-TEST] Invoking tool get_registers...")
            reg_result = await session.call_tool("get_registers", {})
            print(f"[MCP-TEST] get_registers is_error: {reg_result.is_error}")
            for content in reg_result.content:
                print(f"[MCP-TEST] Register content: {content.text}")

            # 5. Call read_memory tool (Regression check)
            print("[MCP-TEST] Invoking tool read_memory(address='RIP', size=16)...")
            mem_rip_result = await session.call_tool("read_memory", {"address": "RIP", "size": 16})
            print(f"[MCP-TEST] read_memory RIP is_error: {mem_rip_result.is_error}")
            for content in mem_rip_result.content:
                print(f"[MCP-TEST] Memory content (RIP): {content.text}")

            # Query active main module name dynamically
            mod_list_res = await session.call_tool("list_modules", {})
            mod_list_data = json.loads(mod_list_res.content[0].text)
            main_module_name = ""
            if isinstance(mod_list_data, dict) and "modules" in mod_list_data and len(mod_list_data["modules"]) > 0:
                main_module_name = mod_list_data["modules"][0].get("name", "")
            elif isinstance(mod_list_data, list) and len(mod_list_data) > 0:
                main_module_name = mod_list_data[0].get("name", "")
            if not main_module_name:
                main_module_name = "main"

            print(f"[MCP-TEST] Invoking tool read_memory(address='{main_module_name}', size=64)...")
            mem_base_result = await session.call_tool("read_memory", {"address": main_module_name, "size": 64})
            print(f"[MCP-TEST] read_memory {main_module_name} is_error: {mem_base_result.is_error}")
            for content in mem_base_result.content:
                print(f"[MCP-TEST] Memory content ({main_module_name}): {content.text}")

            # 6. Negative test: read_memory on invalid address 0x0
            print("[MCP-TEST] Invoking tool read_memory(address='0x0', size=16) (expected failure)...")
            mem_null_result = await session.call_tool("read_memory", {"address": "0x0", "size": 16})
            print(f"[MCP-TEST] read_memory 0x0 is_error: {mem_null_result.is_error}")
            for content in mem_null_result.content:
                print(f"[MCP-TEST] Null read error content: {content.text}")

            # 7. Call disassemble tool (Phase 6A check)
            print("[MCP-TEST] Invoking tool disassemble(address='RIP', count=5)...")
            disasm_result = await session.call_tool("disassemble", {"address": "RIP", "count": 5})
            print(f"[MCP-TEST] disassemble is_error: {disasm_result.is_error}")
            for content in disasm_result.content:
                print(f"[MCP-TEST] Disassembly content: {content.text}")

            # 8. Negative test: disassemble on invalid address 0x0
            print("[MCP-TEST] Invoking tool disassemble(address='0x0', count=5) (expected failure)...")
            disasm_null_result = await session.call_tool("disassemble", {"address": "0x0", "count": 5})
            print(f"[MCP-TEST] disassemble 0x0 is_error: {disasm_null_result.is_error}")
            for content in disasm_null_result.content:
                print(f"[MCP-TEST] Disassemble 0x0 error content: {content.text}")

            # 9. Breakpoint tools verification (Phase 7A)
            print("[MCP-TEST] Invoking tool list_breakpoints (initial)...")
            list_initial = await session.call_tool("list_breakpoints", {})
            print(f"[MCP-TEST] list_breakpoints initial is_error: {list_initial.is_error}")
            for content in list_initial.content:
                print(f"[MCP-TEST] Initial breakpoints: {content.text}")

            print("[MCP-TEST] Invoking tool set_breakpoint(address='RIP')...")
            set_bp_res = await session.call_tool("set_breakpoint", {"address": "RIP"})
            print(f"[MCP-TEST] set_breakpoint RIP is_error: {set_bp_res.is_error}")
            for content in set_bp_res.content:
                print(f"[MCP-TEST] set_breakpoint content: {content.text}")

            print("[MCP-TEST] Invoking tool list_breakpoints (after set)...")
            list_after_set = await session.call_tool("list_breakpoints", {})
            print(f"[MCP-TEST] list_breakpoints after set is_error: {list_after_set.is_error}")
            for content in list_after_set.content:
                print(f"[MCP-TEST] Breakpoints after set: {content.text}")

            print("[MCP-TEST] Invoking duplicate set_breakpoint(address='RIP') (expected failure)...")
            set_dup_res = await session.call_tool("set_breakpoint", {"address": "RIP"})
            print(f"[MCP-TEST] duplicate set_breakpoint is_error: {set_dup_res.is_error}")
            for content in set_dup_res.content:
                print(f"[MCP-TEST] Duplicate set error content: {content.text}")

            print("[MCP-TEST] Invoking set_breakpoint(address='0x0') (expected failure)...")
            set_null_res = await session.call_tool("set_breakpoint", {"address": "0x0"})
            print(f"[MCP-TEST] null set_breakpoint is_error: {set_null_res.is_error}")
            for content in set_null_res.content:
                print(f"[MCP-TEST] Null set error content: {content.text}")

            print("[MCP-TEST] Invoking tool delete_breakpoint(address='RIP')...")
            del_bp_res = await session.call_tool("delete_breakpoint", {"address": "RIP"})
            print(f"[MCP-TEST] delete_breakpoint RIP is_error: {del_bp_res.is_error}")
            for content in del_bp_res.content:
                print(f"[MCP-TEST] delete_breakpoint content: {content.text}")

            print("[MCP-TEST] Invoking duplicate delete_breakpoint(address='RIP') (expected failure)...")
            del_dup_res = await session.call_tool("delete_breakpoint", {"address": "RIP"})
            print(f"[MCP-TEST] duplicate delete_breakpoint is_error: {del_dup_res.is_error}")
            for content in del_dup_res.content:
                print(f"[MCP-TEST] Duplicate delete error content: {content.text}")

            print("[MCP-TEST] Invoking tool list_breakpoints (after delete)...")
            list_after_del = await session.call_tool("list_breakpoints", {})
            print(f"[MCP-TEST] list_breakpoints after delete is_error: {list_after_del.is_error}")
            for content in list_after_del.content:
                print(f"[MCP-TEST] Breakpoints after delete: {content.text}")

            # 10. Execution control step_into verification (Phase 7B)
            print("[MCP-TEST] Invoking tool step_into(timeout_ms=5000)...")
            step_res = await session.call_tool("step_into", {"timeout_ms": 5000})
            print(f"[MCP-TEST] step_into is_error: {step_res.is_error}")
            for content in step_res.content:
                print(f"[MCP-TEST] step_into content: {content.text}")

            print("[MCP-TEST] Invoking invalid step_into(timeout_ms=-1) (expected failure)...")
            step_neg_res = await session.call_tool("step_into", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid step_into is_error: {step_neg_res.is_error}")
            for content in step_neg_res.content:
                print(f"[MCP-TEST] Invalid step_into error content: {content.text}")

            # 11. Execution control resume and pause verification (Phase 7C)
            print("[MCP-TEST] Invoking tool resume(timeout_ms=5000)...")
            resume_res = await session.call_tool("resume", {"timeout_ms": 5000})
            print(f"[MCP-TEST] resume is_error: {resume_res.is_error}")
            for content in resume_res.content:
                print(f"[MCP-TEST] resume content: {content.text}")

            print("[MCP-TEST] Invoking invalid resume(timeout_ms=-1) (expected failure)...")
            resume_neg_res = await session.call_tool("resume", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid resume is_error: {resume_neg_res.is_error}")
            for content in resume_neg_res.content:
                print(f"[MCP-TEST] Invalid resume error content: {content.text}")

            print("[MCP-TEST] Invoking tool pause(timeout_ms=5000)...")
            pause_res = await session.call_tool("pause", {"timeout_ms": 5000})
            print(f"[MCP-TEST] pause is_error: {pause_res.is_error}")
            for content in pause_res.content:
                print(f"[MCP-TEST] pause content: {content.text}")

            status_after_pause = await session.call_tool("get_bridge_status", {})
            assert not status_after_pause.is_error
            data_after_pause = json.loads(status_after_pause.content[0].text)
            print(f"[MCP-TEST] get_bridge_status (after pause): {data_after_pause}")
            assert data_after_pause.get("connected") is True
            assert data_after_pause.get("state") == "paused"
            assert data_after_pause.get("is_debugging") is True
            assert data_after_pause.get("is_running") is False
            assert data_after_pause.get("stop_address", "").startswith("0x")

            print("[MCP-TEST] Invoking invalid pause(timeout_ms=-1) (expected failure)...")
            pause_neg_res = await session.call_tool("pause", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid pause is_error: {pause_neg_res.is_error}")
            for content in pause_neg_res.content:
                print(f"[MCP-TEST] Invalid pause error content: {content.text}")

            # 12. Execution control step_over verification (Phase 8A)
            print("[MCP-TEST] Invoking tool step_over(timeout_ms=5000)...")
            step_over_res = await session.call_tool("step_over", {"timeout_ms": 5000})
            print(f"[MCP-TEST] step_over is_error: {step_over_res.is_error}")
            for content in step_over_res.content:
                print(f"[MCP-TEST] step_over content: {content.text}")

            print("[MCP-TEST] Invoking invalid step_over(timeout_ms=-1) (expected failure)...")
            step_over_neg_res = await session.call_tool("step_over", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid step_over is_error: {step_over_neg_res.is_error}")
            for content in step_over_neg_res.content:
                print(f"[MCP-TEST] Invalid step_over error content: {content.text}")

            # 13. Execution control step_out verification (Phase 8B)
            print("[MCP-TEST] Invoking tool step_out(timeout_ms=5000)...")
            step_out_res = await session.call_tool("step_out", {"timeout_ms": 5000})
            print(f"[MCP-TEST] step_out is_error: {step_out_res.is_error}")
            for content in step_out_res.content:
                print(f"[MCP-TEST] step_out content: {content.text}")

            print("[MCP-TEST] Invoking invalid step_out(timeout_ms=-1) (expected failure)...")
            step_out_neg_res = await session.call_tool("step_out", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid step_out is_error: {step_out_neg_res.is_error}")
            for content in step_out_neg_res.content:
                print(f"[MCP-TEST] Invalid step_out error content: {content.text}")

            # 14. Thread inspection list_threads verification (Phase 8C)
            print("[MCP-TEST] Invoking tool list_threads()...")
            list_threads_res = await session.call_tool("list_threads", {})
            print(f"[MCP-TEST] list_threads is_error: {list_threads_res.is_error}")
            for content in list_threads_res.content:
                print(f"[MCP-TEST] list_threads content: {content.text}")

            # 15. Thread switching switch_thread verification (Phase 8D)
            threads_data = json.loads(list_threads_res.content[0].text)
            active_tid = [t['thread_id'] for t in threads_data['threads'] if t['is_active']][0]
            print(f"[MCP-TEST] Invoking tool switch_thread(thread_id={active_tid}) (already active)...")
            switch_active_res = await session.call_tool("switch_thread", {"thread_id": active_tid})
            print(f"[MCP-TEST] switch_thread active is_error: {switch_active_res.is_error}")
            for content in switch_active_res.content:
                print(f"[MCP-TEST] switch_thread active content: {content.text}")

            print("[MCP-TEST] Invoking invalid switch_thread(thread_id=99999999) (expected failure)...")
            switch_nonexist_res = await session.call_tool("switch_thread", {"thread_id": 99999999})
            print(f"[MCP-TEST] invalid switch_thread non-existent is_error: {switch_nonexist_res.is_error}")
            for content in switch_nonexist_res.content:
                print(f"[MCP-TEST] Invalid switch non-existent error content: {content.text}")

            print("[MCP-TEST] Invoking invalid switch_thread(thread_id=-1) (expected failure)...")
            switch_neg_res = await session.call_tool("switch_thread", {"thread_id": -1})
            print(f"[MCP-TEST] invalid switch_thread negative is_error: {switch_neg_res.is_error}")
            for content in switch_neg_res.content:
                print(f"[MCP-TEST] Invalid switch negative error content: {content.text}")

            # 16. Module inspection list_modules verification (Phase 9A)
            print("[MCP-TEST] Invoking tool list_modules()...")
            list_modules_res = await session.call_tool("list_modules", {})
            print(f"[MCP-TEST] list_modules is_error: {list_modules_res.is_error}")
            for content in list_modules_res.content:
                print(f"[MCP-TEST] list_modules content: {content.text}")


            # 17. Module section inspection list_module_sections verification (Phase 9B)
            modules_data = json.loads(list_modules_res.content[0].text)
            target_mod = modules_data['modules'][0]['name']
            print(f"[MCP-TEST] Invoking tool list_module_sections(module='{target_mod}')...")
            list_sec_res = await session.call_tool("list_module_sections", {"module": target_mod})
            print(f"[MCP-TEST] list_module_sections is_error: {list_sec_res.is_error}")
            for content in list_sec_res.content:
                print(f"[MCP-TEST] list_module_sections content: {content.text}")

            print("[MCP-TEST] Invoking invalid list_module_sections(module='nonexistent_mod_12345.dll') (expected failure)...")
            sec_nonexist_res = await session.call_tool("list_module_sections", {"module": "nonexistent_mod_12345.dll"})
            print(f"[MCP-TEST] invalid list_module_sections nonexistent is_error: {sec_nonexist_res.is_error}")
            for content in sec_nonexist_res.content:
                print(f"[MCP-TEST] Invalid list_module_sections error content: {content.text}")

            print("[MCP-TEST] Invoking invalid list_module_sections(module='') (expected failure)...")
            sec_empty_res = await session.call_tool("list_module_sections", {"module": ""})
            print(f"[MCP-TEST] invalid list_module_sections empty is_error: {sec_empty_res.is_error}")
            for content in sec_empty_res.content:
                print(f"[MCP-TEST] Invalid list_module_sections empty error content: {content.text}")

            # 18. Memory region inspection get_memory_region verification (Phase 9C)
            print("[MCP-TEST] Invoking tool get_memory_region(address='RIP')...")
            mem_reg_res = await session.call_tool("get_memory_region", {"address": "RIP"})
            print(f"[MCP-TEST] get_memory_region is_error: {mem_reg_res.is_error}")
            for content in mem_reg_res.content:
                print(f"[MCP-TEST] get_memory_region content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_memory_region(address='0x1234garbage') (expected failure)...")
            mem_reg_invalid_res = await session.call_tool("get_memory_region", {"address": "0x1234garbage"})
            print(f"[MCP-TEST] invalid get_memory_region is_error: {mem_reg_invalid_res.is_error}")
            for content in mem_reg_invalid_res.content:
                print(f"[MCP-TEST] Invalid get_memory_region error content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_memory_region(address='') (expected failure)...")
            mem_reg_empty_res = await session.call_tool("get_memory_region", {"address": ""})
            print(f"[MCP-TEST] invalid get_memory_region empty is_error: {mem_reg_empty_res.is_error}")
            for content in mem_reg_empty_res.content:
                print(f"[MCP-TEST] Invalid get_memory_region empty error content: {content.text}")

            # 19. Memory map enumeration list_memory_regions verification (Phase 9D)
            print("[MCP-TEST] Invoking tool list_memory_regions(limit=5, include_free=False)...")
            list_mem_res = await session.call_tool("list_memory_regions", {"limit": 5, "include_free": False})
            print(f"[MCP-TEST] list_memory_regions is_error: {list_mem_res.is_error}")
            for content in list_mem_res.content:
                print(f"[MCP-TEST] list_memory_regions content: {content.text}")

            print("[MCP-TEST] Invoking invalid list_memory_regions(limit=0) (expected failure)...")
            list_mem_zero_res = await session.call_tool("list_memory_regions", {"limit": 0})
            print(f"[MCP-TEST] invalid list_memory_regions zero is_error: {list_mem_zero_res.is_error}")
            for content in list_mem_zero_res.content:
                print(f"[MCP-TEST] Invalid list_memory_regions zero error content: {content.text}")

            print("[MCP-TEST] Invoking invalid list_memory_regions(limit=-1) (expected failure)...")
            list_mem_neg_res = await session.call_tool("list_memory_regions", {"limit": -1})
            print(f"[MCP-TEST] invalid list_memory_regions neg is_error: {list_mem_neg_res.is_error}")
            for content in list_mem_neg_res.content:
                print(f"[MCP-TEST] Invalid list_memory_regions neg error content: {content.text}")

            print("[MCP-TEST] Invoking invalid list_memory_regions(start_address='0x1234garbage') (expected failure)...")
            list_mem_addr_res = await session.call_tool("list_memory_regions", {"start_address": "0x1234garbage"})
            print(f"[MCP-TEST] invalid list_memory_regions invalid address is_error: {list_mem_addr_res.is_error}")
            for content in list_mem_addr_res.content:
                print(f"[MCP-TEST] Invalid list_memory_regions invalid address error content: {content.text}")

            # 20. Cross-reference inspection get_xrefs verification (Phase 9E)
            print("[MCP-TEST] Invoking tool get_xrefs(address='RIP')...")
            get_xrefs_res = await session.call_tool("get_xrefs", {"address": "RIP"})
            print(f"[MCP-TEST] get_xrefs is_error: {get_xrefs_res.is_error}")
            for content in get_xrefs_res.content:
                print(f"[MCP-TEST] get_xrefs content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_xrefs(address='0x1234garbage') (expected failure)...")
            get_xrefs_invalid_res = await session.call_tool("get_xrefs", {"address": "0x1234garbage"})
            print(f"[MCP-TEST] invalid get_xrefs invalid address is_error: {get_xrefs_invalid_res.is_error}")
            for content in get_xrefs_invalid_res.content:
                print(f"[MCP-TEST] Invalid get_xrefs invalid address error content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_xrefs(address='') (expected failure)...")
            get_xrefs_empty_res = await session.call_tool("get_xrefs", {"address": ""})
            print(f"[MCP-TEST] invalid get_xrefs empty is_error: {get_xrefs_empty_res.is_error}")
            for content in get_xrefs_empty_res.content:
                print(f"[MCP-TEST] Invalid get_xrefs empty error content: {content.text}")

            # 21. Address context inspection get_address_info verification (Phase 9F)
            print("[MCP-TEST] Invoking tool get_address_info(address='RIP')...")
            get_addr_info_res = await session.call_tool("get_address_info", {"address": "RIP"})
            print(f"[MCP-TEST] get_address_info is_error: {get_addr_info_res.is_error}")
            for content in get_addr_info_res.content:
                print(f"[MCP-TEST] get_address_info content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_address_info(address='0x1234garbage') (expected failure)...")
            get_addr_info_invalid_res = await session.call_tool("get_address_info", {"address": "0x1234garbage"})
            print(f"[MCP-TEST] invalid get_address_info invalid address is_error: {get_addr_info_invalid_res.is_error}")
            for content in get_addr_info_invalid_res.content:
                print(f"[MCP-TEST] Invalid get_address_info invalid address error content: {content.text}")

            print("[MCP-TEST] Invoking invalid get_address_info(address='') (expected failure)...")
            get_addr_info_empty_res = await session.call_tool("get_address_info", {"address": ""})
            print(f"[MCP-TEST] invalid get_address_info empty is_error: {get_addr_info_empty_res.is_error}")
            for content in get_addr_info_empty_res.content:
                print(f"[MCP-TEST] Invalid get_address_info empty error content: {content.text}")

            # 23. Phase 10: get_call_stack
            print("[MCP-TEST] Invoking tool get_call_stack()...")
            call_stack_res = await session.call_tool("get_call_stack", {})
            print(f"[MCP-TEST] get_call_stack is_error: {call_stack_res.is_error}")
            for content in call_stack_res.content:
                print(f"[MCP-TEST] get_call_stack content: {content.text}")

            # 24. Phase 10: eval_expression
            print("[MCP-TEST] Invoking tool eval_expression(expression='rax + 0x20')...")
            eval_expr_res = await session.call_tool("eval_expression", {"expression": "rax + 0x20"})
            print(f"[MCP-TEST] eval_expression is_error: {eval_expr_res.is_error}")
            for content in eval_expr_res.content:
                print(f"[MCP-TEST] eval_expression content: {content.text}")

            print("[MCP-TEST] Invoking invalid eval_expression(expression='') (expected failure)...")
            eval_empty_res = await session.call_tool("eval_expression", {"expression": ""})
            print(f"[MCP-TEST] invalid eval_expression empty is_error: {eval_empty_res.is_error}")
            for content in eval_empty_res.content:
                print(f"[MCP-TEST] Invalid eval_expression empty error content: {content.text}")

            print("[MCP-TEST] Invoking invalid eval_expression(expression='invalid_symbol_xyz_123') (expected failure)...")
            eval_invalid_res = await session.call_tool("eval_expression", {"expression": "invalid_symbol_xyz_123"})
            print(f"[MCP-TEST] invalid eval_expression syntax is_error: {eval_invalid_res.is_error}")
            for content in eval_invalid_res.content:
                print(f"[MCP-TEST] Invalid eval_expression error content: {content.text}")

            # 25. Phase 11: find_pattern
            print("[MCP-TEST] Invoking tool find_pattern(pattern='4D 5A', max_matches=5)...")
            find_pat_res = await session.call_tool("find_pattern", {"pattern": "4D 5A", "max_matches": 5})
            print(f"[MCP-TEST] find_pattern is_error: {find_pat_res.is_error}")
            for content in find_pat_res.content:
                print(f"[MCP-TEST] find_pattern content: {content.text}")

            print("[MCP-TEST] Invoking invalid find_pattern(pattern='') (expected failure)...")
            find_empty_res = await session.call_tool("find_pattern", {"pattern": ""})
            print(f"[MCP-TEST] invalid find_pattern empty is_error: {find_empty_res.is_error}")
            for content in find_empty_res.content:
                print(f"[MCP-TEST] Invalid find_pattern empty error content: {content.text}")

            print("[MCP-TEST] Invoking invalid find_pattern(pattern='ZZ ZZ') (expected failure)...")
            find_invalid_res = await session.call_tool("find_pattern", {"pattern": "ZZ ZZ"})
            print(f"[MCP-TEST] invalid find_pattern syntax is_error: {find_invalid_res.is_error}")
            for content in find_invalid_res.content:
                print(f"[MCP-TEST] Invalid find_pattern error content: {content.text}")

            # 24. Call set_register tool
            orig_regs_data = json.loads(reg_result.content[0].text)
            orig_rax_str = orig_regs_data["rax"]
            print(f"[MCP-TEST] Invoking set_register(register='rax', value='0x1337BEEF')...")
            set_reg_res = await session.call_tool("set_register", {"register": "rax", "value": "0x1337BEEF"})
            print(f"[MCP-TEST] set_register is_error: {set_reg_res.is_error}")
            for content in set_reg_res.content:
                print(f"[MCP-TEST] set_register content: {content.text}")

            # Restore RAX
            restore_reg_res = await session.call_tool("set_register", {"register": "rax", "value": orig_rax_str})
            print(f"[MCP-TEST] restore set_register is_error: {restore_reg_res.is_error}")

            print("[MCP-TEST] Invoking invalid set_register(register='bad_reg_xyz', value='0x1') (expected failure)...")
            set_reg_invalid_res = await session.call_tool("set_register", {"register": "bad_reg_xyz", "value": "0x1"})
            print(f"[MCP-TEST] invalid set_register is_error: {set_reg_invalid_res.is_error}")

            # 25. Call write_memory tool
            orig_mem_rsp = json.loads(mem_rip_result.content[0].text)
            orig_rip_hex = orig_mem_rsp["hex"]
            # Read 8 bytes from RSP
            rsp_read_pre = await session.call_tool("read_memory", {"address": "RSP", "size": 8})
            rsp_pre_hex = json.loads(rsp_read_pre.content[0].text)["hex"]
            print(f"[MCP-TEST] Invoking write_memory(address='RSP', data='AA BB CC DD EE FF 00 11', verify=True)...")
            write_mem_res = await session.call_tool("write_memory", {"address": "RSP", "data": "AA BB CC DD EE FF 00 11", "verify": True})
            print(f"[MCP-TEST] write_memory is_error: {write_mem_res.is_error}")
            for content in write_mem_res.content:
                print(f"[MCP-TEST] write_memory content: {content.text}")

            # Restore memory at RSP
            restore_mem_res = await session.call_tool("write_memory", {"address": "RSP", "data": rsp_pre_hex, "verify": True})
            print(f"[MCP-TEST] restore write_memory is_error: {restore_mem_res.is_error}")

            print("[MCP-TEST] Invoking invalid write_memory(address='0x0', data='90') (expected failure)...")
            write_mem_invalid_res = await session.call_tool("write_memory", {"address": "0x0", "data": "90"})
            print(f"[MCP-TEST] invalid write_memory is_error: {write_mem_invalid_res.is_error}")

            # 26. Call enable_breakpoint tool (reproduce and verify set -> disable -> list confirms disabled -> enable -> list confirms enabled)
            cur_rip = json.loads(reg_result.content[0].text)["rip"]
            rip_int = int(cur_rip, 16)

            # Step A: set breakpoint
            bp_test = await session.call_tool("set_breakpoint", {"address": cur_rip})
            assert not bp_test.is_error, f"set_breakpoint failed: {bp_test.content}"

            # Step B: disable breakpoint
            en_bp_res = await session.call_tool("enable_breakpoint", {"address": cur_rip, "enabled": False})
            print(f"[MCP-TEST] enable_breakpoint is_error: {en_bp_res.is_error}")
            assert not en_bp_res.is_error, f"disable breakpoint failed: {en_bp_res.content}"
            assert json.loads(en_bp_res.content[0].text).get("enabled") is False

            # Step C: list confirms disabled
            list_bp_res = await session.call_tool("list_breakpoints", {})
            assert not list_bp_res.is_error, f"list_breakpoints failed: {list_bp_res.content}"
            bps = json.loads(list_bp_res.content[0].text)["breakpoints"]
            match_bp = next((b for b in bps if int(b["address"], 16) == rip_int), None)
            assert match_bp is not None, "Disabled breakpoint missing from list_breakpoints"
            assert match_bp["enabled"] is False, f"Expected breakpoint disabled in list, got: {match_bp}"

            # Step D: re-enable breakpoint (the exact scenario that previously failed with 'breakpoint not found')
            en_bp_re_res = await session.call_tool("enable_breakpoint", {"address": cur_rip, "enabled": True})
            assert not en_bp_re_res.is_error, f"re-enable breakpoint failed on disabled breakpoint: {en_bp_re_res.content}"
            assert json.loads(en_bp_re_res.content[0].text).get("enabled") is True

            # Step E: list confirms enabled
            list_bp_re_res = await session.call_tool("list_breakpoints", {})
            bps_re = json.loads(list_bp_re_res.content[0].text)["breakpoints"]
            match_re_bp = next((b for b in bps_re if int(b["address"], 16) == rip_int), None)
            assert match_re_bp is not None, "Re-enabled breakpoint missing from list_breakpoints"
            assert match_re_bp["enabled"] is True, f"Expected breakpoint enabled in list, got: {match_re_bp}"

            # Step F: delete while disabled test
            # Disable again, then verify delete_breakpoint can delete disabled breakpoint
            await session.call_tool("enable_breakpoint", {"address": cur_rip, "enabled": False})
            del_res = await session.call_tool("delete_breakpoint", {"address": cur_rip})
            assert not del_res.is_error, f"delete_breakpoint on disabled breakpoint failed: {del_res.content}"
            list_bp_del = await session.call_tool("list_breakpoints", {})
            bps_del = json.loads(list_bp_del.content[0].text)["breakpoints"]
            assert next((b for b in bps_del if int(b["address"], 16) == rip_int), None) is None, "Deleted breakpoint still present"

            # 27. Call set_comment and get_comment
            set_c_res = await session.call_tool("set_comment", {"address": cur_rip, "comment": "test_comment_123"})
            print(f"[MCP-TEST] set_comment is_error: {set_c_res.is_error}")
            get_c_res = await session.call_tool("get_comment", {"address": cur_rip})
            print(f"[MCP-TEST] get_comment is_error: {get_c_res.is_error}")
            await session.call_tool("set_comment", {"address": cur_rip, "comment": ""})

            # 28. Call set_label and get_label
            set_l_res = await session.call_tool("set_label", {"address": cur_rip, "label": "test_label_123"})
            print(f"[MCP-TEST] set_label is_error: {set_l_res.is_error}")
            get_l_res = await session.call_tool("get_label", {"address": cur_rip})
            print(f"[MCP-TEST] get_label is_error: {get_l_res.is_error}")
            await session.call_tool("set_label", {"address": cur_rip, "label": ""})

            # 29. Call set_bookmark and get_bookmark
            set_bm_res = await session.call_tool("set_bookmark", {"address": cur_rip, "bookmarked": True})
            print(f"[MCP-TEST] set_bookmark is_error: {set_bm_res.is_error}")
            get_bm_res = await session.call_tool("get_bookmark", {"address": cur_rip})
            print(f"[MCP-TEST] get_bookmark is_error: {get_bm_res.is_error}")
            await session.call_tool("set_bookmark", {"address": cur_rip, "bookmarked": False})

            # 30. Call get_function_boundary
            get_fn_res = await session.call_tool("get_function_boundary", {"address": cur_rip})
            print(f"[MCP-TEST] get_function_boundary is_error: {get_fn_res.is_error}")

            # 31. Call assemble
            assemble_res = await session.call_tool("assemble", {"instruction": "nop", "address": cur_rip, "write_to_memory": False})
            print(f"[MCP-TEST] assemble is_error: {assemble_res.is_error}")

            # 32. Call list_imports
            list_imp_res = await session.call_tool("list_imports", {"module": "kernel32.dll", "offset": 0, "limit": 5})
            print(f"[MCP-TEST] list_imports is_error: {list_imp_res.is_error}")

            # 33. Call list_exports
            list_exp_res = await session.call_tool("list_exports", {"module": "kernel32.dll", "offset": 0, "limit": 5})
            print(f"[MCP-TEST] list_exports is_error: {list_exp_res.is_error}")

            # 34. Call get_peb_info
            get_peb_res = await session.call_tool("get_peb_info", {})
            print(f"[MCP-TEST] get_peb_info is_error: {get_peb_res.is_error}")

            # 35. Call get_teb_info
            get_teb_res = await session.call_tool("get_teb_info", {})
            print(f"[MCP-TEST] get_teb_info is_error: {get_teb_res.is_error}")

            # 36. Call get_command_line
            get_cmd_res = await session.call_tool("get_command_line", {})
            print(f"[MCP-TEST] get_command_line is_error: {get_cmd_res.is_error}")

            # 37. Call get_seh_chain
            get_seh_res = await session.call_tool("get_seh_chain", {})
            print(f"[MCP-TEST] get_seh_chain is_error: {get_seh_res.is_error}")

            # 38. Call get_page_rights
            get_rights_res = await session.call_tool("get_page_rights", {"address": cur_rip})
            print(f"[MCP-TEST] get_page_rights is_error: {get_rights_res.is_error}")

            # 39. Call list_heaps
            list_heaps_res = await session.call_tool("list_heaps", {})
            print(f"[MCP-TEST] list_heaps is_error: {list_heaps_res.is_error}")

            # 40. Call list_handles
            list_handles_res = await session.call_tool("list_handles", {"offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_handles is_error: {list_handles_res.is_error}")

            # 41. Call get_handle_info
            get_handle_res = await session.call_tool("get_handle_info", {"handle": "0x4"})
            print(f"[MCP-TEST] get_handle_info is_error: {get_handle_res.is_error}")

            # 42. Call list_tcp_connections
            list_tcp_res = await session.call_tool("list_tcp_connections", {})
            print(f"[MCP-TEST] list_tcp_connections is_error: {list_tcp_res.is_error}")

            # 43. Call list_windows
            list_win_res = await session.call_tool("list_windows", {})
            print(f"[MCP-TEST] list_windows is_error: {list_win_res.is_error}")

            # 44. Call va_to_file_offset
            va_offset_res = await session.call_tool("va_to_file_offset", {"address": cur_rip})
            print(f"[MCP-TEST] va_to_file_offset is_error: {va_offset_res.is_error}")

            # 45. Call file_offset_to_va
            offset_va_res = await session.call_tool("file_offset_to_va", {"module": main_module_name, "offset": 0})
            print(f"[MCP-TEST] file_offset_to_va is_error: {offset_va_res.is_error}")

            # 46. Call list_relocations
            list_reloc_res = await session.call_tool("list_relocations", {"address": cur_rip, "size": 4096, "offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_relocations is_error: {list_reloc_res.is_error}")

            # 47. Call get_relocation
            get_reloc_res = await session.call_tool("get_relocation", {"address": cur_rip})
            print(f"[MCP-TEST] get_relocation is_error: {get_reloc_res.is_error}")

            # Read original byte for patch test
            read_rip_byte = json.loads((await session.call_tool("read_memory", {"address": cur_rip, "size": 1})).content[0].text)
            orig_b = read_rip_byte["hex"][:2]
            patch_b = "90" if orig_b.lower() != "90" else "cc"

            # 48. Call patch_memory
            patch_mem_res = await session.call_tool("patch_memory", {"address": cur_rip, "data": patch_b})
            print(f"[MCP-TEST] patch_memory is_error: {patch_mem_res.is_error}")

            # 49. Call list_patches
            list_patch_res = await session.call_tool("list_patches", {"offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_patches is_error: {list_patch_res.is_error}")

            # 50. Call get_patch
            get_patch_res = await session.call_tool("get_patch", {"address": cur_rip})
            print(f"[MCP-TEST] get_patch is_error: {get_patch_res.is_error}")

            # 51. Call restore_patch
            restore_patch_res = await session.call_tool("restore_patch", {"address": cur_rip})
            print(f"[MCP-TEST] restore_patch is_error: {restore_patch_res.is_error}")

            # 52. Call restore_patches_range (on empty/cleared range)
            restore_range_res = await session.call_tool("restore_patches_range", {"start_address": cur_rip, "end_address": cur_rip})
            print(f"[MCP-TEST] restore_patches_range is_error: {restore_range_res.is_error}")

            # 53. Call resolve_symbol
            resolve_sym_res = await session.call_tool("resolve_symbol", {"symbol": f"{main_module_name}:entry"})
            print(f"[MCP-TEST] resolve_symbol is_error: {resolve_sym_res.is_error}")

            # 54. Call list_symbols
            list_sym_res = await session.call_tool("list_symbols", {"module": main_module_name, "offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_symbols is_error: {list_sym_res.is_error}")

            # 55. Call get_symbol_status
            sym_stat_res = await session.call_tool("get_symbol_status", {"module": main_module_name})
            print(f"[MCP-TEST] get_symbol_status is_error: {sym_stat_res.is_error}")

            # 56. Call get_source_location
            src_loc_res = await session.call_tool("get_source_location", {"address": cur_rip})
            print(f"[MCP-TEST] get_source_location is_error: {src_loc_res.is_error}")

            # 57. Call find_source_address
            find_src_res = await session.call_tool("find_source_address", {"module": main_module_name, "source_file": "test.c", "line": 1})
            print(f"[MCP-TEST] find_source_address is_error: {find_src_res.is_error}")

            # 58. Call symbol_autocomplete
            auto_sym_res = await session.call_tool("symbol_autocomplete", {"prefix": "e", "max_results": 10})
            print(f"[MCP-TEST] symbol_autocomplete is_error: {auto_sym_res.is_error}")

            # 59. Call list_exceptions
            list_ex_res = await session.call_tool("list_exceptions", {"offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_exceptions is_error: {list_ex_res.is_error}")

            # 60. Call get_exception_info
            get_ex_res = await session.call_tool("get_exception_info", {"exception": "0xC0000005"})
            print(f"[MCP-TEST] get_exception_info is_error: {get_ex_res.is_error}")

            # 61. Call set_exception_breakpoint
            set_ex_bp_res = await session.call_tool("set_exception_breakpoint", {"code": "0xC0000005"})
            print(f"[MCP-TEST] set_exception_breakpoint is_error: {set_ex_bp_res.is_error}")

            # 62. Call enable_exception_breakpoint
            en_ex_bp_res = await session.call_tool("enable_exception_breakpoint", {"code": "0xC0000005", "enabled": True})
            print(f"[MCP-TEST] enable_exception_breakpoint is_error: {en_ex_bp_res.is_error}")

            # 63. Call delete_exception_breakpoint
            del_ex_bp_res = await session.call_tool("delete_exception_breakpoint", {"code": "0xC0000005"})
            print(f"[MCP-TEST] delete_exception_breakpoint is_error: {del_ex_bp_res.is_error}")

            # 64. Call get_last_exception
            get_last_ex_res = await session.call_tool("get_last_exception", {})
            print(f"[MCP-TEST] get_last_exception is_error: {get_last_ex_res.is_error}")

            # 65. Call get_trace_status
            get_tr_stat_res = await session.call_tool("get_trace_status", {"address": cur_rip})
            print(f"[MCP-TEST] get_trace_status is_error: {get_tr_stat_res.is_error}")

            # 66. Call get_trace_record
            get_tr_rec_res = await session.call_tool("get_trace_record", {"address": cur_rip})
            print(f"[MCP-TEST] get_trace_record is_error: {get_tr_rec_res.is_error}")

            # 67. Call set_trace_record_type
            set_tr_type_res = await session.call_tool("set_trace_record_type", {"address": cur_rip, "type": "none"})
            print(f"[MCP-TEST] set_trace_record_type is_error: {set_tr_type_res.is_error}")

            # 68. Call set_hardware_breakpoint
            set_hw_res = await session.call_tool("set_hardware_breakpoint", {"address": cur_rip, "type": "execute", "size": 1})
            print(f"[MCP-TEST] set_hardware_breakpoint is_error: {set_hw_res.is_error}")

            # 69. Call enable_hardware_breakpoint
            en_hw_res = await session.call_tool("enable_hardware_breakpoint", {"address": cur_rip, "enabled": False})
            print(f"[MCP-TEST] enable_hardware_breakpoint (disable) is_error: {en_hw_res.is_error}")
            en_hw2_res = await session.call_tool("enable_hardware_breakpoint", {"address": cur_rip, "enabled": True})
            print(f"[MCP-TEST] enable_hardware_breakpoint (enable) is_error: {en_hw2_res.is_error}")

            # 70. Call delete_hardware_breakpoint
            del_hw_res = await session.call_tool("delete_hardware_breakpoint", {"address": cur_rip})
            print(f"[MCP-TEST] delete_hardware_breakpoint is_error: {del_hw_res.is_error}")

            # 71. Call set_memory_breakpoint
            set_mem_res = await session.call_tool("set_memory_breakpoint", {"address": cur_rip, "type": "access"})
            print(f"[MCP-TEST] set_memory_breakpoint is_error: {set_mem_res.is_error}")

            # 72. Call enable_memory_breakpoint
            en_mem_res = await session.call_tool("enable_memory_breakpoint", {"address": cur_rip, "enabled": True})
            print(f"[MCP-TEST] enable_memory_breakpoint is_error: {en_mem_res.is_error}")

            # 73. Call delete_memory_breakpoint
            del_mem_res = await session.call_tool("delete_memory_breakpoint", {"address": cur_rip})
            print(f"[MCP-TEST] delete_memory_breakpoint is_error: {del_mem_res.is_error}")

            # 74. Call set_memory_range_breakpoint
            set_memr_res = await session.call_tool("set_memory_range_breakpoint", {"address": cur_rip, "size": 64, "type": "read"})
            print(f"[MCP-TEST] set_memory_range_breakpoint is_error: {set_memr_res.is_error}")

            # 75. Call delete_memory_breakpoint (range)
            del_memr_res = await session.call_tool("delete_memory_breakpoint", {"address": cur_rip})
            print(f"[MCP-TEST] delete_memory_breakpoint (range) is_error: {del_memr_res.is_error}")

            # 76. Call set_dll_breakpoint
            set_dll_res = await session.call_tool("set_dll_breakpoint", {"module": "winmm.dll", "type": "all"})
            print(f"[MCP-TEST] set_dll_breakpoint is_error: {set_dll_res.is_error}")

            # 77. Call enable_dll_breakpoint
            en_dll_res = await session.call_tool("enable_dll_breakpoint", {"module": "winmm.dll", "enabled": True})
            print(f"[MCP-TEST] enable_dll_breakpoint is_error: {en_dll_res.is_error}")

            # 78. Call delete_dll_breakpoint
            del_dll_res = await session.call_tool("delete_dll_breakpoint", {"module": "winmm.dll"})
            print(f"[MCP-TEST] delete_dll_breakpoint is_error: {del_dll_res.is_error}")

            # 79. Call get_breakpoint_details, configure_breakpoint, reset_breakpoint_hit_count
            await session.call_tool("set_breakpoint", {"address": cur_rip})
            get_bp_det_res = await session.call_tool("get_breakpoint_details", {"address": cur_rip, "type": "software"})
            print(f"[MCP-TEST] get_breakpoint_details is_error: {get_bp_det_res.is_error}")

            cfg_bp_res = await session.call_tool("configure_breakpoint", {"address": cur_rip, "type": "software", "silent": True})
            print(f"[MCP-TEST] configure_breakpoint is_error: {cfg_bp_res.is_error}")

            reset_bp_res = await session.call_tool("reset_breakpoint_hit_count", {"address": cur_rip})
            print(f"[MCP-TEST] reset_breakpoint_hit_count is_error: {reset_bp_res.is_error}")
            await session.call_tool("delete_breakpoint", {"address": cur_rip})

            # Phase 20: list_processes
            list_proc_res = await session.call_tool("list_processes", {"limit": 10})
            print(f"[MCP-TEST] list_processes is_error: {list_proc_res.is_error}")

            # Phase 20: get_debug_session_info
            sess_info_res = await session.call_tool("get_debug_session_info", {})
            print(f"[MCP-TEST] get_debug_session_info is_error: {sess_info_res.is_error}")

            # Phase 20: Thread control
            threads_data = json.loads(list_threads_res.content[0].text)
            curr_tid = threads_data.get("threads", [{}])[0].get("thread_id", 0)

            sus_t_res = await session.call_tool("suspend_thread", {"thread_id": curr_tid})
            print(f"[MCP-TEST] suspend_thread is_error: {sus_t_res.is_error}")

            res_t_res = await session.call_tool("resume_thread", {"thread_id": curr_tid})
            print(f"[MCP-TEST] resume_thread is_error: {res_t_res.is_error}")

            sus_all_res = await session.call_tool("suspend_all_threads", {})
            print(f"[MCP-TEST] suspend_all_threads is_error: {sus_all_res.is_error}")

            res_all_res = await session.call_tool("resume_all_threads", {})
            print(f"[MCP-TEST] resume_all_threads is_error: {res_all_res.is_error}")

            # Phase 20: Session lifecycle (detach, attach, stop, launch)
            cur_pid_val = json.loads(sess_info_res.content[0].text).get("pid", 0)
            orig_exe_path = json.loads(sess_info_res.content[0].text).get("main_module_path", "")

            detach_res = await session.call_tool("detach_process", {})
            print(f"[MCP-TEST] detach_process is_error: {detach_res.is_error}")
            await anyio.sleep(1.0)
            dismiss_x64dbg_dialogs()

            attach_res = await session.call_tool("attach_process", {"pid": cur_pid_val})
            print(f"[MCP-TEST] attach_process is_error: {attach_res.is_error}")
            await anyio.sleep(1.0)
            dismiss_x64dbg_dialogs()

            stop_res = await session.call_tool("stop_debuggee", {})
            print(f"[MCP-TEST] stop_debuggee is_error: {stop_res.is_error}")
            await anyio.sleep(1.0)
            dismiss_x64dbg_dialogs()

            status_no_dbg = await session.call_tool("get_bridge_status", {})
            assert not status_no_dbg.is_error, f"get_bridge_status failed after stop_debuggee: {status_no_dbg.content}"
            data_no_dbg = json.loads(status_no_dbg.content[0].text)
            print(f"[MCP-TEST] get_bridge_status (no_debuggee): {data_no_dbg}")
            assert data_no_dbg.get("connected") is True
            assert data_no_dbg.get("state") == "no_debuggee"
            assert data_no_dbg.get("is_debugging") is False
            assert data_no_dbg.get("is_running") is False
            assert data_no_dbg.get("stop_address") is None

            launch_res = await session.call_tool("launch_debuggee", {"path": orig_exe_path})
            print(f"[MCP-TEST] launch_debuggee is_error: {launch_res.is_error}")
            await anyio.sleep(1.0)
            dismiss_x64dbg_dialogs()

            # Phase 21: PE metadata, strings, and dumps
            temp_dir = tempfile.gettempdir()
            temp_mem_dump = os.path.join(temp_dir, "x64dbg_mcp_reg_mem_dump.bin")
            temp_mod_dump = os.path.join(temp_dir, "x64dbg_mcp_reg_mod_dump.bin")
            temp_minidump = os.path.join(temp_dir, "x64dbg_mcp_reg_minidump.dmp")

            get_pe_res = await session.call_tool("get_pe_headers", {})
            print(f"[MCP-TEST] get_pe_headers is_error: {get_pe_res.is_error}")

            list_pe_dd_res = await session.call_tool("list_pe_data_directories", {})
            print(f"[MCP-TEST] list_pe_data_directories is_error: {list_pe_dd_res.is_error}")

            list_tls_res = await session.call_tool("list_tls_callbacks", {})
            print(f"[MCP-TEST] list_tls_callbacks is_error: {list_tls_res.is_error}")

            get_rf_res = await session.call_tool("get_runtime_function", {"address": cur_rip})
            print(f"[MCP-TEST] get_runtime_function is_error: {get_rf_res.is_error}")

            list_rf_res = await session.call_tool("list_runtime_functions", {"offset": 0, "limit": 10})
            print(f"[MCP-TEST] list_runtime_functions is_error: {list_rf_res.is_error}")

            get_party_res = await session.call_tool("get_module_party", {})
            print(f"[MCP-TEST] get_module_party is_error: {get_party_res.is_error}")

            find_str_res = await session.call_tool("find_strings", {"start_address": cur_rip, "size": 1024, "encoding": "ascii"})
            print(f"[MCP-TEST] find_strings is_error: {find_str_res.is_error}")

            dump_mem_res = await session.call_tool("dump_memory", {"address": cur_rip, "size": 64, "output_path": temp_mem_dump, "verify": True})
            print(f"[MCP-TEST] dump_memory is_error: {dump_mem_res.is_error}")

            dump_mod_res = await session.call_tool("dump_module", {"output_path": temp_mod_dump, "verify": True})
            print(f"[MCP-TEST] dump_module is_error: {dump_mod_res.is_error}")

            create_dmp_res = await session.call_tool("create_minidump", {"output_path": temp_minidump, "confirm": True})
            print(f"[MCP-TEST] create_minidump is_error: {create_dmp_res.is_error}")

            # Clean up regression artifacts
            for tf in [temp_mem_dump, temp_mod_dump, temp_minidump]:
                if os.path.exists(tf):
                    try:
                        os.remove(tf)
                    except Exception:
                        pass

            # Phase 22: Runtime Intelligence, Scripting & Debug Database
            get_sec_res = await session.call_tool("get_security_mitigations", {})
            print(f"[MCP-TEST] get_security_mitigations is_error: {get_sec_res.is_error}")

            # Query active thread ID in current process
            th_list_check = await session.call_tool("list_threads", {})
            try:
                th_data = json.loads(th_list_check.content[0].text)
                cur_test_tid = th_data.get("active_thread_id") or curr_tid
            except Exception:
                cur_test_tid = curr_tid

            get_th_cs_res = await session.call_tool("get_thread_call_stack", {"thread_id": cur_test_tid})
            print(f"[MCP-TEST] get_thread_call_stack is_error: {get_th_cs_res.is_error}")

            list_structs_res = await session.call_tool("list_structs", {"limit": 20})
            print(f"[MCP-TEST] list_structs is_error: {list_structs_res.is_error}")

            list_const_res = await session.call_tool("list_constants", {"limit": 20})
            print(f"[MCP-TEST] list_constants is_error: {list_const_res.is_error}")

            list_err_res = await session.call_tool("list_error_codes", {"limit": 20})
            print(f"[MCP-TEST] list_error_codes is_error: {list_err_res.is_error}")

            fmt_str_res = await session.call_tool("format_inline_string", {"format": "Target RIP is {p:rip}"})
            print(f"[MCP-TEST] format_inline_string is_error: {fmt_str_res.is_error}")

            temp_script = os.path.abspath("temp_reg_script.txt")
            with open(temp_script, "w") as f:
                f.write('// Temporary script\nlog "Phase 22 regression script execution"\n')
            run_script_res = await session.call_tool("run_script", {"path": temp_script})
            print(f"[MCP-TEST] run_script is_error: {run_script_res.is_error}")
            if os.path.exists(temp_script):
                try:
                    os.remove(temp_script)
                except Exception:
                    pass

            get_loop_init_res = await session.call_tool("get_loop", {"address": cur_rip})
            print(f"[MCP-TEST] get_loop (initial) is_error: {get_loop_init_res.is_error}")

            loop_end_addr = hex(int(cur_rip, 16) + 0x10)
            add_loop_res = await session.call_tool("add_loop", {"start": cur_rip, "end": loop_end_addr})
            print(f"[MCP-TEST] add_loop is_error: {add_loop_res.is_error}")

            get_loop_res = await session.call_tool("get_loop", {"address": cur_rip})
            print(f"[MCP-TEST] get_loop (added) is_error: {get_loop_res.is_error}")

            list_loops_res = await session.call_tool("list_loops", {})
            print(f"[MCP-TEST] list_loops is_error: {list_loops_res.is_error}")

            del_loop_res = await session.call_tool("delete_loop", {"address": cur_rip})
            print(f"[MCP-TEST] delete_loop is_error: {del_loop_res.is_error}")

            clear_loops_res = await session.call_tool("clear_loops", {})
            print(f"[MCP-TEST] clear_loops is_error: {clear_loops_res.is_error}")

            get_arg_init_res = await session.call_tool("get_argument", {"address": cur_rip})
            print(f"[MCP-TEST] get_argument (initial) is_error: {get_arg_init_res.is_error}")

            arg_end_addr = hex(int(cur_rip, 16) + 0x20)
            add_arg_res = await session.call_tool("add_argument", {"start": cur_rip, "end": arg_end_addr})
            print(f"[MCP-TEST] add_argument is_error: {add_arg_res.is_error}")

            get_arg_res = await session.call_tool("get_argument", {"address": cur_rip})
            print(f"[MCP-TEST] get_argument (added) is_error: {get_arg_res.is_error}")

            list_args_res = await session.call_tool("list_arguments", {})
            print(f"[MCP-TEST] list_arguments is_error: {list_args_res.is_error}")

            del_arg_res = await session.call_tool("delete_argument", {"address": cur_rip})
            print(f"[MCP-TEST] delete_argument is_error: {del_arg_res.is_error}")

            clear_args_res = await session.call_tool("clear_arguments", {})
            print(f"[MCP-TEST] clear_arguments is_error: {clear_args_res.is_error}")

            # Phase 23: Advanced Execution & Remote Memory Control
            alloc_res = await session.call_tool("allocate_memory", {"size": 4096})
            print(f"[MCP-TEST] allocate_memory is_error: {alloc_res.is_error}")
            alloc_data = json.loads(alloc_res.content[0].text) if not alloc_res.is_error else {}
            alloc_addr = alloc_data.get("address", "0x0")

            fill_res = await session.call_tool("fill_memory", {"address": alloc_addr, "value": 0x42, "size": 64})
            print(f"[MCP-TEST] fill_memory is_error: {fill_res.is_error}")

            dst_addr = hex(int(alloc_addr, 16) + 128)
            copy_res = await session.call_tool("copy_memory", {"destination": dst_addr, "source": alloc_addr, "size": 32})
            print(f"[MCP-TEST] copy_memory is_error: {copy_res.is_error}")

            rights_res = await session.call_tool("set_page_rights", {"address": alloc_addr, "rights": "ReadOnly"})
            print(f"[MCP-TEST] set_page_rights is_error: {rights_res.is_error}")

            fn_t_start = hex(int(alloc_addr, 16) + 0x100)
            fn_t_end = hex(int(alloc_addr, 16) + 0x200)
            add_fn_res = await session.call_tool("add_function", {"start": fn_t_start, "end": fn_t_end, "manual": True})
            print(f"[MCP-TEST] add_function is_error: {add_fn_res.is_error}")

            del_fn_res = await session.call_tool("delete_function", {"address": fn_t_start})
            print(f"[MCP-TEST] delete_function is_error: {del_fn_res.is_error}")

            free_res = await session.call_tool("free_memory", {"address": alloc_addr})
            print(f"[MCP-TEST] free_memory is_error: {free_res.is_error}")

            skip_res = await session.call_tool("skip_instruction", {"count": 1})
            print(f"[MCP-TEST] skip_instruction is_error: {skip_res.is_error}")
            skip_data = json.loads(skip_res.content[0].text) if not skip_res.is_error else {}
            if "old_rip" in skip_data:
                await session.call_tool("set_register", {"register": "rip", "value": skip_data["old_rip"]})

            run_to_cur_res = await session.call_tool("run_to_address", {"address": cur_rip, "timeout_ms": 3000})
            print(f"[MCP-TEST] run_to_address (cur rip) is_error: {run_to_cur_res.is_error}")

            step_exc_res = await session.call_tool("step_over_pass_exceptions", {"timeout_ms": 5000})
            print(f"[MCP-TEST] step_over_pass_exceptions is_error: {step_exc_res.is_error}")

            step_u_res = await session.call_tool("step_user", {"timeout_ms": 5000})
            print(f"[MCP-TEST] step_user is_error: {step_u_res.is_error}")

            step_s_res = await session.call_tool("step_system", {"timeout_ms": 1000})
            print(f"[MCP-TEST] step_system is_error: {step_s_res.is_error}")

            step_out_exc_res = await session.call_tool("step_out_pass_exceptions", {"timeout_ms": 1000})
            print(f"[MCP-TEST] step_out_pass_exceptions is_error: {step_out_exc_res.is_error}")

            rtu_res = await session.call_tool("run_to_user_code", {"timeout_ms": 5000})
            print(f"[MCP-TEST] run_to_user_code is_error: {rtu_res.is_error}")

            # Phase 24: Analysis Engine & Function Intelligence
            anal_code_res = await session.call_tool("analyze_code", {"address": cur_rip})
            print(f"[MCP-TEST] analyze_code is_error: {anal_code_res.is_error}")

            anal_cf_res = await session.call_tool("analyze_control_flow", {"address": cur_rip, "use_exception_directory": False})
            print(f"[MCP-TEST] analyze_control_flow is_error: {anal_cf_res.is_error}")

            anal_ex_res = await session.call_tool("analyze_exception_directory", {"address": cur_rip})
            print(f"[MCP-TEST] analyze_exception_directory is_error: {anal_ex_res.is_error}")

            anal_rec_res = await session.call_tool("analyze_recursive", {"entry": cur_rip})
            print(f"[MCP-TEST] analyze_recursive is_error: {anal_rec_res.is_error}")

            anal_adv_res = await session.call_tool("analyze_advanced", {"address": cur_rip})
            print(f"[MCP-TEST] analyze_advanced is_error: {anal_adv_res.is_error}")

            anal_xrefs_res = await session.call_tool("analyze_xrefs", {"address": cur_rip})
            print(f"[MCP-TEST] analyze_xrefs is_error: {anal_xrefs_res.is_error}")

            anal_nukem_res = await session.call_tool("analyze_nukem", {"address": cur_rip})
            print(f"[MCP-TEST] analyze_nukem is_error: {anal_nukem_res.is_error}")

            list_fn_res = await session.call_tool("list_functions", {"offset": 0, "limit": 20})
            print(f"[MCP-TEST] list_functions is_error: {list_fn_res.is_error}")

            get_fn_info_res = await session.call_tool("get_function_info", {"address": cur_rip})
            print(f"[MCP-TEST] get_function_info is_error: {get_fn_info_res.is_error}")

            get_cfg_res = await session.call_tool("get_control_flow_graph", {"address": cur_rip, "max_blocks": 32})
            print(f"[MCP-TEST] get_control_flow_graph is_error: {get_cfg_res.is_error}")

            get_callers_res = await session.call_tool("get_function_callers", {"address": cur_rip})
            print(f"[MCP-TEST] get_function_callers is_error: {get_callers_res.is_error}")

            get_callees_res = await session.call_tool("get_function_callees", {"address": cur_rip, "max_callees": 20})
            print(f"[MCP-TEST] get_function_callees is_error: {get_callees_res.is_error}")

            # Phase 25: Debugger Event Queue & Asynchronous Event Delivery
            ev_stat_res = await session.call_tool("get_event_status", {})
            print(f"[MCP-TEST] get_event_status is_error: {ev_stat_res.is_error}")

            get_ev_res = await session.call_tool("get_debug_events", {"limit": 10})
            print(f"[MCP-TEST] get_debug_events is_error: {get_ev_res.is_error}")

            wait_ev_res = await session.call_tool("wait_for_debug_event", {"timeout_ms": 200})
            print(f"[MCP-TEST] wait_for_debug_event is_error: {wait_ev_res.is_error}")

            clear_ev_res = await session.call_tool("clear_debug_events", {})
            print(f"[MCP-TEST] clear_debug_events is_error: {clear_ev_res.is_error}")

            # Phase 26: User Database Persistence & Complete Annotation Management
            save_db_res = await session.call_tool("save_database", {"compression": True})
            print(f"[MCP-TEST] save_database is_error: {save_db_res.is_error}")

            load_db_res = await session.call_tool("load_database", {})
            print(f"[MCP-TEST] load_database is_error: {load_db_res.is_error}")

            list_cmt_res = await session.call_tool("list_comments", {"page": 1, "page_size": 20})
            print(f"[MCP-TEST] list_comments is_error: {list_cmt_res.is_error}")

            del_cmt_res = await session.call_tool("delete_comment", {"address": cur_rip})
            print(f"[MCP-TEST] delete_comment is_error: {del_cmt_res.is_error}")

            clear_cmt_res = await session.call_tool("clear_comments", {"confirm": True})
            print(f"[MCP-TEST] clear_comments is_error: {clear_cmt_res.is_error}")

            list_lbl_res = await session.call_tool("list_labels", {"page": 1, "page_size": 20})
            print(f"[MCP-TEST] list_labels is_error: {list_lbl_res.is_error}")

            del_lbl_res = await session.call_tool("delete_label", {"address": cur_rip})
            print(f"[MCP-TEST] delete_label is_error: {del_lbl_res.is_error}")

            clear_lbl_res = await session.call_tool("clear_labels", {"confirm": True})
            print(f"[MCP-TEST] clear_labels is_error: {clear_lbl_res.is_error}")

            list_bm_res = await session.call_tool("list_bookmarks", {"page": 1, "page_size": 20})
            print(f"[MCP-TEST] list_bookmarks is_error: {list_bm_res.is_error}")

            del_bm_res = await session.call_tool("delete_bookmark", {"address": cur_rip})
            print(f"[MCP-TEST] delete_bookmark is_error: {del_bm_res.is_error}")

            clear_bm_res = await session.call_tool("clear_bookmarks", {"confirm": True})
            print(f"[MCP-TEST] clear_bookmarks is_error: {clear_bm_res.is_error}")

            clear_fn_res = await session.call_tool("clear_functions", {"confirm": True})
            print(f"[MCP-TEST] clear_functions is_error: {clear_fn_res.is_error}")

            set_cmd_res = await session.call_tool("set_command_line", {"command_line": "test_cmdline"})
            print(f"[MCP-TEST] set_command_line is_error: {set_cmd_res.is_error}")

            # Phase 27: Rich Tracing & Conditional Execution Control
            set_tr_log_res = await session.call_tool("set_trace_log", {"text": "Trace step at {cip}", "condition": "1"})
            print(f"[MCP-TEST] set_trace_log is_error: {set_tr_log_res.is_error}")

            clear_tr_log_res = await session.call_tool("set_trace_log", {"text": ""})
            print(f"[MCP-TEST] clear set_trace_log is_error: {clear_tr_log_res.is_error}")

            set_tr_cmd_res = await session.call_tool("set_trace_command", {"command": "dputs \"test\"", "condition": "1"})
            print(f"[MCP-TEST] set_trace_command is_error: {set_tr_cmd_res.is_error}")

            clear_tr_cmd_res = await session.call_tool("set_trace_command", {"command": ""})
            print(f"[MCP-TEST] clear set_trace_command is_error: {clear_tr_cmd_res.is_error}")

            set_tr_filt_res = await session.call_tool("set_trace_step_filter", {"filter": "user"})
            print(f"[MCP-TEST] set_trace_step_filter is_error: {set_tr_filt_res.is_error}")

            reset_tr_filt_res = await session.call_tool("set_trace_step_filter", {"filter": "none"})
            print(f"[MCP-TEST] reset set_trace_step_filter is_error: {reset_tr_filt_res.is_error}")

            temp_log_file = os.path.join(tempfile.gettempdir(), f"mcp_trace_log_{os.getpid()}.txt")
            set_tr_logfile_res = await session.call_tool("set_trace_log_file", {"path": temp_log_file})
            print(f"[MCP-TEST] set_trace_log_file is_error: {set_tr_logfile_res.is_error}")

            clear_tr_logfile_res = await session.call_tool("set_trace_log_file", {"path": ""})
            print(f"[MCP-TEST] clear set_trace_log_file is_error: {clear_tr_logfile_res.is_error}")

            temp_rec_file = os.path.join(tempfile.gettempdir(), f"mcp_trace_rec_{os.getpid()}.trace")
            start_rec_res = await session.call_tool("start_trace_recording", {"path": temp_rec_file})
            print(f"[MCP-TEST] start_trace_recording is_error: {start_rec_res.is_error}")

            stop_rec_res = await session.call_tool("stop_trace_recording", {})
            print(f"[MCP-TEST] stop_trace_recording is_error: {stop_rec_res.is_error}")
            try:
                if os.path.exists(temp_rec_file):
                    os.remove(temp_rec_file)
            except Exception:
                pass

            tr_into_cnd_res = await session.call_tool("trace_into_conditional", {"condition": "1", "max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_into_conditional is_error: {tr_into_cnd_res.is_error}")

            tr_over_cnd_res = await session.call_tool("trace_over_conditional", {"condition": "1", "max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_over_conditional is_error: {tr_over_cnd_res.is_error}")

            tr_into_beyond_res = await session.call_tool("trace_into_beyond_trace_record", {"max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_into_beyond_trace_record is_error: {tr_into_beyond_res.is_error}")

            tr_over_beyond_res = await session.call_tool("trace_over_beyond_trace_record", {"max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_over_beyond_trace_record is_error: {tr_over_beyond_res.is_error}")

            tr_into_rec_res = await session.call_tool("trace_into_trace_record", {"max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_into_trace_record is_error: {tr_into_rec_res.is_error}")

            tr_over_rec_res = await session.call_tool("trace_over_trace_record", {"max_steps": 2, "timeout_ms": 3000})
            print(f"[MCP-TEST] trace_over_trace_record is_error: {tr_over_rec_res.is_error}")

            run_to_party_res = await session.call_tool("run_to_party", {"party": "user", "timeout_ms": 3000})
            print(f"[MCP-TEST] run_to_party is_error: {run_to_party_res.is_error}")

            # Phase 28: Watch Expressions & Runtime Value Tracking (10 tools)
            add_w_res = await session.call_tool("add_watch", {"expression": "rip", "type": "uint"})
            print(f"[MCP-TEST] add_watch is_error: {add_w_res.is_error}")
            add_w_data = json.loads(add_w_res.content[0].text) if not add_w_res.is_error else {}
            w_id = add_w_data.get("id", 1)

            list_w_res = await session.call_tool("list_watches", {})
            print(f"[MCP-TEST] list_watches is_error: {list_w_res.is_error}")

            get_w_res = await session.call_tool("get_watch", {"id": w_id, "evaluate": True})
            print(f"[MCP-TEST] get_watch is_error: {get_w_res.is_error}")

            ren_w_res = await session.call_tool("rename_watch", {"id": w_id, "name": "RipWatcher"})
            print(f"[MCP-TEST] rename_watch is_error: {ren_w_res.is_error}")

            set_w_type_res = await session.call_tool("set_watch_type", {"id": w_id, "type": "int"})
            print(f"[MCP-TEST] set_watch_type is_error: {set_w_type_res.is_error}")

            mod_w_res = await session.call_tool("modify_watch", {"id": w_id, "expression": "rip + 4", "type": "uint"})
            print(f"[MCP-TEST] modify_watch is_error: {mod_w_res.is_error}")

            set_wd_res = await session.call_tool("set_watchdog", {"id": w_id, "mode": "changed"})
            print(f"[MCP-TEST] set_watchdog is_error: {set_wd_res.is_error}")

            check_wd_res = await session.call_tool("check_watchdogs", {})
            print(f"[MCP-TEST] check_watchdogs is_error: {check_wd_res.is_error}")

            del_w_res = await session.call_tool("delete_watch", {"id": w_id})
            print(f"[MCP-TEST] delete_watch is_error: {del_w_res.is_error}")

            clear_w_res = await session.call_tool("clear_watches", {"confirm": True})
            print(f"[MCP-TEST] clear_watches is_error: {clear_w_res.is_error}")

            clear_db_res = await session.call_tool("clear_database", {"confirm": True})
            print(f"[MCP-TEST] clear_database is_error: {clear_db_res.is_error}")

            # Phase 29: Trace File Inspection & Analysis (12 tools)
            temp_trace_path = os.path.join(tempfile.gettempdir(), f"mcp_phase29_test_{os.getpid()}.trace64")
            with open(temp_trace_path, "wb") as tf_out:
                hdr_json = json.dumps({
                    "ver": 1,
                    "arch": "x64",
                    "compression": "",
                    "hashAlgorithm": "murmurhash",
                    "hash": "0x12345678",
                    "path": r"C:\test.exe"
                }).encode("utf-8")
                tf_out.write(b"TRAC" + struct.pack("<I", len(hdr_json)) + hdr_json)
                # Instruction 0: checkpoint
                b0 = struct.pack("<BBB", 172, 0, 0x83)
                tid_bytes = struct.pack("<I", 1234)
                op0 = b"\x48\x89\xc0"  # mov rax, rax
                c_pos = b"\x00" * 172
                r_words = [0] * 172
                r_words[0] = 0x42  # rax
                r_words[16] = 0x140001000  # rip
                r_bytes = struct.pack("<172Q", *r_words)
                tf_out.write(b"\x00" + b0 + tid_bytes + op0 + c_pos + r_bytes)
                # Instruction 1: delta with memory access and call
                b1 = struct.pack("<BBB", 1, 1, 0x05)
                op1 = b"\xe8\x00\x10\x00\x00"  # call rel32 (5 bytes)
                c_pos1 = bytes([16])  # rip changed
                r_bytes1 = struct.pack("<1Q", 0x140001003)
                m_flag = b"\x00"
                m_addr = struct.pack("<Q", 0x7FFE0000)
                m_old = struct.pack("<Q", 0x1111)
                m_new = struct.pack("<Q", 0x2222)
                tf_out.write(b"\x00" + b1 + op1 + c_pos1 + r_bytes1 + m_flag + m_addr + m_old + m_new)

            open_trace_res = await session.call_tool("open_trace_file", {"path": temp_trace_path})
            print(f"[MCP-TEST] open_trace_file is_error: {open_trace_res.is_error}")
            open_trace_data = json.loads(open_trace_res.content[0].text) if not open_trace_res.is_error else {}
            tid = open_trace_data.get("trace_id", "trace_1")

            get_tr_info_res = await session.call_tool("get_trace_info", {"trace_id": tid})
            print(f"[MCP-TEST] get_trace_info is_error: {get_tr_info_res.is_error}")

            get_tr_inst_res = await session.call_tool("get_trace_instruction", {"trace_id": tid, "index": 0})
            print(f"[MCP-TEST] get_trace_instruction is_error: {get_tr_inst_res.is_error}")

            get_tr_insts_res = await session.call_tool("get_trace_instructions", {"trace_id": tid, "start_index": 0, "count": 10})
            print(f"[MCP-TEST] get_trace_instructions is_error: {get_tr_insts_res.is_error}")

            get_tr_regs_res = await session.call_tool("get_trace_registers", {"trace_id": tid, "index": 0})
            print(f"[MCP-TEST] get_trace_registers is_error: {get_tr_regs_res.is_error}")

            get_tr_mem_res = await session.call_tool("get_trace_memory_accesses", {"trace_id": tid, "index": 1})
            print(f"[MCP-TEST] get_trace_memory_accesses is_error: {get_tr_mem_res.is_error}")

            read_tr_mem_res = await session.call_tool("read_trace_memory", {"trace_id": tid, "address": "0x7FFE0000", "size": 8, "index": 1})
            print(f"[MCP-TEST] read_trace_memory is_error: {read_tr_mem_res.is_error}")

            search_tr_addr_res = await session.call_tool("search_trace_address", {"trace_id": tid, "address": "0x140001000", "end_address": "0x140001010"})
            print(f"[MCP-TEST] search_trace_address is_error: {search_tr_addr_res.is_error}")

            search_tr_mem_res = await session.call_tool("search_trace_memory", {"trace_id": tid, "pattern": "11 11 ??"})
            print(f"[MCP-TEST] search_trace_memory is_error: {search_tr_mem_res.is_error}")

            get_tr_refs_res = await session.call_tool("get_trace_references", {"trace_id": tid, "start_address": "0x7FFE0000", "end_address": "0x7FFE0010"})
            print(f"[MCP-TEST] get_trace_references is_error: {get_tr_refs_res.is_error}")

            find_tr_calls_res = await session.call_tool("find_trace_calls", {"trace_id": tid})
            print(f"[MCP-TEST] find_trace_calls is_error: {find_tr_calls_res.is_error}")

            close_tr_res = await session.call_tool("close_trace_file", {"trace_id": tid})
            print(f"[MCP-TEST] close_trace_file is_error: {close_tr_res.is_error}")

            try:
                if os.path.exists(temp_trace_path):
                    os.remove(temp_trace_path)
            except Exception:
                pass

            restart_res = await session.call_tool("restart_debuggee", {})
            print(f"[MCP-TEST] restart_debuggee is_error: {restart_res.is_error}")

            # Settle post-restart
            for _ in range(30):
                st_res = await session.call_tool("get_debugger_state", {})
                st_data = json.loads(st_res.content[0].text)
                if st_data.get("is_debugging") and not st_data.get("is_running"):
                    break
                await anyio.sleep(0.1)

            # Phase 30 positive tests: Data Encoding Maps & Structured Types
            print("[MCP-TEST] Testing Phase 30 tools...")
            reg_st = await session.call_tool("get_registers", {})
            st_rip = json.loads(reg_st.content[0].text).get("rip", cur_rip)
            dt_res = await session.call_tool("get_data_type", {"address": st_rip, "size": 1})
            print(f"[MCP-TEST] get_data_type is_error: {dt_res.is_error}")
            ds_res = await session.call_tool("get_data_size", {"address": st_rip, "code_size": 16})
            print(f"[MCP-TEST] get_data_size is_error: {ds_res.is_error}")
            dm_res = await session.call_tool("get_data_map", {"address": st_rip, "max_bytes": 64})
            print(f"[MCP-TEST] get_data_map is_error: {dm_res.is_error}")
            sdt_res = await session.call_tool("set_data_type", {"address": st_rip, "size": 1, "type": "byte"})
            print(f"[MCP-TEST] set_data_type is_error: {sdt_res.is_error}")
            cdtr_res = await session.call_tool("clear_data_type_range", {"start_address": st_rip, "end_address": st_rip})
            print(f"[MCP-TEST] clear_data_type_range is_error: {cdtr_res.is_error}")
            cdts_res = await session.call_tool("clear_data_type_segment", {"address": st_rip})
            print(f"[MCP-TEST] clear_data_type_segment is_error: {cdts_res.is_error}")

            ast_res = await session.call_tool("add_struct_type", {"name": "PHASE30_TEST_STRUCT"})
            print(f"[MCP-TEST] add_struct_type is_error: {ast_res.is_error}")
            asm_res = await session.call_tool("add_struct_member", {"parent_type": "PHASE30_TEST_STRUCT", "member_type": "int", "name": "field_a"})
            print(f"[MCP-TEST] add_struct_member is_error: {asm_res.is_error}")
            at_res = await session.call_tool("add_type", {"name": "PHASE30_INT_ALIAS", "type": "int"})
            print(f"[MCP-TEST] add_type is_error: {at_res.is_error}")
            au_res = await session.call_tool("add_union_type", {"name": "PHASE30_TEST_UNION"})
            print(f"[MCP-TEST] add_union_type is_error: {au_res.is_error}")
            it_res = await session.call_tool("inspect_type", {"type_name": "PHASE30_TEST_STRUCT"})
            print(f"[MCP-TEST] inspect_type is_error: {it_res.is_error}")
            gts_res = await session.call_tool("get_type_size", {"type_name": "PHASE30_TEST_STRUCT"})
            print(f"[MCP-TEST] get_type_size is_error: {gts_res.is_error}")
            lst_res = await session.call_tool("list_struct_types", {"filter": "PHASE30_TEST_STRUCT", "limit": 10})
            print(f"[MCP-TEST] list_struct_types is_error: {lst_res.is_error}")
            rt_res = await session.call_tool("remove_type", {"name": "PHASE30_TEST_UNION"})
            print(f"[MCP-TEST] remove_type is_error: {rt_res.is_error}")
            ct_res = await session.call_tool("clear_types", {"confirm": True, "owner": "cmd"})
            print(f"[MCP-TEST] clear_types is_error: {ct_res.is_error}")

            # Phase 31 positive tests: Breakpoint References, Thread Metadata & Configuration
            print("[MCP-TEST] Testing Phase 31 tools...")
            list_bp_refs_res = await session.call_tool("list_breakpoint_references", {})
            print(f"[MCP-TEST] list_breakpoint_references is_error: {list_bp_refs_res.is_error}")

            await session.call_tool("set_breakpoint", {"address": st_rip})
            get_bp_ref_res = await session.call_tool("get_breakpoint_reference", {"address": st_rip})
            print(f"[MCP-TEST] get_breakpoint_reference is_error: {get_bp_ref_res.is_error}")

            set_bp_ref_res = await session.call_tool("set_breakpoint_reference_fields", {
                "address": st_rip,
                "name": "REGRESSION_P31_BP",
                "breakcondition": "rax == 0",
                "logtext": "Hit",
                "hitcount": 10
            })
            print(f"[MCP-TEST] set_breakpoint_reference_fields is_error: {set_bp_ref_res.is_error}")
            await session.call_tool("delete_breakpoint", {"address": st_rip})

            # Refresh active thread ID after restart
            th_list_fresh = await session.call_tool("list_threads", {})
            threads_fresh = json.loads(th_list_fresh.content[0].text).get("threads", [])
            active_th = next((t for t in threads_fresh if t.get("active")), threads_fresh[0] if threads_fresh else {})
            curr_tid = active_th.get("thread_id", curr_tid)

            get_th_name_res = await session.call_tool("get_thread_name", {"thread_id": curr_tid})
            print(f"[MCP-TEST] get_thread_name is_error: {get_th_name_res.is_error}")

            set_th_name_res = await session.call_tool("set_thread_name", {"thread_id": curr_tid, "name": "WorkerThreadP31"})
            print(f"[MCP-TEST] set_thread_name is_error: {set_th_name_res.is_error}")

            set_th_name_clear = await session.call_tool("set_thread_name", {"thread_id": curr_tid, "name": ""})
            print(f"[MCP-TEST] set_thread_name (clear) is_error: {set_th_name_clear.is_error}")

            get_th_prio_res = await session.call_tool("get_thread_priority", {"thread_id": curr_tid})
            print(f"[MCP-TEST] get_thread_priority is_error: {get_th_prio_res.is_error}")

            set_th_prio_res = await session.call_tool("set_thread_priority", {"thread_id": curr_tid, "priority": "Normal"})
            print(f"[MCP-TEST] set_thread_priority is_error: {set_th_prio_res.is_error}")

            set_mod_party_res = await session.call_tool("set_module_party", {"party": "user"})
            print(f"[MCP-TEST] set_module_party is_error: {set_mod_party_res.is_error}")

            is_cp_res = await session.call_tool("is_code_page", {"address": st_rip, "skip_cache": False})
            print(f"[MCP-TEST] is_code_page is_error: {is_cp_res.is_error}")

            get_mn_brief_res = await session.call_tool("get_mnemonic_brief", {"mnemonic": "mov"})
            print(f"[MCP-TEST] get_mnemonic_brief is_error: {get_mn_brief_res.is_error}")

            get_dbg_init_res = await session.call_tool("get_debuggee_init_script", {})
            print(f"[MCP-TEST] get_debuggee_init_script is_error: {get_dbg_init_res.is_error}")

            set_dbg_init_res = await session.call_tool("set_debuggee_init_script", {"script_path": ""})
            print(f"[MCP-TEST] set_debuggee_init_script is_error: {set_dbg_init_res.is_error}")

            get_jit_res = await session.call_tool("get_jit_info", {})
            print(f"[MCP-TEST] get_jit_info is_error: {get_jit_res.is_error}")

            # Negative tests for new tools
            alloc_inv = await session.call_tool("allocate_memory", {"size": 0})
            print(f"[MCP-TEST] invalid allocate_memory is_error: {alloc_inv.is_error}")
            free_inv = await session.call_tool("free_memory", {"address": ""})
            print(f"[MCP-TEST] invalid free_memory is_error: {free_inv.is_error}")
            fill_inv = await session.call_tool("fill_memory", {"address": "", "value": 0, "size": 10})
            print(f"[MCP-TEST] invalid fill_memory is_error: {fill_inv.is_error}")
            copy_inv = await session.call_tool("copy_memory", {"destination": "", "source": "0x1000", "size": 10})
            print(f"[MCP-TEST] invalid copy_memory is_error: {copy_inv.is_error}")
            rights_inv = await session.call_tool("set_page_rights", {"address": "", "rights": "ReadOnly"})
            print(f"[MCP-TEST] invalid set_page_rights is_error: {rights_inv.is_error}")
            skip_inv = await session.call_tool("skip_instruction", {"count": 0})
            print(f"[MCP-TEST] invalid skip_instruction is_error: {skip_inv.is_error}")
            run_to_inv = await session.call_tool("run_to_address", {"address": ""})
            print(f"[MCP-TEST] invalid run_to_address is_error: {run_to_inv.is_error}")
            step_exc_inv = await session.call_tool("step_over_pass_exceptions", {"timeout_ms": 0})
            print(f"[MCP-TEST] invalid step_over_pass_exceptions is_error: {step_exc_inv.is_error}")
            step_out_exc_inv = await session.call_tool("step_out_pass_exceptions", {"timeout_ms": 0})
            print(f"[MCP-TEST] invalid step_out_pass_exceptions is_error: {step_out_exc_inv.is_error}")
            step_u_inv = await session.call_tool("step_user", {"timeout_ms": 0})
            print(f"[MCP-TEST] invalid step_user is_error: {step_u_inv.is_error}")
            step_s_inv = await session.call_tool("step_system", {"timeout_ms": 0})
            print(f"[MCP-TEST] invalid step_system is_error: {step_s_inv.is_error}")
            rtu_inv = await session.call_tool("run_to_user_code", {"timeout_ms": 0})
            print(f"[MCP-TEST] invalid run_to_user_code is_error: {rtu_inv.is_error}")
            console_inv = await session.call_tool("send_console_input", {"text": 123})
            print(f"[MCP-TEST] invalid send_console_input is_error: {console_inv.is_error}")

            # Item 3: read_console_output negative tests
            rco_inv1 = await session.call_tool("read_console_output", {"max_lines": 0})
            print(f"[MCP-TEST] invalid read_console_output (max_lines=0) is_error: {rco_inv1.is_error}")
            assert rco_inv1.is_error, "read_console_output should fail with max_lines=0"

            rco_inv2 = await session.call_tool("read_console_output", {"max_lines": 1001})
            print(f"[MCP-TEST] invalid read_console_output (max_lines=1001) is_error: {rco_inv2.is_error}")
            assert rco_inv2.is_error, "read_console_output should fail with max_lines=1001"

            rco_inv3 = await session.call_tool("read_console_output", {"pid": -1})
            print(f"[MCP-TEST] invalid read_console_output (negative pid) is_error: {rco_inv3.is_error}")
            assert rco_inv3.is_error, "read_console_output should fail with negative pid"

            rco_inv4 = await session.call_tool("read_console_output", {"visible_only": "invalid"})
            print(f"[MCP-TEST] invalid read_console_output (non-bool visible_only) is_error: {rco_inv4.is_error}")
            assert rco_inv4.is_error, "read_console_output should fail with non-bool visible_only"

            # Item 3: read_console_output positive test
            rco_res = await session.call_tool("read_console_output", {"max_lines": 20})
            print(f"[MCP-TEST] read_console_output is_error: {rco_res.is_error}, content: {rco_res.content}")
            if not rco_res.is_error:
                rco_data = json.loads(rco_res.content[0].text)
                assert rco_data.get("success") is True
                assert "pid" in rco_data and rco_data["pid"] > 0
                assert "cursor_position" in rco_data
                assert "buffer_size" in rco_data
                assert "window_rect" in rco_data
                assert "lines" in rco_data and isinstance(rco_data["lines"], list)
                assert "text" in rco_data and isinstance(rco_data["text"], str)
                print(f"[MCP-TEST] read_console_output lines: {len(rco_data['lines'])}, text: {rco_data['text'][:100]!r}")

                rco_vis = await session.call_tool("read_console_output", {"visible_only": True})
                assert not rco_vis.is_error
                rco_emp = await session.call_tool("read_console_output", {"include_empty": True})
                assert not rco_emp.is_error
            else:
                rco_err = json.loads(rco_res.content[0].text) if rco_res.content else {}
                print(f"[MCP-TEST] read_console_output returned expected error: {rco_err}")
                assert "error" in rco_err

            pe_hdr_inv = await session.call_tool("get_pe_headers", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid get_pe_headers is_error: {pe_hdr_inv.is_error}")
            pe_dd_inv = await session.call_tool("list_pe_data_directories", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid list_pe_data_directories is_error: {pe_dd_inv.is_error}")
            tls_inv = await session.call_tool("list_tls_callbacks", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid list_tls_callbacks is_error: {tls_inv.is_error}")
            rf_inv = await session.call_tool("get_runtime_function", {"address": "0x1000"})
            print(f"[MCP-TEST] invalid get_runtime_function is_error: {rf_inv.is_error}")
            lrf_inv = await session.call_tool("list_runtime_functions", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid list_runtime_functions is_error: {lrf_inv.is_error}")
            party_inv = await session.call_tool("get_module_party", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid get_module_party is_error: {party_inv.is_error}")
            str_inv = await session.call_tool("find_strings", {"start_address": cur_rip, "size": 0})
            print(f"[MCP-TEST] invalid find_strings is_error: {str_inv.is_error}")
            dump_mem_inv = await session.call_tool("dump_memory", {"address": "0x0", "size": 64, "output_path": temp_mem_dump})
            print(f"[MCP-TEST] invalid dump_memory is_error: {dump_mem_inv.is_error}")
            dump_mod_inv = await session.call_tool("dump_module", {"module": "nonexistent_fake_xyz.dll", "output_path": temp_mod_dump})
            print(f"[MCP-TEST] invalid dump_module is_error: {dump_mod_inv.is_error}")
            minidump_inv = await session.call_tool("create_minidump", {"output_path": temp_minidump, "confirm": False})
            print(f"[MCP-TEST] invalid create_minidump (no confirm) is_error: {minidump_inv.is_error}")
            kill_neg_res = await session.call_tool("kill_thread", {"thread_id": curr_tid, "confirm": False})
            print(f"[MCP-TEST] invalid kill_thread (no confirm) is_error: {kill_neg_res.is_error}")
            sus_inv_res = await session.call_tool("suspend_thread", {"thread_id": 99999999})
            print(f"[MCP-TEST] invalid suspend_thread is_error: {sus_inv_res.is_error}")
            res_inv_res = await session.call_tool("resume_thread", {"thread_id": 99999999})
            print(f"[MCP-TEST] invalid resume_thread is_error: {res_inv_res.is_error}")
            att_inv_res = await session.call_tool("attach_process", {"pid": 0})
            print(f"[MCP-TEST] invalid attach_process (pid 0) is_error: {att_inv_res.is_error}")
            launch_inv_res = await session.call_tool("launch_debuggee", {"path": r"C:\fake_nonexistent_xyz.exe"})
            print(f"[MCP-TEST] invalid launch_debuggee is_error: {launch_inv_res.is_error}")
            hw_inv = await session.call_tool("set_hardware_breakpoint", {"address": cur_rip, "size": 3})
            print(f"[MCP-TEST] invalid set_hardware_breakpoint is_error: {hw_inv.is_error}")
            del_hw_inv = await session.call_tool("delete_hardware_breakpoint", {"address": "0x12345"})
            print(f"[MCP-TEST] invalid delete_hardware_breakpoint is_error: {del_hw_inv.is_error}")
            memr_inv = await session.call_tool("set_memory_range_breakpoint", {"address": cur_rip, "size": 0})
            print(f"[MCP-TEST] invalid set_memory_range_breakpoint is_error: {memr_inv.is_error}")
            del_dll_inv = await session.call_tool("delete_dll_breakpoint", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid delete_dll_breakpoint is_error: {del_dll_inv.is_error}")
            bp_det_inv = await session.call_tool("get_breakpoint_details", {})
            print(f"[MCP-TEST] invalid get_breakpoint_details is_error: {bp_det_inv.is_error}")
            en_bp_invalid = await session.call_tool("enable_breakpoint", {"address": "0x12345678"})
            print(f"[MCP-TEST] invalid enable_breakpoint is_error: {en_bp_invalid.is_error}")
            asm_invalid = await session.call_tool("assemble", {"instruction": "invalid_instruction_zzz", "address": cur_rip})
            print(f"[MCP-TEST] invalid assemble is_error: {asm_invalid.is_error}")
            imp_invalid = await session.call_tool("list_imports", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid list_imports is_error: {imp_invalid.is_error}")
            exp_invalid = await session.call_tool("list_exports", {"module": "nonexistent_fake_xyz.dll"})
            print(f"[MCP-TEST] invalid list_exports is_error: {exp_invalid.is_error}")
            teb_invalid = await session.call_tool("get_teb_info", {"thread_id": 9999999})
            print(f"[MCP-TEST] invalid get_teb_info is_error: {teb_invalid.is_error}")
            rights_invalid = await session.call_tool("get_page_rights", {"address": ""})
            print(f"[MCP-TEST] invalid get_page_rights is_error: {rights_invalid.is_error}")
            handles_invalid = await session.call_tool("list_handles", {"offset": -1})
            print(f"[MCP-TEST] invalid list_handles is_error: {handles_invalid.is_error}")
            hinfo_invalid = await session.call_tool("get_handle_info", {"handle": ""})
            print(f"[MCP-TEST] invalid get_handle_info is_error: {hinfo_invalid.is_error}")
            patch_invalid = await session.call_tool("patch_memory", {"address": cur_rip, "data": "ZZ"})
            print(f"[MCP-TEST] invalid patch_memory is_error: {patch_invalid.is_error}")
            restore_range_invalid = await session.call_tool("restore_patches_range", {"start_address": "0x1000", "end_address": "0x500"})
            print(f"[MCP-TEST] invalid restore_patches_range is_error: {restore_range_invalid.is_error}")
            va_offset_invalid = await session.call_tool("va_to_file_offset", {"address": ""})
            print(f"[MCP-TEST] invalid va_to_file_offset is_error: {va_offset_invalid.is_error}")
            offset_va_invalid = await session.call_tool("file_offset_to_va", {"module": "nonexistent_fake_xyz.dll", "offset": 0})
            print(f"[MCP-TEST] invalid file_offset_to_va is_error: {offset_va_invalid.is_error}")
            res_sym_invalid = await session.call_tool("resolve_symbol", {"symbol": ""})
            print(f"[MCP-TEST] invalid resolve_symbol is_error: {res_sym_invalid.is_error}")
            list_sym_invalid = await session.call_tool("list_symbols", {"module": "nonexistent_module_xyz.dll"})
            print(f"[MCP-TEST] invalid list_symbols is_error: {list_sym_invalid.is_error}")
            sym_stat_invalid = await session.call_tool("get_symbol_status", {"module": "nonexistent_module_xyz.dll"})
            print(f"[MCP-TEST] invalid get_symbol_status is_error: {sym_stat_invalid.is_error}")
            src_loc_invalid = await session.call_tool("get_source_location", {"address": ""})
            print(f"[MCP-TEST] invalid get_source_location is_error: {src_loc_invalid.is_error}")
            find_src_invalid = await session.call_tool("find_source_address", {"module": main_module_name, "source_file": "main.cpp", "line": 0})
            print(f"[MCP-TEST] invalid find_source_address is_error: {find_src_invalid.is_error}")
            list_ex_invalid = await session.call_tool("list_exceptions", {"offset": -1})
            print(f"[MCP-TEST] invalid list_exceptions is_error: {list_ex_invalid.is_error}")
            ex_info_invalid = await session.call_tool("get_exception_info", {"exception": ""})
            print(f"[MCP-TEST] invalid get_exception_info is_error: {ex_info_invalid.is_error}")
            set_ex_bp_invalid = await session.call_tool("set_exception_breakpoint", {"code": "0xC0000005", "chance": "invalid_chance"})
            print(f"[MCP-TEST] invalid set_exception_breakpoint is_error: {set_ex_bp_invalid.is_error}")
            del_ex_bp_invalid = await session.call_tool("delete_exception_breakpoint", {"code": "0xDEADBEEF"})
            print(f"[MCP-TEST] invalid delete_exception_breakpoint is_error: {del_ex_bp_invalid.is_error}")
            tr_rec_invalid = await session.call_tool("get_trace_record", {"address": ""})
            print(f"[MCP-TEST] invalid get_trace_record is_error: {tr_rec_invalid.is_error}")
            set_tr_type_invalid = await session.call_tool("set_trace_record_type", {"address": cur_rip, "type": "invalid_type"})
            print(f"[MCP-TEST] invalid set_trace_record_type is_error: {set_tr_type_invalid.is_error}")

            # Phase 22 negative tests
            th_cs_inv = await session.call_tool("get_thread_call_stack", {"thread_id": 99999999})
            print(f"[MCP-TEST] invalid get_thread_call_stack is_error: {th_cs_inv.is_error}")
            script_inv = await session.call_tool("run_script", {"path": r"C:\fake_xyz_dir\nonexistent_script.txt"})
            print(f"[MCP-TEST] invalid run_script is_error: {script_inv.is_error}")
            add_loop_inv = await session.call_tool("add_loop", {"start": "0x2000", "end": "0x1000"})
            print(f"[MCP-TEST] invalid add_loop is_error: {add_loop_inv.is_error}")
            del_loop_inv = await session.call_tool("delete_loop", {"address": "0x12345"})
            print(f"[MCP-TEST] invalid delete_loop is_error: {del_loop_inv.is_error}")
            add_arg_inv = await session.call_tool("add_argument", {"start": "0x2000", "end": "0x1000"})
            print(f"[MCP-TEST] invalid add_argument is_error: {add_arg_inv.is_error}")
            del_arg_inv = await session.call_tool("delete_argument", {"address": "0x12345"})
            print(f"[MCP-TEST] invalid delete_argument is_error: {del_arg_inv.is_error}")

            # Phase 24 negative tests
            anal_code_inv = await session.call_tool("analyze_code", {"address": ""})
            print(f"[MCP-TEST] invalid analyze_code is_error: {anal_code_inv.is_error}")
            anal_cf_inv = await session.call_tool("analyze_control_flow", {"address": "0x0"})
            print(f"[MCP-TEST] invalid analyze_control_flow is_error: {anal_cf_inv.is_error}")
            anal_ex_inv = await session.call_tool("analyze_exception_directory", {"address": ""})
            print(f"[MCP-TEST] invalid analyze_exception_directory is_error: {anal_ex_inv.is_error}")
            anal_rec_inv = await session.call_tool("analyze_recursive", {"entry": ""})
            print(f"[MCP-TEST] invalid analyze_recursive is_error: {anal_rec_inv.is_error}")
            anal_adv_inv = await session.call_tool("analyze_advanced", {"address": ""})
            print(f"[MCP-TEST] invalid analyze_advanced is_error: {anal_adv_inv.is_error}")
            anal_xrefs_inv = await session.call_tool("analyze_xrefs", {"address": ""})
            print(f"[MCP-TEST] invalid analyze_xrefs is_error: {anal_xrefs_inv.is_error}")
            anal_nukem_inv = await session.call_tool("analyze_nukem", {"address": ""})
            print(f"[MCP-TEST] invalid analyze_nukem is_error: {anal_nukem_inv.is_error}")
            list_fn_inv = await session.call_tool("list_functions", {"offset": -1})
            print(f"[MCP-TEST] invalid list_functions is_error: {list_fn_inv.is_error}")
            get_fn_info_inv = await session.call_tool("get_function_info", {"address": ""})
            print(f"[MCP-TEST] invalid get_function_info is_error: {get_fn_info_inv.is_error}")
            get_cfg_inv = await session.call_tool("get_control_flow_graph", {"address": ""})
            print(f"[MCP-TEST] invalid get_control_flow_graph is_error: {get_cfg_inv.is_error}")
            get_callers_inv = await session.call_tool("get_function_callers", {"address": ""})
            print(f"[MCP-TEST] invalid get_function_callers is_error: {get_callers_inv.is_error}")
            get_callees_inv = await session.call_tool("get_function_callees", {"address": ""})
            print(f"[MCP-TEST] invalid get_function_callees is_error: {get_callees_inv.is_error}")

            # Phase 25 negative tests
            get_ev_inv = await session.call_tool("get_debug_events", {"limit": 0})
            print(f"[MCP-TEST] invalid get_debug_events is_error: {get_ev_inv.is_error}")
            wait_ev_inv = await session.call_tool("wait_for_debug_event", {"timeout_ms": -1})
            print(f"[MCP-TEST] invalid wait_for_debug_event is_error: {wait_ev_inv.is_error}")

            # Phase 26 negative tests
            clear_db_inv = await session.call_tool("clear_database", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_database (no confirm) is_error: {clear_db_inv.is_error}")
            clear_cmt_inv = await session.call_tool("clear_comments", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_comments (no confirm) is_error: {clear_cmt_inv.is_error}")
            clear_lbl_inv = await session.call_tool("clear_labels", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_labels (no confirm) is_error: {clear_lbl_inv.is_error}")
            clear_bm_inv = await session.call_tool("clear_bookmarks", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_bookmarks (no confirm) is_error: {clear_bm_inv.is_error}")
            clear_fn_inv = await session.call_tool("clear_functions", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_functions (no confirm) is_error: {clear_fn_inv.is_error}")
            add_fn_inv = await session.call_tool("add_function", {"start": "0x2000", "end": "0x1000"})
            print(f"[MCP-TEST] invalid add_function (start > end) is_error: {add_fn_inv.is_error}")
            del_fn_inv = await session.call_tool("delete_function", {"address": ""})
            print(f"[MCP-TEST] invalid delete_function is_error: {del_fn_inv.is_error}")

            # Phase 27 negative tests
            tr_into_inv = await session.call_tool("trace_into_conditional", {"condition": ""})
            print(f"[MCP-TEST] invalid trace_into_conditional is_error: {tr_into_inv.is_error}")
            tr_over_inv = await session.call_tool("trace_over_conditional", {"condition": ""})
            print(f"[MCP-TEST] invalid trace_over_conditional is_error: {tr_over_inv.is_error}")
            rtp_inv = await session.call_tool("run_to_party", {"party": "invalid_xyz"})
            print(f"[MCP-TEST] invalid run_to_party is_error: {rtp_inv.is_error}")
            tr_filt_inv = await session.call_tool("set_trace_step_filter", {"filter": "invalid_filter"})
            print(f"[MCP-TEST] invalid set_trace_step_filter is_error: {tr_filt_inv.is_error}")
            start_rec_inv = await session.call_tool("start_trace_recording", {"path": ""})
            print(f"[MCP-TEST] invalid start_trace_recording is_error: {start_rec_inv.is_error}")

            # Phase 28 negative tests
            add_w_inv = await session.call_tool("add_watch", {"expression": ""})
            print(f"[MCP-TEST] invalid add_watch is_error: {add_w_inv.is_error}")
            get_w_inv = await session.call_tool("get_watch", {"id": 9999999})
            print(f"[MCP-TEST] invalid get_watch is_error: {get_w_inv.is_error}")
            mod_w_inv = await session.call_tool("modify_watch", {"id": 9999999, "expression": "rip"})
            print(f"[MCP-TEST] invalid modify_watch is_error: {mod_w_inv.is_error}")
            ren_w_inv = await session.call_tool("rename_watch", {"id": 9999999, "name": "bad"})
            print(f"[MCP-TEST] invalid rename_watch is_error: {ren_w_inv.is_error}")
            set_w_type_inv = await session.call_tool("set_watch_type", {"id": 9999999, "type": "uint"})
            print(f"[MCP-TEST] invalid set_watch_type is_error: {set_w_type_inv.is_error}")
            del_w_inv = await session.call_tool("delete_watch", {"id": 9999999})
            print(f"[MCP-TEST] invalid delete_watch is_error: {del_w_inv.is_error}")
            clear_w_inv = await session.call_tool("clear_watches", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_watches (no confirm) is_error: {clear_w_inv.is_error}")
            set_wd_inv = await session.call_tool("set_watchdog", {"id": 9999999, "mode": "changed"})
            print(f"[MCP-TEST] invalid set_watchdog is_error: {set_wd_inv.is_error}")

            # Phase 29 negative tests
            open_tr_inv = await session.call_tool("open_trace_file", {"path": r"C:\nonexistent_trace_12345.trace64"})
            print(f"[MCP-TEST] invalid open_trace_file is_error: {open_tr_inv.is_error}")
            get_tr_info_inv = await session.call_tool("get_trace_info", {"trace_id": "nonexistent_trace_id"})
            print(f"[MCP-TEST] invalid get_trace_info is_error: {get_tr_info_inv.is_error}")
            get_tr_inst_inv = await session.call_tool("get_trace_instruction", {"trace_id": "nonexistent_trace_id", "index": 0})
            print(f"[MCP-TEST] invalid get_trace_instruction is_error: {get_tr_inst_inv.is_error}")
            get_tr_insts_inv = await session.call_tool("get_trace_instructions", {"trace_id": "nonexistent_trace_id", "start_index": -1})
            print(f"[MCP-TEST] invalid get_trace_instructions is_error: {get_tr_insts_inv.is_error}")
            get_tr_regs_inv = await session.call_tool("get_trace_registers", {"trace_id": "nonexistent_trace_id", "index": 0})
            print(f"[MCP-TEST] invalid get_trace_registers is_error: {get_tr_regs_inv.is_error}")
            get_tr_mem_inv = await session.call_tool("get_trace_memory_accesses", {"trace_id": "nonexistent_trace_id", "index": 0})
            print(f"[MCP-TEST] invalid get_trace_memory_accesses is_error: {get_tr_mem_inv.is_error}")
            read_tr_mem_inv = await session.call_tool("read_trace_memory", {"trace_id": "nonexistent_trace_id", "address": 0, "size": 0, "index": 0})
            print(f"[MCP-TEST] invalid read_trace_memory is_error: {read_tr_mem_inv.is_error}")
            search_tr_addr_inv = await session.call_tool("search_trace_address", {"trace_id": "nonexistent_trace_id", "address": -1})
            print(f"[MCP-TEST] invalid search_trace_address is_error: {search_tr_addr_inv.is_error}")
            search_tr_mem_inv = await session.call_tool("search_trace_memory", {"trace_id": "nonexistent_trace_id", "pattern": ""})
            print(f"[MCP-TEST] invalid search_trace_memory is_error: {search_tr_mem_inv.is_error}")
            get_tr_refs_inv = await session.call_tool("get_trace_references", {"trace_id": "nonexistent_trace_id", "start_address": -1})
            print(f"[MCP-TEST] invalid get_trace_references is_error: {get_tr_refs_inv.is_error}")
            find_tr_calls_inv = await session.call_tool("find_trace_calls", {"trace_id": "nonexistent_trace_id"})
            print(f"[MCP-TEST] invalid find_trace_calls is_error: {find_tr_calls_inv.is_error}")

            # Phase 30 negative tests
            dt_inv = await session.call_tool("get_data_type", {"address": ""})
            print(f"[MCP-TEST] invalid get_data_type is_error: {dt_inv.is_error}")
            ds_inv = await session.call_tool("get_data_size", {"address": "", "code_size": 0})
            print(f"[MCP-TEST] invalid get_data_size is_error: {ds_inv.is_error}")
            dm_inv = await session.call_tool("get_data_map", {"address": "", "max_bytes": 5000})
            print(f"[MCP-TEST] invalid get_data_map is_error: {dm_inv.is_error}")
            sdt_inv = await session.call_tool("set_data_type", {"address": "", "size": 0})
            print(f"[MCP-TEST] invalid set_data_type is_error: {sdt_inv.is_error}")
            cdtr_inv = await session.call_tool("clear_data_type_range", {"start_address": "0x2000", "end_address": "0x1000"})
            print(f"[MCP-TEST] invalid clear_data_type_range is_error: {cdtr_inv.is_error}")
            cdts_inv = await session.call_tool("clear_data_type_segment", {"address": ""})
            print(f"[MCP-TEST] invalid clear_data_type_segment is_error: {cdts_inv.is_error}")
            it_inv = await session.call_tool("inspect_type", {"type_name": ""})
            print(f"[MCP-TEST] invalid inspect_type is_error: {it_inv.is_error}")
            gts_inv = await session.call_tool("get_type_size", {"type_name": ""})
            print(f"[MCP-TEST] invalid get_type_size is_error: {gts_inv.is_error}")
            lst_inv = await session.call_tool("list_struct_types", {"offset": -1})
            print(f"[MCP-TEST] invalid list_struct_types is_error: {lst_inv.is_error}")
            at_inv = await session.call_tool("add_type", {"name": "", "type": ""})
            print(f"[MCP-TEST] invalid add_type is_error: {at_inv.is_error}")
            ast_inv = await session.call_tool("add_struct_type", {"name": "inv@lid!"})
            print(f"[MCP-TEST] invalid add_struct_type is_error: {ast_inv.is_error}")
            au_inv = await session.call_tool("add_union_type", {"name": ""})
            print(f"[MCP-TEST] invalid add_union_type is_error: {au_inv.is_error}")
            asm_inv = await session.call_tool("add_struct_member", {"parent_type": "", "member_type": "", "name": ""})
            print(f"[MCP-TEST] invalid add_struct_member is_error: {asm_inv.is_error}")
            rt_inv = await session.call_tool("remove_type", {"name": ""})
            print(f"[MCP-TEST] invalid remove_type is_error: {rt_inv.is_error}")
            ct_inv = await session.call_tool("clear_types", {"confirm": False})
            print(f"[MCP-TEST] invalid clear_types is_error: {ct_inv.is_error}")

            # Phase 31 negative tests
            set_bp_ref_inv = await session.call_tool("set_breakpoint_reference_fields", {"address": cur_rip, "enabled": True})
            print(f"[MCP-TEST] invalid set_breakpoint_reference_fields (enabled) is_error: {set_bp_ref_inv.is_error}")
            get_th_name_inv = await session.call_tool("get_thread_name", {"thread_id": 0})
            print(f"[MCP-TEST] invalid get_thread_name is_error: {get_th_name_inv.is_error}")
            set_th_name_inv = await session.call_tool("set_thread_name", {"thread_id": -1, "name": "bad"})
            print(f"[MCP-TEST] invalid set_thread_name is_error: {set_th_name_inv.is_error}")
            set_th_prio_inv = await session.call_tool("set_thread_priority", {"thread_id": -1, "priority": "Normal"})
            print(f"[MCP-TEST] invalid set_thread_priority is_error: {set_th_prio_inv.is_error}")
            get_th_prio_inv = await session.call_tool("get_thread_priority", {"thread_id": -1})
            print(f"[MCP-TEST] invalid get_thread_priority is_error: {get_th_prio_inv.is_error}")
            set_mod_party_inv = await session.call_tool("set_module_party", {"party": "invalid_party_xyz"})
            print(f"[MCP-TEST] invalid set_module_party is_error: {set_mod_party_inv.is_error}")
            is_cp_inv = await session.call_tool("is_code_page", {"address": ""})
            print(f"[MCP-TEST] invalid is_code_page is_error: {is_cp_inv.is_error}")
            get_mn_brief_inv = await session.call_tool("get_mnemonic_brief", {"mnemonic": ""})
            print(f"[MCP-TEST] invalid get_mnemonic_brief is_error: {get_mn_brief_inv.is_error}")
            set_jit_inv = await session.call_tool("set_jit", {"confirm": False})
            print(f"[MCP-TEST] invalid set_jit (no confirm) is_error: {set_jit_inv.is_error}")
            set_jit_auto_inv = await session.call_tool("set_jit_auto", {"confirm": False, "enabled": True})
            print(f"[MCP-TEST] invalid set_jit_auto (no confirm) is_error: {set_jit_auto_inv.is_error}")


            # Check positive test assertions
            if (state_result.is_error or reg_result.is_error or mem_rip_result.is_error
                    or mem_base_result.is_error or disasm_result.is_error
                    or list_initial.is_error or set_bp_res.is_error
                    or list_after_set.is_error or del_bp_res.is_error
                    or list_after_del.is_error or step_res.is_error
                    or resume_res.is_error or pause_res.is_error
                    or step_over_res.is_error or step_out_res.is_error
                    or list_threads_res.is_error or switch_active_res.is_error
                    or list_modules_res.is_error or list_sec_res.is_error
                    or mem_reg_res.is_error or list_mem_res.is_error
                    or get_xrefs_res.is_error
                    or get_addr_info_res.is_error
                    or call_stack_res.is_error
                    or eval_expr_res.is_error
                    or find_pat_res.is_error
                    or set_reg_res.is_error
                    or restore_reg_res.is_error
                    or write_mem_res.is_error
                    or restore_mem_res.is_error
                    or en_bp_res.is_error
                    or en_bp_re_res.is_error
                    or set_c_res.is_error
                    or get_c_res.is_error
                    or set_l_res.is_error
                    or get_l_res.is_error
                    or set_bm_res.is_error
                    or get_bm_res.is_error
                    or get_fn_res.is_error
                    or assemble_res.is_error
                    or list_imp_res.is_error
                    or list_exp_res.is_error
                    or get_peb_res.is_error
                    or get_teb_res.is_error
                    or get_cmd_res.is_error
                    or get_seh_res.is_error
                    or get_rights_res.is_error
                    or list_heaps_res.is_error
                    or list_handles_res.is_error
                    or get_handle_res.is_error
                    or list_tcp_res.is_error
                    or list_win_res.is_error
                    or va_offset_res.is_error
                    or offset_va_res.is_error
                    or list_reloc_res.is_error
                    or get_reloc_res.is_error
                    or patch_mem_res.is_error
                    or list_patch_res.is_error
                    or get_patch_res.is_error
                    or restore_patch_res.is_error
                    or restore_range_res.is_error
                    or resolve_sym_res.is_error
                    or list_sym_res.is_error
                    or sym_stat_res.is_error
                    or src_loc_res.is_error
                    or find_src_res.is_error
                    or auto_sym_res.is_error
                    or list_ex_res.is_error
                    or get_ex_res.is_error
                    or set_ex_bp_res.is_error
                    or en_ex_bp_res.is_error
                    or del_ex_bp_res.is_error
                    or get_last_ex_res.is_error
                    or get_tr_stat_res.is_error
                    or get_tr_rec_res.is_error
                    or set_tr_type_res.is_error
                    or set_hw_res.is_error
                    or en_hw_res.is_error
                    or en_hw2_res.is_error
                    or del_hw_res.is_error
                    or set_mem_res.is_error
                    or en_mem_res.is_error
                    or del_mem_res.is_error
                    or set_memr_res.is_error
                    or del_memr_res.is_error
                    or set_dll_res.is_error
                    or en_dll_res.is_error
                    or del_dll_res.is_error
                    or get_bp_det_res.is_error
                    or cfg_bp_res.is_error
                    or reset_bp_res.is_error
                    or list_proc_res.is_error
                    or sess_info_res.is_error
                    or sus_t_res.is_error
                    or res_t_res.is_error
                    or sus_all_res.is_error
                    or res_all_res.is_error
                    or detach_res.is_error
                    or attach_res.is_error
                    or stop_res.is_error
                    or launch_res.is_error
                    or get_pe_res.is_error
                    or list_pe_dd_res.is_error
                    or list_tls_res.is_error
                    or get_rf_res.is_error
                    or list_rf_res.is_error
                    or get_party_res.is_error
                    or find_str_res.is_error
                    or dump_mem_res.is_error
                    or dump_mod_res.is_error
                    or create_dmp_res.is_error
                    or get_sec_res.is_error
                    or get_th_cs_res.is_error
                    or list_structs_res.is_error
                    or list_const_res.is_error
                    or list_err_res.is_error
                    or fmt_str_res.is_error
                    or run_script_res.is_error
                    or get_loop_init_res.is_error
                    or add_loop_res.is_error
                    or get_loop_res.is_error
                    or list_loops_res.is_error
                    or del_loop_res.is_error
                    or clear_loops_res.is_error
                    or get_arg_init_res.is_error
                    or add_arg_res.is_error
                    or get_arg_res.is_error
                    or list_args_res.is_error
                    or del_arg_res.is_error
                    or clear_args_res.is_error
                    or alloc_res.is_error
                    or fill_res.is_error
                    or copy_res.is_error
                    or rights_res.is_error
                    or free_res.is_error
                    or skip_res.is_error
                    or run_to_cur_res.is_error
                    or step_exc_res.is_error
                    or step_u_res.is_error
                    or step_s_res.is_error
                    or step_out_exc_res.is_error
                    or rtu_res.is_error
                    or anal_code_res.is_error
                    or anal_cf_res.is_error
                    or anal_ex_res.is_error
                    or anal_rec_res.is_error
                    or anal_adv_res.is_error
                    or anal_xrefs_res.is_error
                    or anal_nukem_res.is_error
                    or list_fn_res.is_error
                    or get_fn_info_res.is_error
                    or get_cfg_res.is_error
                    or get_callers_res.is_error
                    or get_callees_res.is_error
                    or ev_stat_res.is_error
                    or get_ev_res.is_error
                    or wait_ev_res.is_error
                    or clear_ev_res.is_error
                    or add_fn_res.is_error
                    or del_fn_res.is_error
                    or save_db_res.is_error
                    or load_db_res.is_error
                    or list_cmt_res.is_error
                    or del_cmt_res.is_error
                    or clear_cmt_res.is_error
                    or list_lbl_res.is_error
                    or del_lbl_res.is_error
                    or clear_lbl_res.is_error
                    or list_bm_res.is_error
                    or del_bm_res.is_error
                    or clear_bm_res.is_error
                    or clear_fn_res.is_error
                    or set_cmd_res.is_error
                    or set_tr_log_res.is_error
                    or clear_tr_log_res.is_error
                    or set_tr_cmd_res.is_error
                    or clear_tr_cmd_res.is_error
                    or set_tr_filt_res.is_error
                    or reset_tr_filt_res.is_error
                    or set_tr_logfile_res.is_error
                    or clear_tr_logfile_res.is_error
                    or start_rec_res.is_error
                    or stop_rec_res.is_error
                    or tr_into_cnd_res.is_error
                    or tr_over_cnd_res.is_error
                    or tr_into_beyond_res.is_error
                    or tr_over_beyond_res.is_error
                    or tr_into_rec_res.is_error
                    or tr_over_rec_res.is_error
                    or run_to_party_res.is_error
                    or add_w_res.is_error
                    or list_w_res.is_error
                    or get_w_res.is_error
                    or ren_w_res.is_error
                    or set_w_type_res.is_error
                    or mod_w_res.is_error
                    or set_wd_res.is_error
                    or check_wd_res.is_error
                    or del_w_res.is_error
                    or clear_w_res.is_error
                    or open_trace_res.is_error
                    or get_tr_info_res.is_error
                    or get_tr_inst_res.is_error
                    or get_tr_insts_res.is_error
                    or get_tr_regs_res.is_error
                    or get_tr_mem_res.is_error
                    or read_tr_mem_res.is_error
                    or search_tr_addr_res.is_error
                    or search_tr_mem_res.is_error
                    or get_tr_refs_res.is_error
                    or find_tr_calls_res.is_error
                    or close_tr_res.is_error
                    or dt_res.is_error
                    or ds_res.is_error
                    or dm_res.is_error
                    or sdt_res.is_error
                    or cdtr_res.is_error
                    or cdts_res.is_error
                    or ast_res.is_error
                    or asm_res.is_error
                    or at_res.is_error
                    or au_res.is_error
                    or it_res.is_error
                    or gts_res.is_error
                    or lst_res.is_error
                    or rt_res.is_error
                    or ct_res.is_error
                    or list_bp_refs_res.is_error
                    or get_bp_ref_res.is_error
                    or set_bp_ref_res.is_error
                    or get_th_name_res.is_error
                    or set_th_name_res.is_error
                    or set_th_name_clear.is_error
                    or get_th_prio_res.is_error
                    or set_th_prio_res.is_error
                    or set_mod_party_res.is_error
                    or is_cp_res.is_error
                    or get_mn_brief_res.is_error
                    or get_dbg_init_res.is_error
                    or set_dbg_init_res.is_error
                    or get_jit_res.is_error
                    or restart_res.is_error):
                all_pos = [
                    ("add_fn_res", add_fn_res), ("del_fn_res", del_fn_res),
                    ("save_db_res", save_db_res), ("load_db_res", load_db_res),
                    ("list_cmt_res", list_cmt_res), ("del_cmt_res", del_cmt_res),
                    ("clear_cmt_res", clear_cmt_res), ("list_lbl_res", list_lbl_res),
                    ("del_lbl_res", del_lbl_res), ("clear_lbl_res", clear_lbl_res),
                    ("list_bm_res", list_bm_res), ("del_bm_res", del_bm_res),
                    ("clear_bm_res", clear_bm_res), ("clear_fn_res", clear_fn_res),
                    ("set_cmd_res", set_cmd_res), ("clear_db_res", clear_db_res),
                    ("set_tr_log_res", set_tr_log_res), ("clear_tr_log_res", clear_tr_log_res),
                    ("set_tr_cmd_res", set_tr_cmd_res), ("clear_tr_cmd_res", clear_tr_cmd_res),
                    ("set_tr_filt_res", set_tr_filt_res), ("reset_tr_filt_res", reset_tr_filt_res),
                    ("set_tr_logfile_res", set_tr_logfile_res), ("clear_tr_logfile_res", clear_tr_logfile_res),
                    ("start_rec_res", start_rec_res), ("stop_rec_res", stop_rec_res),
                    ("tr_into_cnd_res", tr_into_cnd_res), ("tr_over_cnd_res", tr_over_cnd_res),
                    ("tr_into_beyond_res", tr_into_beyond_res), ("tr_over_beyond_res", tr_over_beyond_res),
                    ("tr_into_rec_res", tr_into_rec_res), ("tr_over_rec_res", tr_over_rec_res),
                    ("run_to_party_res", run_to_party_res),
                    ("add_w_res", add_w_res), ("list_w_res", list_w_res),
                    ("get_w_res", get_w_res), ("ren_w_res", ren_w_res),
                    ("set_w_type_res", set_w_type_res), ("mod_w_res", mod_w_res),
                    ("set_wd_res", set_wd_res), ("check_wd_res", check_wd_res),
                    ("del_w_res", del_w_res), ("clear_w_res", clear_w_res),
                    ("open_trace_res", open_trace_res), ("get_tr_info_res", get_tr_info_res),
                    ("get_tr_inst_res", get_tr_inst_res), ("get_tr_insts_res", get_tr_insts_res),
                    ("get_tr_regs_res", get_tr_regs_res), ("get_tr_mem_res", get_tr_mem_res),
                    ("read_tr_mem_res", read_tr_mem_res), ("search_tr_addr_res", search_tr_addr_res),
                    ("search_tr_mem_res", search_tr_mem_res), ("get_tr_refs_res", get_tr_refs_res),
                    ("find_tr_calls_res", find_tr_calls_res), ("close_tr_res", close_tr_res),
                    ("dt_res", dt_res), ("ds_res", ds_res),
                    ("dm_res", dm_res), ("sdt_res", sdt_res),
                    ("cdtr_res", cdtr_res), ("cdts_res", cdts_res),
                    ("ast_res", ast_res), ("asm_res", asm_res),
                    ("at_res", at_res), ("au_res", au_res),
                    ("it_res", it_res), ("gts_res", gts_res),
                    ("lst_res", lst_res), ("rt_res", rt_res),
                    ("ct_res", ct_res),
                    ("list_bp_refs_res", list_bp_refs_res), ("get_bp_ref_res", get_bp_ref_res),
                    ("set_bp_ref_res", set_bp_ref_res), ("get_th_name_res", get_th_name_res),
                    ("set_th_name_res", set_th_name_res), ("set_th_name_clear", set_th_name_clear),
                    ("get_th_prio_res", get_th_prio_res), ("set_th_prio_res", set_th_prio_res),
                    ("set_mod_party_res", set_mod_party_res), ("is_cp_res", is_cp_res),
                    ("get_mn_brief_res", get_mn_brief_res), ("get_dbg_init_res", get_dbg_init_res),
                    ("set_dbg_init_res", set_dbg_init_res), ("get_jit_res", get_jit_res),
                    ("restart_res", restart_res)
                ]
                for name, res in all_pos:
                    if res.is_error:
                        print(f"FAILED POSITIVE TOOL: {name} content: {res.content}", file=sys.stderr)
                print("ERROR: One or more positive tool calls failed!", file=sys.stderr)
                return 2

            # Check negative test assertions
            if (not mem_null_result.is_error or not disasm_null_result.is_error
                    or not set_dup_res.is_error or not set_null_res.is_error
                    or not del_dup_res.is_error or not step_neg_res.is_error
                    or not resume_neg_res.is_error or not pause_neg_res.is_error
                    or not step_over_neg_res.is_error or not step_out_neg_res.is_error
                    or not switch_nonexist_res.is_error or not switch_neg_res.is_error
                    or not sec_nonexist_res.is_error or not sec_empty_res.is_error
                    or not mem_reg_invalid_res.is_error or not mem_reg_empty_res.is_error
                    or not list_mem_zero_res.is_error or not list_mem_neg_res.is_error
                    or not list_mem_addr_res.is_error
                    or not get_xrefs_invalid_res.is_error or not get_xrefs_empty_res.is_error
                    or not get_addr_info_invalid_res.is_error or not get_addr_info_empty_res.is_error
                    or not eval_empty_res.is_error or not eval_invalid_res.is_error
                    or not find_empty_res.is_error or not find_invalid_res.is_error
                    or not set_reg_invalid_res.is_error
                    or not write_mem_invalid_res.is_error
                    or not en_bp_invalid.is_error
                    or not asm_invalid.is_error
                    or not imp_invalid.is_error
                    or not exp_invalid.is_error
                    or not teb_invalid.is_error
                    or not rights_invalid.is_error
                    or not handles_invalid.is_error
                    or not hinfo_invalid.is_error
                    or not patch_invalid.is_error
                    or not restore_range_invalid.is_error
                    or not va_offset_invalid.is_error
                    or not offset_va_invalid.is_error
                    or not res_sym_invalid.is_error
                    or not list_sym_invalid.is_error
                    or not sym_stat_invalid.is_error
                    or not src_loc_invalid.is_error
                    or not find_src_invalid.is_error
                    or not list_ex_invalid.is_error
                    or not ex_info_invalid.is_error
                    or not set_ex_bp_invalid.is_error
                    or not del_ex_bp_invalid.is_error
                    or not tr_rec_invalid.is_error
                    or not set_tr_type_invalid.is_error
                    or not hw_inv.is_error
                    or not del_hw_inv.is_error
                    or not memr_inv.is_error
                    or not del_dll_inv.is_error
                    or not bp_det_inv.is_error
                    or not kill_neg_res.is_error
                    or not sus_inv_res.is_error
                    or not res_inv_res.is_error
                    or not att_inv_res.is_error
                    or not launch_inv_res.is_error
                    or not pe_hdr_inv.is_error
                    or not pe_dd_inv.is_error
                    or not tls_inv.is_error
                    or not rf_inv.is_error
                    or not lrf_inv.is_error
                    or not party_inv.is_error
                    or not str_inv.is_error
                    or not dump_mem_inv.is_error
                    or not dump_mod_inv.is_error
                    or not minidump_inv.is_error
                    or not th_cs_inv.is_error
                    or not script_inv.is_error
                    or not add_loop_inv.is_error
                    or not del_loop_inv.is_error
                    or not add_arg_inv.is_error
                    or not del_arg_inv.is_error
                    or not alloc_inv.is_error
                    or not free_inv.is_error
                    or not fill_inv.is_error
                    or not copy_inv.is_error
                    or not rights_inv.is_error
                    or not skip_inv.is_error
                    or not run_to_inv.is_error
                    or not step_exc_inv.is_error
                    or not step_out_exc_inv.is_error
                    or not step_u_inv.is_error
                    or not step_s_inv.is_error
                    or not rtu_inv.is_error
                    or not anal_code_inv.is_error
                    or not anal_cf_inv.is_error
                    or not anal_ex_inv.is_error
                    or not anal_rec_inv.is_error
                    or not anal_adv_inv.is_error
                    or not anal_xrefs_inv.is_error
                    or not anal_nukem_inv.is_error
                    or not list_fn_inv.is_error
                    or not get_fn_info_inv.is_error
                    or not get_cfg_inv.is_error
                    or not get_callers_inv.is_error
                    or not get_callees_inv.is_error
                    or not get_ev_inv.is_error
                    or not wait_ev_inv.is_error
                    or not clear_db_inv.is_error
                    or not clear_cmt_inv.is_error
                    or not clear_lbl_inv.is_error
                    or not clear_bm_inv.is_error
                    or not clear_fn_inv.is_error
                    or not add_fn_inv.is_error
                    or not del_fn_inv.is_error
                    or not tr_into_inv.is_error
                    or not tr_over_inv.is_error
                    or not rtp_inv.is_error
                    or not tr_filt_inv.is_error
                    or not start_rec_inv.is_error
                    or not add_w_inv.is_error
                    or not get_w_inv.is_error
                    or not mod_w_inv.is_error
                    or not ren_w_inv.is_error
                    or not set_w_type_inv.is_error
                    or not del_w_inv.is_error
                    or not clear_w_inv.is_error
                    or not set_wd_inv.is_error
                    or not open_tr_inv.is_error
                    or not get_tr_info_inv.is_error
                    or not get_tr_inst_inv.is_error
                    or not get_tr_insts_inv.is_error
                    or not get_tr_regs_inv.is_error
                    or not get_tr_mem_inv.is_error
                    or not read_tr_mem_inv.is_error
                    or not search_tr_addr_inv.is_error
                    or not search_tr_mem_inv.is_error
                    or not get_tr_refs_inv.is_error
                    or not find_tr_calls_inv.is_error
                    or not dt_inv.is_error
                    or not ds_inv.is_error
                    or not dm_inv.is_error
                    or not sdt_inv.is_error
                    or not cdtr_inv.is_error
                    or not cdts_inv.is_error
                    or not it_inv.is_error
                    or not gts_inv.is_error
                    or not lst_inv.is_error
                    or not at_inv.is_error
                    or not ast_inv.is_error
                    or not au_inv.is_error
                    or not asm_inv.is_error
                    or not rt_inv.is_error
                    or not ct_inv.is_error
                    or not set_bp_ref_inv.is_error
                    or not get_th_name_inv.is_error
                    or not set_th_name_inv.is_error
                    or not set_th_prio_inv.is_error
                    or not get_th_prio_inv.is_error
                    or not set_mod_party_inv.is_error
                    or not is_cp_inv.is_error
                    or not get_mn_brief_inv.is_error
                    or not set_jit_inv.is_error
                    or not set_jit_auto_inv.is_error):

                print("ERROR: Expected negative tests to report is_error=True!", file=sys.stderr)
                return 3

            return 0


if __name__ == "__main__":
    ret = anyio.run(run_mcp_test)
    sys.exit(ret)

