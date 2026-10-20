#include "pipe_server.h"
#include "execution.h"
#include "registers.h"
#include "memory.h"
#include "disassembly.h"
#include "breakpoints.h"
#include "threads.h"
#include "modules.h"
#include "xrefs.h"
#include "address_info.h"
#include "call_stack.h"
#include "expressions.h"
#include "patterns.h"
#include "annotations.h"
#include "functions.h"
#include "assembler.h"
#include "environment.h"
#include "handles.h"
#include "patches.h"
#include "symbols.h"
#include "exceptions.h"
#include "trace.h"
#include "advanced_breakpoints.h"
#include "session_control.h"
#include "pe_metadata.h"
#include "strings_scanner.h"
#include "dump.h"
#include "type_system.h"
#include "scripts.h"
#include "analysis.h"
#include "events.h"
#include "database.h"
#include "tracing.h"
#include "watches.h"
#include "types.h"
#include "dbg_config.h"
#include "console_input.h"
#include "console_output.h"
#include <sddl.h>

static bool dispatch_commands_core(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
        if (strcmp(cmdStr, "ping") == 0)
        {
            _plugin_logprintf("[x64dbg-MCP] Ping received.\n");
            log_lifecycle("[x64dbg-MCP] Ping received.\n");
            responseText = "{\"res\":\"pong\"}\n";
            return true;
        }
        else if (strcmp(cmdStr, "get_debugger_state") == 0)
        {
            handle_get_debugger_state(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_bridge_status") == 0)
        {
            handle_get_bridge_status(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_registers") == 0)
        {
            handle_get_registers(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_register") == 0)
        {
            handle_set_register(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "read_memory") == 0)
        {
            handle_read_memory(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "write_memory") == 0)
        {
            handle_write_memory(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "disassemble") == 0)
        {
            handle_disassemble(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_breakpoint") == 0)
        {
            handle_set_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_breakpoints") == 0)
        {
            handle_list_breakpoints(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_threads") == 0)
        {
            handle_list_threads(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "switch_thread") == 0)
        {
            handle_switch_thread(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_modules") == 0)
        {
            handle_list_modules(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_module_sections") == 0)
        {
            handle_list_module_sections(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_memory_region") == 0)
        {
            handle_get_memory_region(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_memory_regions") == 0)
        {
            handle_list_memory_regions(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_xrefs") == 0)
        {
            handle_get_xrefs(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_address_info") == 0)
        {
            handle_get_address_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_call_stack") == 0)
        {
            handle_get_call_stack(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "eval_expression") == 0)
        {
            handle_eval_expression(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "find_pattern") == 0)
        {
            handle_find_pattern(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_breakpoint") == 0)
        {
            handle_delete_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "enable_breakpoint") == 0)
        {
            handle_enable_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_comment") == 0)
        {
            handle_set_comment(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_comment") == 0)
        {
            handle_get_comment(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_label") == 0)
        {
            handle_set_label(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_label") == 0)
        {
            handle_get_label(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_bookmark") == 0)
        {
            handle_set_bookmark(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_bookmark") == 0)
        {
            handle_get_bookmark(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_function_boundary") == 0)
        {
            handle_get_function_boundary(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "assemble") == 0)
        {
            handle_assemble(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "step_into") == 0)
        {
            handle_step_into(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "step_over") == 0)
        {
            handle_step_over(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "step_out") == 0)
        {
            handle_step_out(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "resume") == 0)
        {
            handle_resume(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "pause") == 0)
        {
            handle_pause(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "test_raw_regdump") == 0)
        {
            handle_test_raw_regdump(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "test_raw_memread") == 0)
        {
            handle_test_raw_memread(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "test_raw_disasm") == 0)
        {
            handle_test_raw_disasm(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
    return false;
}

static bool dispatch_commands_system(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
        if (strcmp(cmdStr, "send_console_input") == 0)
        {
            handle_send_console_input(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "read_console_output") == 0)
        {
            handle_read_console_output(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_imports") == 0)
        {
            handle_list_imports(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_exports") == 0)
        {
            handle_list_exports(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_peb_info") == 0)
        {
            handle_get_peb_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_teb_info") == 0)
        {
            handle_get_teb_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_command_line") == 0)
        {
            handle_get_command_line(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_seh_chain") == 0)
        {
            handle_get_seh_chain(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_page_rights") == 0)
        {
            handle_get_page_rights(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_heaps") == 0)
        {
            handle_list_heaps(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_handles") == 0)
        {
            handle_list_handles(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_handle_info") == 0)
        {
            handle_get_handle_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_tcp_connections") == 0)
        {
            handle_list_tcp_connections(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_windows") == 0)
        {
            handle_list_windows(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "patch_memory") == 0)
        {
            handle_patch_memory(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_patches") == 0)
        {
            handle_list_patches(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_patch") == 0)
        {
            handle_get_patch(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "restore_patch") == 0)
        {
            handle_restore_patch(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "restore_patches_range") == 0)
        {
            handle_restore_patches_range(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "va_to_file_offset") == 0)
        {
            handle_va_to_file_offset(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "file_offset_to_va") == 0)
        {
            handle_file_offset_to_va(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_relocation") == 0)
        {
            handle_get_relocation(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_relocations") == 0)
        {
            handle_list_relocations(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "resolve_symbol") == 0)
        {
            handle_resolve_symbol(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_symbols") == 0)
        {
            handle_list_symbols(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_symbol_status") == 0)
        {
            handle_get_symbol_status(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_source_location") == 0)
        {
            handle_get_source_location(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "find_source_address") == 0)
        {
            handle_find_source_address(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "symbol_autocomplete") == 0)
        {
            handle_symbol_autocomplete(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_exceptions") == 0)
        {
            handle_list_exceptions(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_exception_info") == 0)
        {
            handle_get_exception_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_exception_breakpoint") == 0)
        {
            handle_set_exception_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_exception_breakpoint") == 0)
        {
            handle_delete_exception_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "enable_exception_breakpoint") == 0)
        {
            handle_enable_exception_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_last_exception") == 0)
        {
            handle_get_last_exception(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_trace_record") == 0)
        {
            handle_get_trace_record(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_trace_record_type") == 0)
        {
            handle_set_trace_record_type(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_trace_status") == 0)
        {
            handle_get_trace_status(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
    return false;
}

static bool dispatch_commands_advanced(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
        if (strcmp(cmdStr, "set_hardware_breakpoint") == 0)
        {
            handle_set_hardware_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_hardware_breakpoint") == 0)
        {
            handle_delete_hardware_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "enable_hardware_breakpoint") == 0)
        {
            handle_enable_hardware_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_memory_breakpoint") == 0)
        {
            handle_set_memory_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_memory_range_breakpoint") == 0)
        {
            handle_set_memory_range_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_memory_breakpoint") == 0)
        {
            handle_delete_memory_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "enable_memory_breakpoint") == 0)
        {
            handle_enable_memory_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "set_dll_breakpoint") == 0)
        {
            handle_set_dll_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_dll_breakpoint") == 0)
        {
            handle_delete_dll_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "enable_dll_breakpoint") == 0)
        {
            handle_enable_dll_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_breakpoint_details") == 0)
        {
            handle_get_breakpoint_details(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "configure_breakpoint") == 0)
        {
            handle_configure_breakpoint(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "reset_breakpoint_hit_count") == 0)
        {
            handle_reset_breakpoint_hit_count(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_processes") == 0)
        {
            handle_list_processes(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "launch_debuggee") == 0)
        {
            handle_launch_debuggee(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "attach_process") == 0)
        {
            handle_attach_process(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "detach_process") == 0)
        {
            handle_detach_process(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "stop_debuggee") == 0)
        {
            handle_stop_debuggee(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "suspend_thread") == 0)
        {
            handle_suspend_thread(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "resume_thread") == 0)
        {
            handle_resume_thread(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "suspend_all_threads") == 0)
        {
            handle_suspend_all_threads(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "resume_all_threads") == 0)
        {
            handle_resume_all_threads(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "kill_thread") == 0)
        {
            handle_kill_thread(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_debug_session_info") == 0)
        {
            handle_get_debug_session_info(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_pe_headers") == 0)
        {
            handle_get_pe_headers(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_pe_data_directories") == 0)
        {
            handle_list_pe_data_directories(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_tls_callbacks") == 0)
        {
            handle_list_tls_callbacks(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_runtime_function") == 0)
        {
            handle_get_runtime_function(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_runtime_functions") == 0)
        {
            handle_list_runtime_functions(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_module_party") == 0)
        {
            handle_get_module_party(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "find_strings") == 0)
        {
            handle_find_strings(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "dump_memory") == 0)
        {
            handle_dump_memory(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "dump_module") == 0)
        {
            handle_dump_module(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "create_minidump") == 0)
        {
            handle_create_minidump(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_security_mitigations") == 0)
        {
            handle_get_security_mitigations(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_thread_call_stack") == 0)
        {
            handle_get_thread_call_stack(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_structs") == 0)
        {
            handle_list_structs(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_constants") == 0)
        {
            handle_list_constants(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_error_codes") == 0)
        {
            handle_list_error_codes(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "format_inline_string") == 0)
        {
            handle_format_inline_string(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "run_script") == 0)
        {
            handle_run_script(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_loop") == 0)
        {
            handle_get_loop(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_loops") == 0)
        {
            handle_list_loops(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "add_loop") == 0)
        {
            handle_add_loop(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_loop") == 0)
        {
            handle_delete_loop(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "clear_loops") == 0)
        {
            handle_clear_loops(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "get_argument") == 0)
        {
            handle_get_argument(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "list_arguments") == 0)
        {
            handle_list_arguments(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "add_argument") == 0)
        {
            handle_add_argument(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "delete_argument") == 0)
        {
            handle_delete_argument(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
        else if (strcmp(cmdStr, "clear_arguments") == 0)
        {
            handle_clear_arguments(readBuf, responseBuf, responseBufSize, responseText);
            return true;
        }
    return false;
}

static bool dispatch_commands_phase23(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "run_to_address") == 0)
    {
        handle_run_to_address(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "restart_debuggee") == 0)
    {
        handle_restart_debuggee(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "run_to_user_code") == 0)
    {
        handle_run_to_user_code(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "step_user") == 0)
    {
        handle_step_user(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "step_system") == 0)
    {
        handle_step_system(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "skip_instruction") == 0)
    {
        handle_skip_instruction(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "step_over_pass_exceptions") == 0)
    {
        handle_step_over_pass_exceptions(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "step_out_pass_exceptions") == 0)
    {
        handle_step_out_pass_exceptions(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "allocate_memory") == 0)
    {
        handle_allocate_memory(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "free_memory") == 0)
    {
        handle_free_memory(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "fill_memory") == 0)
    {
        handle_fill_memory(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "copy_memory") == 0)
    {
        handle_copy_memory(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_page_rights") == 0)
    {
        handle_set_page_rights(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}

static bool dispatch_commands_phase24(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "analyze_code") == 0)
    {
        handle_analyze_code(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_control_flow") == 0)
    {
        handle_analyze_control_flow(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_exception_directory") == 0)
    {
        handle_analyze_exception_directory(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_recursive") == 0)
    {
        handle_analyze_recursive(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_advanced") == 0)
    {
        handle_analyze_advanced(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_xrefs") == 0)
    {
        handle_analyze_xrefs(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "analyze_nukem") == 0)
    {
        handle_analyze_nukem(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "list_functions") == 0)
    {
        handle_list_functions(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_function_info") == 0)
    {
        handle_get_function_info(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_control_flow_graph") == 0)
    {
        handle_get_control_flow_graph(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_function_callers") == 0)
    {
        handle_get_function_callers(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_function_callees") == 0)
    {
        handle_get_function_callees(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}

// Worker thread hosting the named pipe server
unsigned __stdcall PipeWorkerThreadProc(void* arg)
{
    (void)arg;
    log_lifecycle("[x64dbg-MCP] Worker thread entered.\n");
    _plugin_logprintf("[x64dbg-MCP] Worker thread started.\n");

    // Allow a medium-integrity MCP client to connect when x64dbg runs elevated
    // (high integrity): world-access DACL + low mandatory integrity label so
    // the no-write-up policy never blocks lower-integrity pipe clients.
    PSECURITY_DESCRIPTOR pipeSd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;WD)S:(ML;;NW;;;LW)",
            SDDL_REVISION_1,
            &pipeSd,
            nullptr))
    {
        DWORD sdErr = GetLastError();
        _plugin_logprintf("[x64dbg-MCP] ERROR: SDDL conversion failed (0x%08X).\n", sdErr);
        log_lifecycle("[x64dbg-MCP] ERROR: SDDL conversion failed.\n");
        return 1;
    }

    SECURITY_ATTRIBUTES pipeSa;
    pipeSa.nLength = sizeof(pipeSa);
    pipeSa.lpSecurityDescriptor = pipeSd;
    pipeSa.bInheritHandle = FALSE;

    // Create named pipe in overlapped mode for non-blocking cancellation
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,
        65536,
        4096,
        0,
        &pipeSa
    );
    LocalFree(pipeSd);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        _plugin_logprintf("[x64dbg-MCP] ERROR: CreateNamedPipe failed (0x%08X).\n", err);
        log_lifecycle("[x64dbg-MCP] ERROR: CreateNamedPipe failed.\n");
        return 1;
    }

    _plugin_logprintf("[x64dbg-MCP] Pipe created: \\\\.\\pipe\\x64dbg_mcp\n");
    log_lifecycle("[x64dbg-MCP] Pipe created.\n");

    // Overlapped event for pipe I/O
    OVERLAPPED ol = { 0 };
    ol.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ol.hEvent == nullptr)
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: CreateEvent for overlapped I/O failed.\n");
        log_lifecycle("[x64dbg-MCP] ERROR: CreateEvent failed.\n");
        CloseHandle(hPipe);
        return 1;
    }

    HANDLE waitHandles[2] = { g_hStopEvent, ol.hEvent };

    while (true)
    {
        ResetEvent(ol.hEvent);

        // Wait for a client connection
        BOOL connected = ConnectNamedPipe(hPipe, &ol);
        DWORD err = GetLastError();

        if (!connected)
        {
            if (err == ERROR_IO_PENDING)
            {
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0)
                {
                    log_lifecycle("[x64dbg-MCP] Stop signaled during ConnectNamedPipe.\n");
                    CancelIoEx(hPipe, &ol);
                    WaitForSingleObject(ol.hEvent, 1000);
                    break;
                }
                else if (waitResult == WAIT_OBJECT_0 + 1)
                {
                    DWORD bytesTransferred = 0;
                    if (!GetOverlappedResult(hPipe, &ol, &bytesTransferred, FALSE))
                    {
                        DisconnectNamedPipe(hPipe);
                        continue;
                    }
                }
                else
                {
                    break;
                }
            }
            else if (err == ERROR_PIPE_CONNECTED)
            {
                // Client already connected before ConnectNamedPipe
            }
            else
            {
                _plugin_logprintf("[x64dbg-MCP] ConnectNamedPipe error (0x%08X).\n", err);
                break;
            }
        }

        _plugin_logprintf("[x64dbg-MCP] Client connected.\n");
        log_lifecycle("[x64dbg-MCP] Client connected.\n");

        // Read single request from client
        char readBuf[8192] = { 0 };
        DWORD bytesRead = 0;
        ResetEvent(ol.hEvent);

        BOOL readOk = ReadFile(hPipe, readBuf, sizeof(readBuf) - 1, nullptr, &ol);
        DWORD readErr = GetLastError();

        if (!readOk)
        {
            if (readErr == ERROR_IO_PENDING)
            {
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0)
                {
                    log_lifecycle("[x64dbg-MCP] Stop signaled during ReadFile.\n");
                    CancelIoEx(hPipe, &ol);
                    WaitForSingleObject(ol.hEvent, 1000);
                    break;
                }
                else if (waitResult == WAIT_OBJECT_0 + 1)
                {
                    if (!GetOverlappedResult(hPipe, &ol, &bytesRead, FALSE))
                    {
                        log_lifecycle("[x64dbg-MCP] Read failed / client disconnected.\n");
                        DisconnectNamedPipe(hPipe);
                        continue;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                log_lifecycle("[x64dbg-MCP] ReadFile error / client disconnected.\n");
                DisconnectNamedPipe(hPipe);
                continue;
            }
        }
        else
        {
            GetOverlappedResult(hPipe, &ol, &bytesRead, FALSE);
        }

        readBuf[bytesRead] = '\0';

        // Match protocol request
        char responseBuf[65536] = { 0 };
        const char* responseText = nullptr;

        char cmdStr[64] = { 0 };
        if (!json_get_string(readBuf, "cmd", cmdStr, sizeof(cmdStr)) || cmdStr[0] == '\0')
        {
            json_get_string(readBuf, "command", cmdStr, sizeof(cmdStr));
        }

        if (!dispatch_commands_core(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_system(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_advanced(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase23(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase24(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase25(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase26(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase27(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase28(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase30(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText) &&
            !dispatch_commands_phase31(cmdStr, readBuf, responseBuf, sizeof(responseBuf), responseText))
        {
            _plugin_logprintf("[x64dbg-MCP] Unknown command received: %s\n", readBuf);
            log_lifecycle("[x64dbg-MCP] Unknown command received.\n");
            responseText = "{\"error\":\"unknown command\"}\n";
        }

        // Send response
        DWORD bytesWritten = 0;
        ResetEvent(ol.hEvent);
        BOOL writeOk = WriteFile(hPipe, responseText, (DWORD)strlen(responseText), nullptr, &ol);
        if (!writeOk && GetLastError() == ERROR_IO_PENDING)
        {
            DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0)
            {
                CancelIoEx(hPipe, &ol);
                WaitForSingleObject(ol.hEvent, 1000);
                break;
            }
            GetOverlappedResult(hPipe, &ol, &bytesWritten, FALSE);
        }

        FlushFileBuffers(hPipe);
        _plugin_logprintf("[x64dbg-MCP] Response sent.\n");
        log_lifecycle("[x64dbg-MCP] Response sent.\n");

        DisconnectNamedPipe(hPipe);
        log_lifecycle("[x64dbg-MCP] Client disconnected.\n");

        // Check if stop was signaled
        if (WaitForSingleObject(g_hStopEvent, 0) == WAIT_OBJECT_0)
        {
            break;
        }
    }

    CloseHandle(ol.hEvent);
    CloseHandle(hPipe);

    log_lifecycle("[x64dbg-MCP] Worker thread exiting.\n");
    _plugin_logprintf("[x64dbg-MCP] Worker thread exiting.\n");
    return 0;
}

bool StartWorkerThread()
{
    g_hWorkerThread = (HANDLE)_beginthreadex(nullptr, 0, PipeWorkerThreadProc, nullptr, 0, nullptr);
    if (g_hWorkerThread == nullptr)
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: Failed to create worker thread.\n");
        log_lifecycle("[x64dbg-MCP] ERROR: Failed to create worker thread.\n");
        return false;
    }

    log_lifecycle("[x64dbg-MCP] Worker thread created successfully.\n");
    return true;
}

bool StopWorkerThread()
{
    if (g_hWorkerThread == nullptr)
    {
        return true;
    }

    _plugin_logprintf("[x64dbg-MCP] Worker stop requested.\n");
    log_lifecycle("[x64dbg-MCP] Worker stop requested.\n");

    // Signal stop event to unblock WaitForMultipleObjects
    if (g_hStopEvent != nullptr)
    {
        SetEvent(g_hStopEvent);
    }

    // Wait up to 5000ms for thread to finish cancellation and cleanup
    DWORD waitResult = WaitForSingleObject(g_hWorkerThread, 5000);
    bool success = false;

    if (waitResult == WAIT_OBJECT_0)
    {
        _plugin_logprintf("[x64dbg-MCP] Worker stopped.\n");
        log_lifecycle("[x64dbg-MCP] Worker thread joined successfully.\n");
        success = true;
    }
    else if (waitResult == WAIT_TIMEOUT)
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: Worker stop timed out.\n");
        log_lifecycle("[x64dbg-MCP] ERROR: Worker stop timed out.\n");
    }
    else
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: Worker join failed (0x%08X).\n", waitResult);
        log_lifecycle("[x64dbg-MCP] ERROR: Worker join failed.\n");
    }

    CloseHandle(g_hWorkerThread);
    g_hWorkerThread = nullptr;

    if (g_hStopEvent != nullptr)
    {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
    }

    if (g_hExecEvent != nullptr)
    {
        CloseHandle(g_hExecEvent);
        g_hExecEvent = nullptr;
    }

    return success;
}
