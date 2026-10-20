#pragma once

#include "common.h"
#include <_plugins.h>
#include <string>
#include <vector>
#include <deque>

// Core Event Record definition
struct DebugEventRecord
{
    uint64_t sequence;
    uint32_t session_id;
    char iso_timestamp[32];
    std::string type;       // Stable taxonomy type
    std::string callback;   // x64dbg callback name (e.g. "CB_BREAKPOINT")
    uint32_t process_id;
    uint32_t thread_id;

    // Optional event-specific metadata
    duint address;
    duint base_address;
    duint size;
    uint32_t exception_code;
    uint32_t exit_code;
    bool first_chance;
    std::string module_name;
    std::string symbol_name;
    std::string string_content;
    std::string details;
    uint32_t debug_event_code;
};

// Lifecycle and subsystem initialization
void events_init();
void events_cleanup();

// Dispatcher for Phase 25 named pipe commands
bool dispatch_commands_phase25(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// MCP Tool Handlers
void handle_get_debug_events(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_wait_for_debug_event(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_debug_events(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_event_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Callback hook functions invoked by plugin.cpp
void event_queue_on_init_debug(const PLUG_CB_INITDEBUG* info);
void event_queue_on_stop_debug(const PLUG_CB_STOPDEBUG* info);
void event_queue_on_create_process(const PLUG_CB_CREATEPROCESS* info);
void event_queue_on_exit_process(const PLUG_CB_EXITPROCESS* info);
void event_queue_on_create_thread(const PLUG_CB_CREATETHREAD* info);
void event_queue_on_exit_thread(const PLUG_CB_EXITTHREAD* info);
void event_queue_on_system_breakpoint(const PLUG_CB_SYSTEMBREAKPOINT* info);
void event_queue_on_load_dll(const PLUG_CB_LOADDLL* info);
void event_queue_on_unload_dll(const PLUG_CB_UNLOADDLL* info);
void event_queue_on_output_debug_string(const PLUG_CB_OUTPUTDEBUGSTRING* info);
void event_queue_on_exception(const PLUG_CB_EXCEPTION* info);
void event_queue_on_breakpoint(const PLUG_CB_BREAKPOINT* info);
void event_queue_on_pause(const PLUG_CB_PAUSEDEBUG* info);
void event_queue_on_resume(const PLUG_CB_RESUMEDEBUG* info);
void event_queue_on_stepped(const PLUG_CB_STEPPED* info);
void event_queue_on_attach(const PLUG_CB_ATTACH* info);
void event_queue_on_detach(const PLUG_CB_DETACH* info);
void event_queue_on_start_trace(const PLUG_CB_STARTTRACE* info);
void event_queue_on_stop_trace(const PLUG_CB_STOPTRACE* info);
void event_queue_on_trace_execute(const PLUG_CB_TRACEEXECUTE* info);
void event_queue_on_debug_event(const PLUG_CB_DEBUGEVENT* info);
