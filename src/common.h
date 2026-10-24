#pragma once

#pragma warning(disable: 4324)

#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <string.h>
#include "_plugins.h"
#include "bridgemain.h"
#include "bridgelist.h"
#include "_scriptapi_debug.h"
#include "_scriptapi_module.h"
#include "_scriptapi_misc.h"
#include "_scriptapi_pattern.h"
#include "_dbgfunctions.h"

#include <string>
#include <vector>
#include <algorithm>
#include <memory>

// Named pipe configuration
#ifdef _WIN64
static const wchar_t* const PIPE_NAME = L"\\\\.\\pipe\\x64dbg_mcp";
#else
static const wchar_t* const PIPE_NAME = L"\\\\.\\pipe\\x32dbg_mcp";
#endif

// Execution control event tracking
enum StopReason
{
    STOP_NONE = 0,
    STOP_STEP_COMPLETED,
    STOP_BREAKPOINT_HIT,
    STOP_EXCEPTION,
    STOP_PAUSED,
    STOP_DEBUG_ENDED,
    STOP_RESUMED,
    STOP_PROCESS_EXITED
};

// Global handles and synchronization state
extern int g_pluginHandle;
extern HANDLE g_hWorkerThread;
extern HANDLE g_hStopEvent;
extern HANDLE g_hExecEvent;
extern volatile LONG g_lastStopReason;
extern volatile duint g_lastBpAddr;
extern volatile DWORD g_lastExceptionCode;
extern volatile LONG g_execActive;

// Common helper functions
void log_lifecycle(const char* message);
void escape_json_string(const char* src, char* dst, size_t dstSize);
bool json_get_string(const char* json, const char* key, char* out, size_t outSize);
bool json_get_int(const char* json, const char* key, int* out);
bool json_get_bool(const char* json, const char* key, bool* out);
bool resolve_address(const char* addrStr, duint* outVa);
bool is_user_breakpoint(duint addr);
