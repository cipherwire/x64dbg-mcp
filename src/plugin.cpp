#include "common.h"
#include "pipe_server.h"
#include "exceptions.h"
#include "trace.h"
#include "session_control.h"
#include "events.h"
#include "database.h"


// Minimal DllMain with no initializations
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    return TRUE;
}

// Debug event callbacks
static void cbStepped(CBTYPE cbType, PLUG_CB_STEPPED* info)
{
    (void)cbType;
    LONG current = InterlockedCompareExchange(&g_lastStopReason, STOP_STEP_COMPLETED, STOP_NONE);
    if (current != STOP_BREAKPOINT_HIT)
    {
        InterlockedExchange(&g_lastStopReason, STOP_STEP_COMPLETED);
    }
    event_queue_on_stepped(info);
    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbBreakpoint(CBTYPE cbType, PLUG_CB_BREAKPOINT* info)
{
    (void)cbType;
    duint bpAddr = 0;
    bool isSingleShoot = false;
    bool isSilent = false;
    if (info != nullptr && info->breakpoint != nullptr)
    {
        bpAddr = info->breakpoint->addr;
        isSingleShoot = info->breakpoint->singleshoot;
        isSilent = info->breakpoint->silent;
    }
    (void)isSingleShoot;
    (void)isSilent;

    if (is_user_breakpoint(bpAddr))
    {
        InterlockedExchange(&g_lastStopReason, STOP_BREAKPOINT_HIT);
        g_lastBpAddr = bpAddr;
    }
    else
    {
        InterlockedExchange(&g_lastStopReason, STOP_STEP_COMPLETED);
    }

    event_queue_on_breakpoint(info);

    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbResumeDebug(CBTYPE cbType, PLUG_CB_RESUMEDEBUG* info)
{
    (void)cbType;
    InterlockedExchange(&g_lastStopReason, STOP_RESUMED);
    event_queue_on_resume(info);
}

static void cbPauseDebug(CBTYPE cbType, PLUG_CB_PAUSEDEBUG* info)
{
    (void)cbType;
    LONG prev = InterlockedCompareExchange(&g_lastStopReason, STOP_PAUSED, STOP_NONE);
    if (prev == STOP_NONE || prev == STOP_RESUMED)
    {
        InterlockedExchange(&g_lastStopReason, STOP_PAUSED);
        if (g_hExecEvent != nullptr)
        {
            SetEvent(g_hExecEvent);
        }
    }
    event_queue_on_pause(info);
}

static void cbExitProcess(CBTYPE cbType, PLUG_CB_EXITPROCESS* info)
{
    (void)cbType;
    reset_last_exception();
    on_trace_stopped();
    on_session_stop();
    event_queue_on_exit_process(info);
    InterlockedExchange(&g_lastStopReason, STOP_PROCESS_EXITED);
    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbStoppingDebug(CBTYPE cbType, PLUG_CB_STOPPINGDEBUG* info)
{
    (void)cbType;
    reset_last_exception();
    on_trace_stopped();
    on_session_stop();
    event_queue_on_stop_debug((const PLUG_CB_STOPDEBUG*)info);
    InterlockedExchange(&g_lastStopReason, STOP_DEBUG_ENDED);
    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbStopDebug(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    (void)cbType;
    reset_last_exception();
    on_trace_stopped();
    on_session_stop();
    event_queue_on_stop_debug(info);
    InterlockedExchange(&g_lastStopReason, STOP_DEBUG_ENDED);
    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbException(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
    (void)cbType;
    InterlockedExchange(&g_lastStopReason, STOP_EXCEPTION);
    if (info != nullptr && info->Exception != nullptr)
    {
        g_lastExceptionCode = info->Exception->ExceptionRecord.ExceptionCode;
        record_last_exception(info);
    }
    event_queue_on_exception(info);
    if (g_hExecEvent != nullptr)
    {
        SetEvent(g_hExecEvent);
    }
}

static void cbStartTrace(CBTYPE cbType, PLUG_CB_STARTTRACE* info)
{
    (void)cbType;
    on_trace_started(info != nullptr ? info->traceFilePath : nullptr);
    event_queue_on_start_trace(info);
}

static void cbStopTrace(CBTYPE cbType, PLUG_CB_STOPTRACE* info)
{
    (void)cbType;
    on_trace_stopped();
    event_queue_on_stop_trace(info);
}

static void cbInitDebug(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
    (void)cbType;
    on_session_init_debug((info != nullptr) ? info->szFileName : nullptr);
    event_queue_on_init_debug(info);
}

static void cbAttach(CBTYPE cbType, PLUG_CB_ATTACH* info)
{
    (void)cbType;
    on_session_attach((info != nullptr) ? info->dwProcessId : 0);
    event_queue_on_attach(info);
}

static void cbDetach(CBTYPE cbType, PLUG_CB_DETACH* info)
{
    (void)cbType;
    on_session_detach();
    event_queue_on_detach(info);
}


// Plugin lifecycle exports
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    if (initStruct == nullptr)
    {
        return false;
    }

    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), "x64dbg-MCP", _TRUNCATE);

    g_pluginHandle = initStruct->pluginHandle;

    _plugin_logprintf("[x64dbg-MCP] Plugin loaded (version %d, handle %d)\n",
                      initStruct->pluginVersion,
                      initStruct->pluginHandle);
    log_lifecycle("[x64dbg-MCP] pluginit called.\n");

    // Create manual-reset stop event
    g_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_hStopEvent == nullptr)
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: Failed to create stop event.\n");
        log_lifecycle("[x64dbg-MCP] ERROR: Failed to create stop event.\n");
        return false;
    }

    // Create auto-reset execution event
    g_hExecEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_hExecEvent == nullptr)
    {
        _plugin_logprintf("[x64dbg-MCP] ERROR: Failed to create execution event.\n");
        log_lifecycle("[x64dbg-MCP] ERROR: Failed to create execution event.\n");
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
        return false;
    }

    // Register execution control callbacks
    _plugin_registercallback(g_pluginHandle, CB_RESUMEDEBUG, (CBPLUGIN)cbResumeDebug);
    _plugin_registercallback(g_pluginHandle, CB_PAUSEDEBUG, (CBPLUGIN)cbPauseDebug);
    _plugin_registercallback(g_pluginHandle, CB_STEPPED, (CBPLUGIN)cbStepped);
    _plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, (CBPLUGIN)cbBreakpoint);
    _plugin_registercallback(g_pluginHandle, CB_EXCEPTION, (CBPLUGIN)cbException);
    _plugin_registercallback(g_pluginHandle, CB_EXITPROCESS, (CBPLUGIN)cbExitProcess);
    _plugin_registercallback(g_pluginHandle, CB_STOPPINGDEBUG, (CBPLUGIN)cbStoppingDebug);
    _plugin_registercallback(g_pluginHandle, CB_STOPDEBUG, (CBPLUGIN)cbStopDebug);
    _plugin_registercallback(g_pluginHandle, CB_STARTTRACE, (CBPLUGIN)cbStartTrace);
    _plugin_registercallback(g_pluginHandle, CB_STOPTRACE, (CBPLUGIN)cbStopTrace);
    _plugin_registercallback(g_pluginHandle, CB_INITDEBUG, (CBPLUGIN)cbInitDebug);
    _plugin_registercallback(g_pluginHandle, CB_ATTACH, (CBPLUGIN)cbAttach);
    _plugin_registercallback(g_pluginHandle, CB_DETACH, (CBPLUGIN)cbDetach);

    // Initialize events queue subsystem and its specific callbacks
    events_init();
    database_init();

    // Spawn background worker thread
    if (!StartWorkerThread())
    {
        database_cleanup();
        events_cleanup();
        CloseHandle(g_hStopEvent);
        g_hStopEvent = nullptr;
        CloseHandle(g_hExecEvent);
        g_hExecEvent = nullptr;
        return false;
    }

    return true;
}

extern "C" __declspec(dllexport) bool plugstop()
{
    log_lifecycle("[x64dbg-MCP] plugstop called.\n");

    database_cleanup();
    events_cleanup();

    _plugin_unregistercallback(g_pluginHandle, CB_RESUMEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_PAUSEDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STEPPED);
    _plugin_unregistercallback(g_pluginHandle, CB_BREAKPOINT);
    _plugin_unregistercallback(g_pluginHandle, CB_EXCEPTION);
    _plugin_unregistercallback(g_pluginHandle, CB_EXITPROCESS);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPPINGDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_STARTTRACE);
    _plugin_unregistercallback(g_pluginHandle, CB_STOPTRACE);
    _plugin_unregistercallback(g_pluginHandle, CB_INITDEBUG);
    _plugin_unregistercallback(g_pluginHandle, CB_ATTACH);
    _plugin_unregistercallback(g_pluginHandle, CB_DETACH);

    bool ok = StopWorkerThread();

    _plugin_logprintf("[x64dbg-MCP] Plugin stopped.\n");
    log_lifecycle("[x64dbg-MCP] plugstop finished.\n");

    return ok;
}
