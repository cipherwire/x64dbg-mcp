#include "events.h"
#include <sstream>
#include <iomanip>
#include <set>

static CRITICAL_SECTION g_eventQueueCs;
static CONDITION_VARIABLE g_eventQueueCv;
static std::deque<DebugEventRecord> g_eventQueue;
static const size_t MAX_EVENT_CAPACITY = 4096;

static uint64_t g_currentSequence = 0;
static uint64_t g_earliestRetainedSequence = 1;
static uint64_t g_droppedCount = 0;
static uint32_t g_currentSessionId = 0;
static bool g_isShuttingDown = false;
static std::string g_lastEventType = "none";

// Helpers
static void get_iso8601_timestamp(char* buf, size_t bufSize)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    sprintf_s(buf, bufSize, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static bool json_get_uint64(const char* json, const char* key, uint64_t* out)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);
    const char* p = strstr(json, searchKey);
    if (!p) return false;
    p += strlen(searchKey);
    while (*p == ' ' || *p == '\t') p++;
    char* endPtr = nullptr;
    unsigned __int64 val = _strtoui64(p, &endPtr, 10);
    if (endPtr == p) return false;
    *out = (uint64_t)val;
    return true;
}

static bool json_get_string_list(const char* json, const char* key, std::vector<std::string>& out)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);
    const char* p = strstr(json, searchKey);
    if (!p) return false;
    p += strlen(searchKey);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '[') return false;
    p++;

    while (*p != '\0' && *p != ']')
    {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == '\r' || *p == '\n') p++;
        if (*p == ']') break;
        if (*p != '\"') return false;
        p++;
        const char* end = strchr(p, '\"');
        if (!end) return false;
        out.push_back(std::string(p, end - p));
        p = end + 1;
    }
    return true;
}

static std::string event_to_json(const DebugEventRecord& ev)
{
    std::string j = "{";
    j += "\"sequence\":" + std::to_string(ev.sequence);
    j += ",\"session_id\":" + std::to_string(ev.session_id);
    j += ",\"timestamp\":\"" + std::string(ev.iso_timestamp) + "\"";
    j += ",\"type\":\"" + ev.type + "\"";
    j += ",\"callback\":\"" + ev.callback + "\"";
    j += ",\"process_id\":" + std::to_string(ev.process_id);
    j += ",\"thread_id\":" + std::to_string(ev.thread_id);

    if (ev.address != 0)
    {
        char addrBuf[32];
        sprintf_s(addrBuf, sizeof(addrBuf), "0x%016llX", (unsigned long long)ev.address);
        j += ",\"address\":\"" + std::string(addrBuf) + "\"";
    }
    if (ev.base_address != 0)
    {
        char baseBuf[32];
        sprintf_s(baseBuf, sizeof(baseBuf), "0x%016llX", (unsigned long long)ev.base_address);
        j += ",\"base_address\":\"" + std::string(baseBuf) + "\"";
    }
    if (ev.size != 0)
    {
        j += ",\"size\":" + std::to_string(ev.size);
    }
    if (ev.exception_code != 0)
    {
        char codeBuf[32];
        sprintf_s(codeBuf, sizeof(codeBuf), "0x%08X", ev.exception_code);
        j += ",\"exception_code\":\"" + std::string(codeBuf) + "\"";
        j += ",\"first_chance\":" + std::string(ev.first_chance ? "true" : "false");
    }
    if (ev.exit_code != 0)
    {
        j += ",\"exit_code\":" + std::to_string(ev.exit_code);
    }
    if (!ev.module_name.empty())
    {
        char escMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(ev.module_name.c_str(), escMod, sizeof(escMod));
        j += ",\"module\":\"" + std::string(escMod) + "\"";
    }
    if (!ev.symbol_name.empty())
    {
        char escSym[MAX_LABEL_SIZE * 2] = { 0 };
        escape_json_string(ev.symbol_name.c_str(), escSym, sizeof(escSym));
        j += ",\"symbol\":\"" + std::string(escSym) + "\"";
    }
    if (!ev.string_content.empty())
    {
        char escStr[512] = { 0 };
        escape_json_string(ev.string_content.c_str(), escStr, sizeof(escStr));
        j += ",\"string\":\"" + std::string(escStr) + "\"";
    }
    if (!ev.details.empty())
    {
        char escDet[256] = { 0 };
        escape_json_string(ev.details.c_str(), escDet, sizeof(escDet));
        j += ",\"details\":\"" + std::string(escDet) + "\"";
    }
    if (ev.debug_event_code != 0)
    {
        j += ",\"debug_event_code\":" + std::to_string(ev.debug_event_code);
    }
    j += "}";
    return j;
}

static void enqueue_event(DebugEventRecord& ev)
{
    EnterCriticalSection(&g_eventQueueCs);
    if (g_isShuttingDown)
    {
        LeaveCriticalSection(&g_eventQueueCs);
        return;
    }

    ev.sequence = ++g_currentSequence;
    ev.session_id = g_currentSessionId;
    get_iso8601_timestamp(ev.iso_timestamp, sizeof(ev.iso_timestamp));
    g_lastEventType = ev.type;

    if (g_eventQueue.size() >= MAX_EVENT_CAPACITY)
    {
        g_eventQueue.pop_front();
        g_droppedCount++;
        if (!g_eventQueue.empty())
        {
            g_earliestRetainedSequence = g_eventQueue.front().sequence;
        }
    }

    g_eventQueue.push_back(ev);
    WakeAllConditionVariable(&g_eventQueueCv);
    LeaveCriticalSection(&g_eventQueueCs);
}

// ---------------------------------------------------------------------------
// Callbacks registered specifically by events subsystem
// ---------------------------------------------------------------------------
static void cbCreateProcess(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
{
    (void)cbType;
    event_queue_on_create_process(info);
}

static void cbCreateThread(CBTYPE cbType, PLUG_CB_CREATETHREAD* info)
{
    (void)cbType;
    event_queue_on_create_thread(info);
}

static void cbExitThread(CBTYPE cbType, PLUG_CB_EXITTHREAD* info)
{
    (void)cbType;
    event_queue_on_exit_thread(info);
}

static void cbSystemBreakpoint(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
{
    (void)cbType;
    event_queue_on_system_breakpoint(info);
}

static void cbLoadDll(CBTYPE cbType, PLUG_CB_LOADDLL* info)
{
    (void)cbType;
    event_queue_on_load_dll(info);
}

static void cbUnloadDll(CBTYPE cbType, PLUG_CB_UNLOADDLL* info)
{
    (void)cbType;
    event_queue_on_unload_dll(info);
}

static void cbOutputDebugString(CBTYPE cbType, PLUG_CB_OUTPUTDEBUGSTRING* info)
{
    (void)cbType;
    event_queue_on_output_debug_string(info);
}

static void cbTraceExecute(CBTYPE cbType, PLUG_CB_TRACEEXECUTE* info)
{
    (void)cbType;
    event_queue_on_trace_execute(info);
}

static void cbDebugEvent(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
    (void)cbType;
    event_queue_on_debug_event(info);
}

// ---------------------------------------------------------------------------
// Lifecycle management
// ---------------------------------------------------------------------------
void events_init()
{
    InitializeCriticalSection(&g_eventQueueCs);
    InitializeConditionVariable(&g_eventQueueCv);
    g_currentSequence = 0;
    g_earliestRetainedSequence = 1;
    g_droppedCount = 0;
    g_currentSessionId = DbgIsDebugging() ? 1 : 0;
    g_isShuttingDown = false;
    g_lastEventType = "none";
    g_eventQueue.clear();

    if (g_pluginHandle != 0)
    {
        _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, (CBPLUGIN)cbCreateProcess);
        _plugin_registercallback(g_pluginHandle, CB_CREATETHREAD, (CBPLUGIN)cbCreateThread);
        _plugin_registercallback(g_pluginHandle, CB_EXITTHREAD, (CBPLUGIN)cbExitThread);
        _plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, (CBPLUGIN)cbSystemBreakpoint);
        _plugin_registercallback(g_pluginHandle, CB_LOADDLL, (CBPLUGIN)cbLoadDll);
        _plugin_registercallback(g_pluginHandle, CB_UNLOADDLL, (CBPLUGIN)cbUnloadDll);
        _plugin_registercallback(g_pluginHandle, CB_OUTPUTDEBUGSTRING, (CBPLUGIN)cbOutputDebugString);
        _plugin_registercallback(g_pluginHandle, CB_TRACEEXECUTE, (CBPLUGIN)cbTraceExecute);
        _plugin_registercallback(g_pluginHandle, CB_DEBUGEVENT, (CBPLUGIN)cbDebugEvent);
    }
}

void events_cleanup()
{
    if (g_pluginHandle != 0)
    {
        _plugin_unregistercallback(g_pluginHandle, CB_CREATEPROCESS);
        _plugin_unregistercallback(g_pluginHandle, CB_CREATETHREAD);
        _plugin_unregistercallback(g_pluginHandle, CB_EXITTHREAD);
        _plugin_unregistercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT);
        _plugin_unregistercallback(g_pluginHandle, CB_LOADDLL);
        _plugin_unregistercallback(g_pluginHandle, CB_UNLOADDLL);
        _plugin_unregistercallback(g_pluginHandle, CB_OUTPUTDEBUGSTRING);
        _plugin_unregistercallback(g_pluginHandle, CB_TRACEEXECUTE);
        _plugin_unregistercallback(g_pluginHandle, CB_DEBUGEVENT);
    }

    EnterCriticalSection(&g_eventQueueCs);
    g_isShuttingDown = true;
    WakeAllConditionVariable(&g_eventQueueCv);
    LeaveCriticalSection(&g_eventQueueCs);

    DeleteCriticalSection(&g_eventQueueCs);
}

// ---------------------------------------------------------------------------
// Callback hooks implementations
// ---------------------------------------------------------------------------
void event_queue_on_init_debug(const PLUG_CB_INITDEBUG* info)
{
    EnterCriticalSection(&g_eventQueueCs);
    g_currentSessionId++;
    LeaveCriticalSection(&g_eventQueueCs);

    DebugEventRecord ev = { 0 };
    ev.type = "initialize";
    ev.callback = "CB_INITDEBUG";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->szFileName)
    {
        ev.module_name = info->szFileName;
    }
    enqueue_event(ev);
}

void event_queue_on_stop_debug(const PLUG_CB_STOPDEBUG* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "stop";
    ev.callback = "CB_STOPDEBUG";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_create_process(const PLUG_CB_CREATEPROCESS* info)
{
    EnterCriticalSection(&g_eventQueueCs);
    if (g_currentSessionId == 0) g_currentSessionId = 1;
    LeaveCriticalSection(&g_eventQueueCs);

    DebugEventRecord ev = { 0 };
    ev.type = "create_process";
    ev.callback = "CB_CREATEPROCESS";
    if (info)
    {
        if (info->fdProcessInfo)
        {
            ev.process_id = info->fdProcessInfo->dwProcessId;
            ev.thread_id = info->fdProcessInfo->dwThreadId;
        }
        else if (info->CreateProcessInfo)
        {
            ev.process_id = GetProcessId(info->CreateProcessInfo->hProcess);
            ev.thread_id = GetThreadId(info->CreateProcessInfo->hThread);
        }
        if (info->CreateProcessInfo)
        {
            ev.base_address = (duint)info->CreateProcessInfo->lpBaseOfImage;
            ev.address = (duint)info->CreateProcessInfo->lpStartAddress;
        }
        if (info->DebugFileName)
        {
            ev.module_name = info->DebugFileName;
        }
    }
    if (ev.process_id == 0) ev.process_id = DbgGetProcessId();
    if (ev.thread_id == 0) ev.thread_id = DbgGetThreadId();

    enqueue_event(ev);
}

void event_queue_on_exit_process(const PLUG_CB_EXITPROCESS* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "exit_process";
    ev.callback = "CB_EXITPROCESS";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->ExitProcess)
    {
        ev.exit_code = info->ExitProcess->dwExitCode;
    }
    enqueue_event(ev);
}

void event_queue_on_create_thread(const PLUG_CB_CREATETHREAD* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "create_thread";
    ev.callback = "CB_CREATETHREAD";
    ev.process_id = DbgGetProcessId();
    if (info)
    {
        ev.thread_id = info->dwThreadId;
        if (info->CreateThread)
        {
            ev.address = (duint)info->CreateThread->lpStartAddress;
        }
    }
    if (ev.thread_id == 0) ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_exit_thread(const PLUG_CB_EXITTHREAD* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "exit_thread";
    ev.callback = "CB_EXITTHREAD";
    ev.process_id = DbgGetProcessId();
    if (info)
    {
        ev.thread_id = info->dwThreadId;
        if (info->ExitThread)
        {
            ev.exit_code = info->ExitThread->dwExitCode;
        }
    }
    if (ev.thread_id == 0) ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_system_breakpoint(const PLUG_CB_SYSTEMBREAKPOINT* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "system_breakpoint";
    ev.callback = "CB_SYSTEMBREAKPOINT";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    ev.address = DbgValFromString("CIP");
    enqueue_event(ev);
}

void event_queue_on_load_dll(const PLUG_CB_LOADDLL* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "load_dll";
    ev.callback = "CB_LOADDLL";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info)
    {
        if (info->LoadDll)
        {
            ev.base_address = (duint)info->LoadDll->lpBaseOfDll;
        }
        if (info->modname)
        {
            ev.module_name = info->modname;
        }
    }
    enqueue_event(ev);
}

void event_queue_on_unload_dll(const PLUG_CB_UNLOADDLL* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "unload_dll";
    ev.callback = "CB_UNLOADDLL";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->UnloadDll)
    {
        ev.base_address = (duint)info->UnloadDll->lpBaseOfDll;
    }
    enqueue_event(ev);
}

void event_queue_on_output_debug_string(const PLUG_CB_OUTPUTDEBUGSTRING* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "output_debug_string";
    ev.callback = "CB_OUTPUTDEBUGSTRING";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->DebugString && info->DebugString->lpDebugStringData)
    {
        WORD len = min(info->DebugString->nDebugStringLength, (WORD)256);
        if (len > 0)
        {
            if (info->DebugString->fUnicode)
            {
                std::vector<wchar_t> wbuf(len + 1, 0);
                if (DbgMemRead((duint)info->DebugString->lpDebugStringData, wbuf.data(), len * sizeof(wchar_t)))
                {
                    char u8[512] = { 0 };
                    WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1, u8, sizeof(u8), nullptr, nullptr);
                    ev.string_content = u8;
                }
            }
            else
            {
                std::vector<char> abuf(len + 1, 0);
                if (DbgMemRead((duint)info->DebugString->lpDebugStringData, abuf.data(), len))
                {
                    ev.string_content = abuf.data();
                }
            }
        }
    }
    enqueue_event(ev);
}

void event_queue_on_exception(const PLUG_CB_EXCEPTION* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "exception";
    ev.callback = "CB_EXCEPTION";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->Exception)
    {
        ev.exception_code = info->Exception->ExceptionRecord.ExceptionCode;
        ev.address = (duint)info->Exception->ExceptionRecord.ExceptionAddress;
        ev.first_chance = (info->Exception->dwFirstChance != 0);
    }
    enqueue_event(ev);
}

void event_queue_on_breakpoint(const PLUG_CB_BREAKPOINT* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "breakpoint";
    ev.callback = "CB_BREAKPOINT";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->breakpoint)
    {
        ev.address = info->breakpoint->addr;
        if (info->breakpoint->mod[0] != '\0')
        {
            ev.module_name = info->breakpoint->mod;
        }
        if (info->breakpoint->name[0] != '\0')
        {
            ev.symbol_name = info->breakpoint->name;
        }
        ev.details = info->breakpoint->singleshoot ? "singleshoot" : "normal";
    }
    enqueue_event(ev);
}

void event_queue_on_pause(const PLUG_CB_PAUSEDEBUG* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "pause";
    ev.callback = "CB_PAUSEDEBUG";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    ev.address = DbgValFromString("CIP");
    enqueue_event(ev);
}

void event_queue_on_resume(const PLUG_CB_RESUMEDEBUG* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "resume";
    ev.callback = "CB_RESUMEDEBUG";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_stepped(const PLUG_CB_STEPPED* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "stepped";
    ev.callback = "CB_STEPPED";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    ev.address = DbgValFromString("CIP");
    enqueue_event(ev);
}

void event_queue_on_attach(const PLUG_CB_ATTACH* info)
{
    EnterCriticalSection(&g_eventQueueCs);
    g_currentSessionId++;
    LeaveCriticalSection(&g_eventQueueCs);

    DebugEventRecord ev = { 0 };
    ev.type = "attach";
    ev.callback = "CB_ATTACH";
    ev.process_id = (info != nullptr) ? info->dwProcessId : DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_detach(const PLUG_CB_DETACH* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "detach";
    ev.callback = "CB_DETACH";
    if (info && info->fdProcessInfo)
    {
        ev.process_id = info->fdProcessInfo->dwProcessId;
    }
    else
    {
        ev.process_id = DbgGetProcessId();
    }
    ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_start_trace(const PLUG_CB_STARTTRACE* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "trace_start";
    ev.callback = "CB_STARTTRACE";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info && info->traceFilePath)
    {
        ev.string_content = info->traceFilePath;
    }
    enqueue_event(ev);
}

void event_queue_on_stop_trace(const PLUG_CB_STOPTRACE* info)
{
    (void)info;
    DebugEventRecord ev = { 0 };
    ev.type = "trace_stop";
    ev.callback = "CB_STOPTRACE";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    enqueue_event(ev);
}

void event_queue_on_trace_execute(const PLUG_CB_TRACEEXECUTE* info)
{
    DebugEventRecord ev = { 0 };
    ev.type = "trace_execute";
    ev.callback = "CB_TRACEEXECUTE";
    ev.process_id = DbgGetProcessId();
    ev.thread_id = DbgGetThreadId();
    if (info)
    {
        ev.address = info->cip;
        ev.details = info->stop ? "stop_requested" : "continue";
    }
    enqueue_event(ev);
}

void event_queue_on_debug_event(const PLUG_CB_DEBUGEVENT* info)
{
    if (!info || !info->DebugEvent)
        return;

    DWORD code = info->DebugEvent->dwDebugEventCode;

    // To prevent duplicate event emissions for standard events that are handled
    // by dedicated semantic callbacks (1..8), only emit raw debug_event for unhandled
    // codes such as RIP_EVENT (9) or custom/kernel events.
    if (code == 9 /* RIP_EVENT */ || code > 9 || code == 0)
    {
        DebugEventRecord ev = { 0 };
        ev.type = "debug_event";
        ev.callback = "CB_DEBUGEVENT";
        ev.process_id = info->DebugEvent->dwProcessId;
        ev.thread_id = info->DebugEvent->dwThreadId;
        ev.debug_event_code = code;
        enqueue_event(ev);
    }
}

// ---------------------------------------------------------------------------
// Tool Handlers
// ---------------------------------------------------------------------------

// 1. get_debug_events
void handle_get_debug_events(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    uint64_t afterSeq = 0;
    json_get_uint64(readBuf, "after_sequence", &afterSeq);

    int limit = 50;
    json_get_int(readBuf, "limit", &limit);
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    std::vector<std::string> typeFilters;
    json_get_string_list(readBuf, "types", typeFilters);

    std::vector<DebugEventRecord> matched;
    uint64_t earliestRetained = 0;
    uint64_t droppedCount = 0;
    uint64_t nextSeq = 0;

    EnterCriticalSection(&g_eventQueueCs);
    earliestRetained = g_earliestRetainedSequence;
    droppedCount = g_droppedCount;
    nextSeq = g_currentSequence + 1;

    for (const auto& ev : g_eventQueue)
    {
        if (ev.sequence <= afterSeq)
            continue;

        if (!typeFilters.empty())
        {
            bool foundType = false;
            for (const auto& tf : typeFilters)
            {
                if (_stricmp(tf.c_str(), ev.type.c_str()) == 0)
                {
                    foundType = true;
                    break;
                }
            }
            if (!foundType)
                continue;
        }

        matched.push_back(ev);
        if (matched.size() >= (size_t)limit)
            break;
    }
    LeaveCriticalSection(&g_eventQueueCs);

    std::string json = "{\"count\":" + std::to_string(matched.size()) +
                       ",\"next_sequence\":" + std::to_string(nextSeq) +
                       ",\"earliest_retained_sequence\":" + std::to_string(earliestRetained) +
                       ",\"dropped_before_sequence\":" + std::to_string(earliestRetained) +
                       ",\"dropped_count\":" + std::to_string(droppedCount) +
                       ",\"events\":[";

    for (size_t i = 0; i < matched.size(); i++)
    {
        if (i > 0) json += ",";
        json += event_to_json(matched[i]);
    }
    json += "],\"success\":true}\n";

    if (json.length() < responseBufSize)
    {
        strcpy_s(responseBuf, responseBufSize, json.c_str());
        responseText = responseBuf;
    }
    else
    {
        responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Event batch exceeds response buffer size\"}}\n";
    }
}

// 2. wait_for_debug_event
void handle_wait_for_debug_event(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    uint64_t afterSeq = 0;
    json_get_uint64(readBuf, "after_sequence", &afterSeq);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs < 0) timeoutMs = 0;
    if (timeoutMs > 60000) timeoutMs = 60000;

    std::vector<std::string> typeFilters;
    json_get_string_list(readBuf, "types", typeFilters);

    DebugEventRecord matchedEvent;
    bool found = false;
    bool timedOut = false;

    ULONGLONG startTick = GetTickCount64();

    EnterCriticalSection(&g_eventQueueCs);
    while (!found && !timedOut)
    {
        if (g_isShuttingDown)
        {
            LeaveCriticalSection(&g_eventQueueCs);
            responseText = "{\"error\":{\"code\":\"queue_shutdown\",\"message\":\"Event queue is shutting down\"}}\n";
            return;
        }

        // 1. Check existing queued events
        for (const auto& ev : g_eventQueue)
        {
            if (ev.sequence <= afterSeq)
                continue;

            if (!typeFilters.empty())
            {
                bool typeOk = false;
                for (const auto& tf : typeFilters)
                {
                    if (_stricmp(tf.c_str(), ev.type.c_str()) == 0)
                    {
                        typeOk = true;
                        break;
                    }
                }
                if (!typeOk)
                    continue;
            }

            matchedEvent = ev;
            found = true;
            break;
        }

        if (found)
            break;

        // Calculate remaining timeout
        ULONGLONG elapsed = GetTickCount64() - startTick;
        if (elapsed >= (ULONGLONG)timeoutMs)
        {
            timedOut = true;
            break;
        }

        DWORD waitMs = (DWORD)((ULONGLONG)timeoutMs - elapsed);
        if (!SleepConditionVariableCS(&g_eventQueueCv, &g_eventQueueCs, waitMs))
        {
            if (GetLastError() == ERROR_TIMEOUT)
            {
                timedOut = true;
                break;
            }
        }
    }

    uint64_t nextSeq = g_currentSequence + 1;
    LeaveCriticalSection(&g_eventQueueCs);

    if (found)
    {
        std::string json = "{\"event\":" + event_to_json(matchedEvent) + ",\"timed_out\":false,\"success\":true}\n";
        if (json.length() < responseBufSize)
        {
            strcpy_s(responseBuf, responseBufSize, json.c_str());
            responseText = responseBuf;
        }
        else
        {
            responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Event JSON exceeds response buffer size\"}}\n";
        }
    }
    else
    {
        std::string json = "{\"event\":null,\"timed_out\":true,\"next_sequence\":" + std::to_string(nextSeq) + ",\"success\":true}\n";
        strcpy_s(responseBuf, responseBufSize, json.c_str());
        responseText = responseBuf;
    }
}

// 3. clear_debug_events
void handle_clear_debug_events(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    EnterCriticalSection(&g_eventQueueCs);
    size_t removed = g_eventQueue.size();
    g_eventQueue.clear();
    g_earliestRetainedSequence = g_currentSequence + 1;
    WakeAllConditionVariable(&g_eventQueueCv);
    LeaveCriticalSection(&g_eventQueueCs);

    sprintf_s(responseBuf, responseBufSize,
              "{\"removed_count\":%zu,\"earliest_retained_sequence\":%llu,\"current_sequence\":%llu,\"success\":true}\n",
              removed,
              (unsigned long long)g_earliestRetainedSequence,
              (unsigned long long)g_currentSequence);
    responseText = responseBuf;
}

// 4. get_event_status
void handle_get_event_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    EnterCriticalSection(&g_eventQueueCs);
    uint64_t curSeq = g_currentSequence;
    uint64_t earliestSeq = g_earliestRetainedSequence;
    size_t queued = g_eventQueue.size();
    uint64_t dropped = g_droppedCount;
    uint32_t sessId = g_currentSessionId;
    bool isShut = g_isShuttingDown;
    std::string lastType = g_lastEventType;
    LeaveCriticalSection(&g_eventQueueCs);

    sprintf_s(responseBuf, responseBufSize,
              "{\"current_sequence\":%llu,\"earliest_retained_sequence\":%llu,\"queued_count\":%zu,\"max_capacity\":%zu,\"dropped_count\":%llu,\"session_id\":%u,\"is_shutting_down\":%s,\"last_event_type\":\"%s\",\"success\":true}\n",
              (unsigned long long)curSeq,
              (unsigned long long)earliestSeq,
              queued,
              MAX_EVENT_CAPACITY,
              (unsigned long long)dropped,
              sessId,
              isShut ? "true" : "false",
              lastType.c_str());
    responseText = responseBuf;
}

// ---------------------------------------------------------------------------
// Phase 25 Named Pipe Dispatcher
// ---------------------------------------------------------------------------
bool dispatch_commands_phase25(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "get_debug_events") == 0)
    {
        handle_get_debug_events(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "wait_for_debug_event") == 0)
    {
        handle_wait_for_debug_event(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_debug_events") == 0)
    {
        handle_clear_debug_events(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_event_status") == 0)
    {
        handle_get_event_status(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}
