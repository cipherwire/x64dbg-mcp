#include "call_stack.h"

void handle_get_call_stack(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_call_stack: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] get_call_stack: debuggee is running.\n");
        responseText = "{\"error\":\"debuggee is running; call stack only available when paused\"}\n";
    }
    else
    {
        DWORD activeThreadId = 0;
        THREADLIST threadList = { 0 };
        DbgGetThreadList(&threadList);
        if (threadList.list != nullptr && threadList.count > 0)
        {
            if (threadList.CurrentThread >= 0 && threadList.CurrentThread < threadList.count)
            {
                activeThreadId = (DWORD)threadList.list[threadList.CurrentThread].BasicInfo.ThreadId;
            }
        }
        if (threadList.list != nullptr)
        {
            BridgeFree(threadList.list);
            threadList.list = nullptr;
        }

        struct CallStackGuard
        {
            DBGCALLSTACK cs = { 0, nullptr };
            ~CallStackGuard()
            {
                if (cs.entries != nullptr)
                {
                    BridgeFree(cs.entries);
                    cs.entries = nullptr;
                }
            }
        } guard;

        DbgFunctions()->GetCallStackEx(&guard.cs, false);

        int count = guard.cs.total;
        if (count < 0) count = 0;

        int offset = sprintf_s(responseBuf, responseBufSize,
                               "{\"thread_id\":%u,\"count\":%d,\"frames\":[",
                               (unsigned int)activeThreadId, count);

        for (int i = 0; i < count && offset < (int)responseBufSize - 1024; i++)
        {
            char safeComment[MAX_COMMENT_SIZE * 2] = { 0 };
            escape_json_string(guard.cs.entries[i].comment, safeComment, sizeof(safeComment));

            offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                                "%s{\"index\":%d,\"address\":\"0x%016llX\",\"from\":\"0x%016llX\",\"to\":\"0x%016llX\",\"comment\":\"%s\"}",
                                (i > 0 ? "," : ""),
                                i,
                                (unsigned long long)guard.cs.entries[i].addr,
                                (unsigned long long)guard.cs.entries[i].from,
                                (unsigned long long)guard.cs.entries[i].to,
                                safeComment);
        }

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
        responseText = responseBuf;

        _plugin_logprintf("[x64dbg-MCP] get_call_stack: %d frames returned for active thread %u.\n",
                          count, (unsigned int)activeThreadId);
    }
}

void handle_get_thread_call_stack(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_thread_call_stack: no debuggee active.\n");
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] get_thread_call_stack: debuggee is running.\n");
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is running; call stack only available when paused\"}}\n";
        return;
    }

    int tidInt = 0;
    if (!json_get_int(readBuf, "thread_id", &tidInt) || tidInt <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or invalid thread_id\"}}\n";
        return;
    }

    DWORD targetTid = (DWORD)tidInt;

    THREADLIST threadList = { 0 };
    DbgGetThreadList(&threadList);

    HANDLE hThread = NULL;
    bool found = false;
    if (threadList.list != nullptr && threadList.count > 0)
    {
        for (int i = 0; i < threadList.count; i++)
        {
            if (threadList.list[i].BasicInfo.ThreadId == targetTid)
            {
                hThread = threadList.list[i].BasicInfo.Handle;
                found = true;
                break;
            }
        }
    }

    if (threadList.list != nullptr)
    {
        BridgeFree(threadList.list);
        threadList.list = nullptr;
    }

    if (!found)
    {
        responseText = "{\"error\":{\"code\":\"thread_not_found\",\"message\":\"Thread not found or thread has exited\"}}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetCallStackByThread == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"GetCallStackByThread API not available\"}}\n";
        return;
    }

    struct ThreadCallStackGuard
    {
        DBGCALLSTACK cs = { 0, nullptr };
        ~ThreadCallStackGuard()
        {
            if (cs.entries != nullptr)
            {
                BridgeFree(cs.entries);
                cs.entries = nullptr;
            }
        }
    } guard;

    dbg->GetCallStackByThread(hThread, &guard.cs);

    int count = guard.cs.total;
    if (count < 0) count = 0;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"thread_id\":%u,\"count\":%d,\"frames\":[",
                           (unsigned int)targetTid, count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 1024; i++)
    {
        char safeComment[MAX_COMMENT_SIZE * 2] = { 0 };
        escape_json_string(guard.cs.entries[i].comment, safeComment, sizeof(safeComment));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s{\"index\":%d,\"address\":\"0x%016llX\",\"from\":\"0x%016llX\",\"to\":\"0x%016llX\",\"comment\":\"%s\"}",
                            (i > 0 ? "," : ""),
                            i,
                            (unsigned long long)guard.cs.entries[i].addr,
                            (unsigned long long)guard.cs.entries[i].from,
                            (unsigned long long)guard.cs.entries[i].to,
                            safeComment);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_thread_call_stack: %d frames returned for thread %u.\n",
                      count, (unsigned int)targetTid);
}

void handle_get_seh_chain(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_seh_chain: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] get_seh_chain: debuggee is running.\n");
        responseText = "{\"error\":\"debuggee is running; SEH chain only available when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetSEHChain == nullptr)
    {
        responseText = "{\"error\":\"GetSEHChain API not available\"}\n";
        return;
    }

    struct SEHGuard
    {
        DBGSEHCHAIN sc = { 0, nullptr };
        ~SEHGuard()
        {
            if (sc.records != nullptr)
            {
                BridgeFree(sc.records);
                sc.records = nullptr;
            }
        }
    } guard;

    dbg->GetSEHChain(&guard.sc);

    duint count = guard.sc.total;
    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%llu,\"records\":[",
                           (unsigned long long)count);

    for (duint i = 0; i < count && offset < (int)responseBufSize - 1024; i++)
    {
        duint handlerAddr = guard.sc.records[i].handler;
        char modName[MAX_MODULE_SIZE] = { 0 };
        char labelName[MAX_LABEL_SIZE] = { 0 };

        DbgGetModuleAt(handlerAddr, modName);
        DbgGetLabelAt(handlerAddr, SEG_DEFAULT, labelName);

        char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(modName, safeMod, sizeof(safeMod));

        char safeLabel[MAX_LABEL_SIZE * 2] = { 0 };
        escape_json_string(labelName, safeLabel, sizeof(safeLabel));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s{\"address\":\"0x%016llX\",\"handler\":\"0x%016llX\",\"module\":\"%s\",\"label\":\"%s\"}",
                            (i > 0 ? "," : ""),
                            (unsigned long long)guard.sc.records[i].addr,
                            (unsigned long long)handlerAddr,
                            safeMod,
                            safeLabel);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_seh_chain: %llu records returned.\n", (unsigned long long)count);
}
