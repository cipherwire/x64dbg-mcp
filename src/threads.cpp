#include "threads.h"

const char* thread_priority_string(THREADPRIORITY priority)
{
    switch (priority)
    {
    case _PriorityIdle: return "idle";
    case _PriorityLowest: return "lowest";
    case _PriorityBelowNormal: return "below_normal";
    case _PriorityNormal: return "normal";
    case _PriorityAboveNormal: return "above_normal";
    case _PriorityHighest: return "highest";
    case _PriorityTimeCritical: return "time_critical";
    default: return "unknown";
    }
}

const char* thread_wait_reason_string(THREADWAITREASON reason)
{
    switch (reason)
    {
    case _Executive: return "executive";
    case _FreePage: return "free_page";
    case _PageIn: return "page_in";
    case _PoolAllocation: return "pool_allocation";
    case _DelayExecution: return "delay_execution";
    case _Suspended: return "suspended";
    case _UserRequest: return "user_request";
    case _WrExecutive: return "wr_executive";
    case _WrFreePage: return "wr_free_page";
    case _WrPageIn: return "wr_page_in";
    case _WrPoolAllocation: return "wr_pool_allocation";
    case _WrDelayExecution: return "wr_delay_execution";
    case _WrSuspended: return "wr_suspended";
    case _WrUserRequest: return "wr_user_request";
    case _WrEventPair: return "wr_event_pair";
    case _WrQueue: return "wr_queue";
    case _WrLpcReceive: return "wr_lpc_receive";
    case _WrLpcReply: return "wr_lpc_reply";
    case _WrVirtualMemory: return "wr_virtual_memory";
    case _WrPageOut: return "wr_page_out";
    case _WrRendezvous: return "wr_rendezvous";
    default: return "unknown";
    }
}

void handle_list_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] list_threads: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        THREADLIST threadList = { 0 };
        DbgGetThreadList(&threadList);

        DWORD activeThreadId = DbgGetThreadId();

        int offset = sprintf_s(responseBuf, responseBufSize,
                               "{\"count\":%d,\"active_thread_id\":%u,\"threads\":[",
                               threadList.count,
                               (unsigned int)activeThreadId);

        for (int i = 0; i < threadList.count && offset < (int)responseBufSize - 512; i++)
        {
            bool isActive = (i == threadList.CurrentThread);

            char safeName[MAX_THREAD_NAME_SIZE * 2] = { 0 };
            escape_json_string(threadList.list[i].BasicInfo.threadName, safeName, sizeof(safeName));

            const char* prioStr = thread_priority_string(threadList.list[i].Priority);
            const char* waitStr = thread_wait_reason_string(threadList.list[i].WaitReason);

            offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                "%s{\"thread_number\":%d,\"thread_id\":%u,\"is_active\":%s,"
                "\"start_address\":\"0x%016llX\",\"teb\":\"0x%016llX\",\"cip\":\"0x%016llX\","
                "\"suspend_count\":%u,\"priority\":\"%s\",\"wait_reason\":\"%s\","
                "\"last_error\":%u,\"name\":\"%s\"}",
                (i > 0 ? "," : ""),
                threadList.list[i].BasicInfo.ThreadNumber,
                (unsigned int)threadList.list[i].BasicInfo.ThreadId,
                isActive ? "true" : "false",
                (unsigned long long)threadList.list[i].BasicInfo.ThreadStartAddress,
                (unsigned long long)threadList.list[i].BasicInfo.ThreadLocalBase,
                (unsigned long long)threadList.list[i].ThreadCip,
                (unsigned int)threadList.list[i].SuspendCount,
                prioStr,
                waitStr,
                (unsigned int)threadList.list[i].LastError,
                safeName);
        }

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
        responseText = responseBuf;

        if (threadList.list != nullptr)
        {
            BridgeFree(threadList.list);
            threadList.list = nullptr;
        }

        _plugin_logprintf("[x64dbg-MCP] Listed %d threads (active index: %d, active TID: %u).\n",
                          threadList.count, threadList.CurrentThread, (unsigned int)activeThreadId);
    }
}

void handle_switch_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;
    bool isExecActive = (InterlockedCompareExchange(&g_execActive, 0, 0) != 0);

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] switch_thread: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning || isExecActive)
    {
        _plugin_logprintf("[x64dbg-MCP] switch_thread: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        int parsedTid = 0;
        if (!json_get_int(readBuf, "thread_id", &parsedTid) || parsedTid <= 0)
        {
            responseText = "{\"error\":\"invalid thread_id: must be a positive integer\"}\n";
        }
        else
        {
            DWORD targetTid = (DWORD)parsedTid;

            THREADLIST threadList = { 0 };
            DbgGetThreadList(&threadList);

            bool threadFound = false;
            bool isAlreadyActive = false;
            DWORD previousActiveTid = 0;

            if (threadList.list != nullptr && threadList.count > 0)
            {
                if (threadList.CurrentThread >= 0 && threadList.CurrentThread < threadList.count)
                {
                    previousActiveTid = (DWORD)threadList.list[threadList.CurrentThread].BasicInfo.ThreadId;
                }

                for (int i = 0; i < threadList.count; i++)
                {
                    if (threadList.list[i].BasicInfo.ThreadId == targetTid)
                    {
                        threadFound = true;
                        if (i == threadList.CurrentThread)
                        {
                            isAlreadyActive = true;
                        }
                        break;
                    }
                }
            }

            if (threadList.list != nullptr)
            {
                BridgeFree(threadList.list);
                threadList.list = nullptr;
            }

            if (!threadFound)
            {
                _plugin_logprintf("[x64dbg-MCP] switch_thread: thread %u not found.\n", (unsigned int)targetTid);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"thread not found\",\"thread_id\":%u}\n", (unsigned int)targetTid);
                responseText = responseBuf;
            }
            else if (isAlreadyActive)
            {
                _plugin_logprintf("[x64dbg-MCP] switch_thread: thread %u is already active.\n", (unsigned int)targetTid);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"status\":\"already_active\",\"thread_id\":%u}\n", (unsigned int)targetTid);
                responseText = responseBuf;
            }
            else
            {
                char switchCmd[64] = { 0 };
                sprintf_s(switchCmd, sizeof(switchCmd), "switchthread 0x%X", (unsigned int)targetTid);
                bool cmdOk = DbgCmdExecDirect(switchCmd);

                _plugin_logprintf("[x64dbg-MCP] switch_thread: DbgCmdExecDirect('%s') returned %s (isRunning=%s).\n",
                                  switchCmd, cmdOk ? "true" : "false", isRunning ? "true" : "false");

                DWORD postActiveTid = 0;
                duint postCip = 0;

                for (int attempt = 0; attempt < 10; attempt++)
                {
                    THREADLIST postList = { 0 };
                    DbgGetThreadList(&postList);

                    if (postList.list != nullptr && postList.count > 0)
                    {
                        if (postList.CurrentThread >= 0 && postList.CurrentThread < postList.count)
                        {
                            postActiveTid = (DWORD)postList.list[postList.CurrentThread].BasicInfo.ThreadId;
                            postCip = postList.list[postList.CurrentThread].ThreadCip;
                        }
                        BridgeFree(postList.list);
                        postList.list = nullptr;
                    }

                    if (postActiveTid == targetTid)
                    {
                        break;
                    }
                    Sleep(10);
                }

                _plugin_logprintf("[x64dbg-MCP] switch_thread: postList.CurrentThread active TID=%u (target was %u).\n",
                                  (unsigned int)postActiveTid, (unsigned int)targetTid);

                if (postActiveTid == targetTid)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"thread_switched\",\"thread_id\":%u,\"previous_thread_id\":%u,\"rip\":\"0x%016llX\"}\n",
                              (unsigned int)targetTid,
                              (unsigned int)previousActiveTid,
                              (unsigned long long)postCip);
                    responseText = responseBuf;
                }
                else
                {
                    _plugin_logprintf("[x64dbg-MCP] switch_thread: authoritative state did not switch to %u (remained %u).\n",
                                      (unsigned int)targetTid, (unsigned int)postActiveTid);
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"error\":\"failed to switch active thread in x64dbg\",\"thread_id\":%u,\"actual_active_thread_id\":%u}\n",
                              (unsigned int)targetTid, (unsigned int)postActiveTid);
                    responseText = responseBuf;
                }
            }
        }
    }
}

// -------------------------------------------------------------
// Phase 31: Thread Metadata & Priority Control
// -------------------------------------------------------------

static const char* PriorityIntToString(int priority)
{
    switch (priority)
    {
    case -15: return "Idle";
    case -2:  return "Lowest";
    case -1:  return "BelowNormal";
    case 0:   return "Normal";
    case 1:   return "AboveNormal";
    case 2:   return "Highest";
    case 15:  return "TimeCritical";
    default:  return "Unknown";
    }
}

static bool ParseThreadPriorityInput(const char* readBuf, int& outPriorityVal, std::string& outPriorityName)
{
    int pVal = 0;
    if (json_get_int(readBuf, "priority", &pVal))
    {
        switch (pVal)
        {
        case -15: case -2: case -1: case 0: case 1: case 2: case 15:
            outPriorityVal = pVal;
            outPriorityName = PriorityIntToString(pVal);
            return true;
        default:
            return false;
        }
    }
    char pStr[64] = { 0 };
    if (json_get_string(readBuf, "priority", pStr, sizeof(pStr)) && pStr[0] != '\0')
    {
        if (_stricmp(pStr, "Normal") == 0) { outPriorityVal = 0; outPriorityName = "Normal"; return true; }
        if (_stricmp(pStr, "AboveNormal") == 0) { outPriorityVal = 1; outPriorityName = "AboveNormal"; return true; }
        if (_stricmp(pStr, "TimeCritical") == 0) { outPriorityVal = 15; outPriorityName = "TimeCritical"; return true; }
        if (_stricmp(pStr, "Idle") == 0) { outPriorityVal = -15; outPriorityName = "Idle"; return true; }
        if (_stricmp(pStr, "BelowNormal") == 0) { outPriorityVal = -1; outPriorityName = "BelowNormal"; return true; }
        if (_stricmp(pStr, "Highest") == 0) { outPriorityVal = 2; outPriorityName = "Highest"; return true; }
        if (_stricmp(pStr, "Lowest") == 0) { outPriorityVal = -2; outPriorityName = "Lowest"; return true; }

        char* endPtr = nullptr;
        long num = strtol(pStr, &endPtr, 10);
        if (endPtr != pStr && *endPtr == '\0')
        {
            switch (num)
            {
            case -15: case -2: case -1: case 0: case 1: case 2: case 15:
                outPriorityVal = (int)num;
                outPriorityName = PriorityIntToString((int)num);
                return true;
            default:
                return false;
            }
        }
    }
    return false;
}

static bool FindThreadById(DWORD tid, THREADALLINFO* outInfo)
{
    THREADLIST threadList = { 0 };
    DbgGetThreadList(&threadList);
    bool found = false;
    if (threadList.list != nullptr)
    {
        for (int i = 0; i < threadList.count; i++)
        {
            if (threadList.list[i].BasicInfo.ThreadId == tid)
            {
                if (outInfo)
                    *outInfo = threadList.list[i];
                found = true;
                break;
            }
        }
        BridgeFree(threadList.list);
    }
    return found;
}

void handle_get_thread_name(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"No active debug session\"}}\n";
        return;
    }

    int tidInt = 0;
    DWORD tid = 0;
    if (json_get_int(readBuf, "thread_id", &tidInt) && tidInt > 0)
    {
        tid = (DWORD)tidInt;
    }
    else
    {
        char tidStr[32] = { 0 };
        if (json_get_string(readBuf, "thread_id", tidStr, sizeof(tidStr)) && tidStr[0] != '\0')
        {
            tid = (DWORD)strtoul(tidStr, nullptr, 0);
        }
    }

    if (tid == 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or invalid 'thread_id'\"}}\n";
        return;
    }

    char nameBuf[MAX_THREAD_NAME_SIZE] = { 0 };
    if (!DbgFunctions()->ThreadGetName(tid, nameBuf))
    {
        // Check if thread exists at all
        if (!FindThreadById(tid, nullptr))
        {
            responseText = "{\"error\":{\"code\":\"thread_not_found\",\"message\":\"Thread not found in debuggee\"}}\n";
            return;
        }
    }

    char safeName[MAX_THREAD_NAME_SIZE * 2] = { 0 };
    escape_json_string(nameBuf, safeName, sizeof(safeName));

    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"name\":\"%s\",\"success\":true}\n",
              (unsigned int)tid, safeName);
    responseText = responseBuf;
}

void handle_set_thread_name(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"No active debug session\"}}\n";
        return;
    }

    int tidInt = 0;
    DWORD tid = 0;
    if (json_get_int(readBuf, "thread_id", &tidInt) && tidInt > 0)
    {
        tid = (DWORD)tidInt;
    }
    else
    {
        char tidStr[32] = { 0 };
        if (json_get_string(readBuf, "thread_id", tidStr, sizeof(tidStr)) && tidStr[0] != '\0')
        {
            tid = (DWORD)strtoul(tidStr, nullptr, 0);
        }
    }

    if (tid == 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or invalid 'thread_id'\"}}\n";
        return;
    }

    if (!FindThreadById(tid, nullptr))
    {
        responseText = "{\"error\":{\"code\":\"thread_not_found\",\"message\":\"Thread not found in debuggee\"}}\n";
        return;
    }

    char nameStr[MAX_THREAD_NAME_SIZE] = { 0 };
    json_get_string(readBuf, "name", nameStr, sizeof(nameStr));

    char cmd[512];
    if (nameStr[0] == '\0')
    {
        sprintf_s(cmd, sizeof(cmd), "setthreadname 0x%X", (unsigned int)tid);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "setthreadname 0x%X, \"%s\"", (unsigned int)tid, nameStr);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"setthreadname command failed\"}}\n";
        return;
    }

    char readback[MAX_THREAD_NAME_SIZE] = { 0 };
    DbgFunctions()->ThreadGetName(tid, readback);

    char safeName[MAX_THREAD_NAME_SIZE * 2] = { 0 };
    escape_json_string(readback, safeName, sizeof(safeName));

    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"name\":\"%s\",\"success\":true}\n",
              (unsigned int)tid, safeName);
    responseText = responseBuf;
}

void handle_set_thread_priority(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"No active debug session\"}}\n";
        return;
    }

    int tidInt = 0;
    DWORD tid = 0;
    if (json_get_int(readBuf, "thread_id", &tidInt) && tidInt > 0)
    {
        tid = (DWORD)tidInt;
    }
    else
    {
        char tidStr[32] = { 0 };
        if (json_get_string(readBuf, "thread_id", tidStr, sizeof(tidStr)) && tidStr[0] != '\0')
        {
            tid = (DWORD)strtoul(tidStr, nullptr, 0);
        }
    }

    if (tid == 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or invalid 'thread_id'\"}}\n";
        return;
    }

    if (!FindThreadById(tid, nullptr))
    {
        responseText = "{\"error\":{\"code\":\"thread_not_found\",\"message\":\"Thread not found in debuggee\"}}\n";
        return;
    }

    int pVal = 0;
    std::string pName;
    if (!ParseThreadPriorityInput(readBuf, pVal, pName))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Unknown or invalid priority value; expected Normal, AboveNormal, TimeCritical, Idle, BelowNormal, Highest, Lowest, or integer (-15, -2, -1, 0, 1, 2, 15)\"}}\n";
        return;
    }

    char cmd[256];
    sprintf_s(cmd, sizeof(cmd), "setthreadpriority 0x%X, %s", (unsigned int)tid, pName.c_str());

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"setthreadpriority command failed\"}}\n";
        return;
    }

    THREADALLINFO info = { 0 };
    if (FindThreadById(tid, &info))
    {
        const char* actualName = thread_priority_string(info.Priority);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"thread_id\":%u,\"priority\":\"%s\",\"priority_value\":%d,\"success\":true}\n",
                  (unsigned int)tid, actualName, (int)info.Priority);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"thread_id\":%u,\"priority\":\"%s\",\"priority_value\":%d,\"success\":true}\n",
                  (unsigned int)tid, pName.c_str(), pVal);
    }
    responseText = responseBuf;
}

void handle_get_thread_priority(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"No active debug session\"}}\n";
        return;
    }

    int tidInt = 0;
    DWORD tid = 0;
    if (json_get_int(readBuf, "thread_id", &tidInt) && tidInt > 0)
    {
        tid = (DWORD)tidInt;
    }
    else
    {
        char tidStr[32] = { 0 };
        if (json_get_string(readBuf, "thread_id", tidStr, sizeof(tidStr)) && tidStr[0] != '\0')
        {
            tid = (DWORD)strtoul(tidStr, nullptr, 0);
        }
    }

    if (tid == 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or invalid 'thread_id'\"}}\n";
        return;
    }

    THREADALLINFO info = { 0 };
    if (!FindThreadById(tid, &info))
    {
        responseText = "{\"error\":{\"code\":\"thread_not_found\",\"message\":\"Thread not found in debuggee\"}}\n";
        return;
    }

    const char* pName = thread_priority_string(info.Priority);
    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"priority\":\"%s\",\"priority_value\":%d,\"success\":true}\n",
              (unsigned int)tid, pName, (int)info.Priority);
    responseText = responseBuf;
}

