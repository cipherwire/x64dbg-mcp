#include "execution.h"

void handle_get_debugger_state(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    _plugin_logprintf("[x64dbg-MCP] State query: debugging=%s, running=%s\n",
                      isDebugging ? "true" : "false",
                      isRunning ? "true" : "false");
    log_lifecycle("[x64dbg-MCP] get_debugger_state called.\n");

    sprintf_s(responseBuf, responseBufSize,
              "{\"is_debugging\":%s,\"is_running\":%s}\n",
              isDebugging ? "true" : "false",
              isRunning ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_bridge_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"connected\":true,\"state\":\"no_debuggee\",\"is_debugging\":false,\"is_running\":false}\n");
        responseText = responseBuf;
        return;
    }

    DWORD pid = DbgGetProcessId();
    DWORD tid = DbgGetThreadId();

    if (isRunning)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"connected\":true,\"state\":\"running\",\"is_debugging\":true,\"is_running\":true,\"pid\":%lu,\"tid\":%lu}\n",
                  pid, tid);
        responseText = responseBuf;
        return;
    }

    duint curRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        curRip = regDump.regcontext.cip;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"connected\":true,\"state\":\"paused\",\"is_debugging\":true,\"is_running\":false,\"stop_address\":\"0x%016llX\",\"pid\":%lu,\"tid\":%lu}\n",
              (unsigned long long)curRip, pid, tid);
    responseText = responseBuf;
}

void handle_step_into(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] step_into: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] step_into: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        _plugin_logprintf("[x64dbg-MCP] step_into: another execution command is already in progress.\n");
        responseText = "{\"error\":\"another execution control command is already in progress\"}\n";
    }
    else
    {
        int timeoutMs = 5000;
        json_get_int(readBuf, "timeout_ms", &timeoutMs);
        if (timeoutMs < 100) timeoutMs = 100;
        if (timeoutMs > 30000) timeoutMs = 30000;

        duint beforeRip = 0;
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            beforeRip = regDump.regcontext.cip;
        }

        ResetEvent(g_hExecEvent);
        InterlockedExchange(&g_lastStopReason, STOP_NONE);
        g_lastBpAddr = 0;
        g_lastExceptionCode = 0;

        bool cmdOk = DbgCmdExecDirect("StepInto");
        if (!cmdOk)
        {
            InterlockedExchange(&g_execActive, 0);
            _plugin_logprintf("[x64dbg-MCP] StepInto command rejected by x64dbg.\n");
            responseText = "{\"error\":\"StepInto command rejected by x64dbg\"}\n";
        }
        else
        {
            HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
            DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

            InterlockedExchange(&g_execActive, 0);

            if (waitRes == WAIT_OBJECT_0)
            {
                _plugin_logprintf("[x64dbg-MCP] Step cancelled due to shutdown.\n");
                responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
            }
            else if (waitRes == WAIT_OBJECT_0 + 1)
            {
                bool isDbg = DbgIsDebugging();
                bool isRun = isDbg ? DbgIsRunning() : false;

                for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
                {
                    Sleep(5);
                    isRun = DbgIsRunning();
                }

                LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);

                duint afterRip = 0;
                char safeInstr[128] = { 0 };
                if (isDbg && !isRun)
                {
                    REGDUMP_AVX512 postDump = { 0 };
                    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                    {
                        afterRip = postDump.regcontext.cip;
                    }
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(afterRip, &instr);
                    escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                }

                if (reason == STOP_STEP_COMPLETED || reason == STOP_PAUSED)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"step_completed\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_BREAKPOINT_HIT)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"breakpoint_hit\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"breakpoint_address\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              (unsigned long long)g_lastBpAddr,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_EXCEPTION)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"exception\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"exception_code\":\"0x%08X\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              (unsigned int)g_lastExceptionCode,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging())
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"process_exited\",\"before_rip\":\"0x%016llX\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"paused\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_TIMEOUT)
            {
                if (DbgIsDebugging() && DbgIsRunning())
                {
                    _plugin_logprintf("[x64dbg-MCP] step_into timed out while target running; pausing to reconcile state.\n");
                    DbgCmdExec("pause");
                    HANDLE hProc = DbgGetProcessHandle();
                    if (hProc != nullptr)
                    {
                        DebugBreakProcess(hProc);
                    }
                    WaitForSingleObject(g_hExecEvent, 1000);
                }

                bool stillRunning = DbgIsDebugging() && DbgIsRunning();
                if (stillRunning)
                {
                    _plugin_logprintf("[x64dbg-MCP] StepInto timed out and target remains running. Retaining exec lock.\n");
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":true,\"before_rip\":\"0x%016llX\",\"error\":\"timed out waiting for step to complete; debuggee remains running\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    InterlockedExchange(&g_execActive, 0);
                    duint afterRip = 0;
                    char safeInstr[128] = { 0 };
                    if (DbgIsDebugging())
                    {
                        REGDUMP_AVX512 postDump = { 0 };
                        if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                        {
                            afterRip = postDump.regcontext.cip;
                        }
                        DISASM_INSTR instr = { 0 };
                        DbgDisasmAt(afterRip, &instr);
                        escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                    }
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":false,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\",\"error\":\"timed out waiting for step to complete; debuggee was paused\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_FAILED)
            {
                DWORD waitErr = GetLastError();
                InterlockedExchange(&g_execActive, 0);
                _plugin_logprintf("[x64dbg-MCP] WaitForMultipleObjects failed (Win32 error %u).\n", waitErr);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"wait failed\",\"win32_error\":%u}\n", (unsigned int)waitErr);
                responseText = responseBuf;
            }
        }
    }
}

void handle_step_over(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] step_over: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] step_over: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        _plugin_logprintf("[x64dbg-MCP] step_over: another execution command is already in progress.\n");
        responseText = "{\"error\":\"another execution control command is already in progress\"}\n";
    }
    else
    {
        int timeoutMs = 5000;
        json_get_int(readBuf, "timeout_ms", &timeoutMs);
        if (timeoutMs < 100) timeoutMs = 100;
        if (timeoutMs > 30000) timeoutMs = 30000;

        duint beforeRip = 0;
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            beforeRip = regDump.regcontext.cip;
        }

        DISASM_INSTR beforeInstr = { 0 };
        DbgDisasmAt(beforeRip, &beforeInstr);
        char safeBeforeInstr[128] = { 0 };
        escape_json_string(beforeInstr.instruction, safeBeforeInstr, sizeof(safeBeforeInstr));

        ResetEvent(g_hExecEvent);
        InterlockedExchange(&g_lastStopReason, STOP_NONE);
        g_lastBpAddr = 0;
        g_lastExceptionCode = 0;

        bool cmdOk = DbgCmdExecDirect("StepOver");
        if (!cmdOk)
        {
            InterlockedExchange(&g_execActive, 0);
            _plugin_logprintf("[x64dbg-MCP] StepOver command rejected by x64dbg.\n");
            responseText = "{\"error\":\"StepOver command rejected by x64dbg\"}\n";
        }
        else
        {
            HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
            DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

            if (waitRes == WAIT_OBJECT_0)
            {
                InterlockedExchange(&g_execActive, 0);
                _plugin_logprintf("[x64dbg-MCP] StepOver cancelled due to shutdown.\n");
                responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
            }
            else if (waitRes == WAIT_OBJECT_0 + 1)
            {
                InterlockedExchange(&g_execActive, 0);

                bool isDbg = DbgIsDebugging();
                bool isRun = isDbg ? DbgIsRunning() : false;

                for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
                {
                    Sleep(5);
                    isRun = DbgIsRunning();
                }

                LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);

                duint afterRip = 0;
                char safeInstr[128] = { 0 };
                if (isDbg && !isRun)
                {
                    REGDUMP_AVX512 postDump = { 0 };
                    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                    {
                        afterRip = postDump.regcontext.cip;
                    }
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(afterRip, &instr);
                    escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                }

                if (reason == STOP_STEP_COMPLETED || reason == STOP_PAUSED)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"step_completed\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_BREAKPOINT_HIT)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"breakpoint_hit\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"breakpoint_address\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              (unsigned long long)g_lastBpAddr,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_EXCEPTION)
                {
                    if (isDbg && !isRun)
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"exception\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"exception_code\":\"0x%08X\",\"instruction\":\"%s\"}\n",
                                  (unsigned long long)beforeRip,
                                  (unsigned long long)afterRip,
                                  (unsigned int)g_lastExceptionCode,
                                  safeInstr);
                        responseText = responseBuf;
                    }
                    else
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"running\",\"before_rip\":\"0x%016llX\"}\n",
                                  (unsigned long long)beforeRip);
                        responseText = responseBuf;
                    }
                }
                else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !isDbg)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"process_exited\",\"before_rip\":\"0x%016llX\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"paused\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_TIMEOUT)
            {
                if (DbgIsDebugging() && DbgIsRunning())
                {
                    _plugin_logprintf("[x64dbg-MCP] step_over timed out while target running; pausing to reconcile state.\n");
                    DbgCmdExec("pause");
                    HANDLE hProc = DbgGetProcessHandle();
                    if (hProc != nullptr)
                    {
                        DebugBreakProcess(hProc);
                    }
                    WaitForSingleObject(g_hExecEvent, 1000);
                }

                bool stillRunning = DbgIsDebugging() && DbgIsRunning();
                if (stillRunning)
                {
                    _plugin_logprintf("[x64dbg-MCP] StepOver timed out and target remains running. Retaining exec lock.\n");
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":true,\"before_rip\":\"0x%016llX\",\"error\":\"timed out waiting for step to complete; debuggee remains running\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    InterlockedExchange(&g_execActive, 0);
                    duint afterRip = 0;
                    char safeInstr[128] = { 0 };
                    if (DbgIsDebugging())
                    {
                        REGDUMP_AVX512 postDump = { 0 };
                        if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                        {
                            afterRip = postDump.regcontext.cip;
                        }
                        DISASM_INSTR instr = { 0 };
                        DbgDisasmAt(afterRip, &instr);
                        escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                    }
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":false,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\",\"error\":\"timed out waiting for step to complete; debuggee was paused\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_FAILED)
            {
                DWORD waitErr = GetLastError();
                InterlockedExchange(&g_execActive, 0);
                _plugin_logprintf("[x64dbg-MCP] WaitForMultipleObjects failed (Win32 error %u).\n", waitErr);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"wait failed\",\"win32_error\":%u}\n", (unsigned int)waitErr);
                responseText = responseBuf;
            }
        }
    }
}

void handle_step_out(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] step_out: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] step_out: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        _plugin_logprintf("[x64dbg-MCP] step_out: another execution command is already in progress.\n");
        responseText = "{\"error\":\"another execution control command is already in progress\"}\n";
    }
    else
    {
        int timeoutMs = 5000;
        json_get_int(readBuf, "timeout_ms", &timeoutMs);
        if (timeoutMs < 100) timeoutMs = 100;
        if (timeoutMs > 30000) timeoutMs = 30000;

        duint beforeRip = 0;
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            beforeRip = regDump.regcontext.cip;
        }

        DISASM_INSTR beforeInstr = { 0 };
        DbgDisasmAt(beforeRip, &beforeInstr);
        char safeBeforeInstr[128] = { 0 };
        escape_json_string(beforeInstr.instruction, safeBeforeInstr, sizeof(safeBeforeInstr));

        ResetEvent(g_hExecEvent);
        InterlockedExchange(&g_lastStopReason, STOP_NONE);
        g_lastBpAddr = 0;
        g_lastExceptionCode = 0;

        bool cmdOk = DbgCmdExecDirect("StepOut");
        if (!cmdOk)
        {
            InterlockedExchange(&g_execActive, 0);
            _plugin_logprintf("[x64dbg-MCP] StepOut command rejected by x64dbg.\n");
            responseText = "{\"error\":\"StepOut command rejected by x64dbg\"}\n";
        }
        else
        {
            HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
            DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

            if (waitRes == WAIT_OBJECT_0)
            {
                InterlockedExchange(&g_execActive, 0);
                _plugin_logprintf("[x64dbg-MCP] StepOut cancelled due to shutdown.\n");
                responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
            }
            else if (waitRes == WAIT_OBJECT_0 + 1)
            {
                InterlockedExchange(&g_execActive, 0);

                bool isDbg = DbgIsDebugging();
                bool isRun = isDbg ? DbgIsRunning() : false;

                for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
                {
                    Sleep(5);
                    isRun = DbgIsRunning();
                }

                LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);

                duint afterRip = 0;
                char safeInstr[128] = { 0 };
                if (isDbg && !isRun)
                {
                    REGDUMP_AVX512 postDump = { 0 };
                    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                    {
                        afterRip = postDump.regcontext.cip;
                    }
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(afterRip, &instr);
                    escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                }

                if (reason == STOP_STEP_COMPLETED || reason == STOP_PAUSED)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"step_completed\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_BREAKPOINT_HIT)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"breakpoint_hit\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"breakpoint_address\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              (unsigned long long)g_lastBpAddr,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (reason == STOP_EXCEPTION)
                {
                    if (isDbg && !isRun)
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"exception\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"exception_code\":\"0x%08X\",\"instruction\":\"%s\"}\n",
                                  (unsigned long long)beforeRip,
                                  (unsigned long long)afterRip,
                                  (unsigned int)g_lastExceptionCode,
                                  safeInstr);
                        responseText = responseBuf;
                    }
                    else
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"running\",\"before_rip\":\"0x%016llX\"}\n",
                                  (unsigned long long)beforeRip);
                        responseText = responseBuf;
                    }
                }
                else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !isDbg)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"process_exited\",\"before_rip\":\"0x%016llX\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"paused\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_TIMEOUT)
            {
                if (DbgIsDebugging() && DbgIsRunning())
                {
                    _plugin_logprintf("[x64dbg-MCP] step_out timed out while target running; pausing to reconcile state.\n");
                    DbgCmdExec("pause");
                    HANDLE hProc = DbgGetProcessHandle();
                    if (hProc != nullptr)
                    {
                        DebugBreakProcess(hProc);
                    }
                    WaitForSingleObject(g_hExecEvent, 1000);
                }

                bool stillRunning = DbgIsDebugging() && DbgIsRunning();
                if (stillRunning)
                {
                    _plugin_logprintf("[x64dbg-MCP] StepOut timed out and target remains running. Retaining exec lock.\n");
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":true,\"before_rip\":\"0x%016llX\",\"error\":\"timed out waiting for step_out to complete; debuggee remains running\"}\n",
                              (unsigned long long)beforeRip);
                    responseText = responseBuf;
                }
                else
                {
                    InterlockedExchange(&g_execActive, 0);
                    duint afterRip = 0;
                    char safeInstr[128] = { 0 };
                    if (DbgIsDebugging())
                    {
                        REGDUMP_AVX512 postDump = { 0 };
                        if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                        {
                            afterRip = postDump.regcontext.cip;
                        }
                        DISASM_INSTR instr = { 0 };
                        DbgDisasmAt(afterRip, &instr);
                        escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
                    }
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":false,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\",\"error\":\"timed out waiting for step_out to complete; debuggee was paused\"}\n",
                              (unsigned long long)beforeRip,
                              (unsigned long long)afterRip,
                              safeInstr);
                    responseText = responseBuf;
                }
            }
            else if (waitRes == WAIT_FAILED)
            {
                DWORD waitErr = GetLastError();
                InterlockedExchange(&g_execActive, 0);
                _plugin_logprintf("[x64dbg-MCP] WaitForMultipleObjects failed (Win32 error %u).\n", waitErr);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"wait failed\",\"win32_error\":%u}\n", (unsigned int)waitErr);
                responseText = responseBuf;
            }
        }
    }
}

void handle_resume(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] resume: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] resume: debuggee is already running.\n");
        responseText = "{\"error\":\"debuggee is already running\"}\n";
    }
    else if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        _plugin_logprintf("[x64dbg-MCP] resume: another execution command is already in progress.\n");
        responseText = "{\"error\":\"another execution control command is already in progress\"}\n";
    }
    else
    {
        int timeoutMs = 5000;
        json_get_int(readBuf, "timeout_ms", &timeoutMs);
        if (timeoutMs < 100) timeoutMs = 100;
        if (timeoutMs > 30000) timeoutMs = 30000;

        ResetEvent(g_hExecEvent);
        InterlockedExchange(&g_lastStopReason, STOP_NONE);
        g_lastBpAddr = 0;
        g_lastExceptionCode = 0;

        bool cmdOk = DbgCmdExecDirect("run");
        if (!cmdOk)
        {
            InterlockedExchange(&g_execActive, 0);
            _plugin_logprintf("[x64dbg-MCP] Run command rejected by x64dbg.\n");
            responseText = "{\"error\":\"Run command rejected by x64dbg\"}\n";
        }
        else
        {
            DWORD settleTimeout = timeoutMs < 100 ? (DWORD)timeoutMs : 100;
            HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
            DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, settleTimeout);

            InterlockedExchange(&g_execActive, 0);

            if (waitRes == WAIT_OBJECT_0)
            {
                _plugin_logprintf("[x64dbg-MCP] Resume cancelled due to shutdown.\n");
                responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
            }
            else
            {
                bool isDbg = DbgIsDebugging();
                bool isRun = isDbg ? DbgIsRunning() : false;

                for (int retry = 0; retry < 10 && isDbg && !isRun && InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE) == STOP_RESUMED; retry++)
                {
                    Sleep(5);
                    isRun = DbgIsRunning();
                }

                if (isDbg && isRun)
                {
                    responseText = "{\"status\":\"running\"}\n";
                }
                else if (isDbg && !isRun)
                {
                    LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
                    duint curRip = 0;
                    char safeInstr[128] = { 0 };
                    REGDUMP_AVX512 postDump = { 0 };
                    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                    {
                        curRip = postDump.regcontext.cip;
                    }
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(curRip, &instr);
                    int dstIdx = 0;
                    for (int s = 0; instr.instruction[s] != '\0' && dstIdx < sizeof(safeInstr) - 2; s++)
                    {
                        if (instr.instruction[s] == '\"' || instr.instruction[s] == '\\')
                        {
                            safeInstr[dstIdx++] = '\\';
                        }
                        safeInstr[dstIdx++] = instr.instruction[s];
                    }

                    if (reason == STOP_BREAKPOINT_HIT)
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"breakpoint_hit\",\"breakpoint_address\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                                  (unsigned long long)g_lastBpAddr,
                                  (unsigned long long)curRip,
                                  safeInstr);
                        responseText = responseBuf;
                    }
                    else if (reason == STOP_EXCEPTION)
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"exception\",\"exception_code\":\"0x%08X\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                                  (unsigned int)g_lastExceptionCode,
                                  (unsigned long long)curRip,
                                  safeInstr);
                        responseText = responseBuf;
                    }
                    else
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"status\":\"paused\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                                  (unsigned long long)curRip,
                                  safeInstr);
                        responseText = responseBuf;
                    }
                }
                else if (!isDbg)
                {
                    LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
                    if (reason == STOP_PROCESS_EXITED)
                    {
                        responseText = "{\"status\":\"process_exited\"}\n";
                    }
                    else
                    {
                        responseText = "{\"status\":\"debugger_stopped\"}\n";
                    }
                }
                else if (waitRes == WAIT_TIMEOUT)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":%s,\"error\":\"timed out waiting for transition\"}\n",
                              isRun ? "true" : "false");
                    responseText = responseBuf;
                }
            }
        }
    }
}

void handle_pause(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] pause: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (!isRunning)
    {
        duint curRip = 0;
        char safeInstr[128] = { 0 };
        REGDUMP_AVX512 postDump = { 0 };
        if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
        {
            curRip = postDump.regcontext.cip;
        }
        DISASM_INSTR instr = { 0 };
        DbgDisasmAt(curRip, &instr);
        int dstIdx = 0;
        for (int s = 0; instr.instruction[s] != '\0' && dstIdx < sizeof(safeInstr) - 2; s++)
        {
            if (instr.instruction[s] == '\"' || instr.instruction[s] == '\\')
            {
                safeInstr[dstIdx++] = '\\';
            }
            safeInstr[dstIdx++] = instr.instruction[s];
        }
        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"already_paused\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                  (unsigned long long)curRip,
                  safeInstr);
        responseText = responseBuf;
    }
    else if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        _plugin_logprintf("[x64dbg-MCP] pause: another execution command is already in progress.\n");
        responseText = "{\"error\":\"another execution control command is already in progress\"}\n";
    }
    else
    {
        int timeoutMs = 5000;
        json_get_int(readBuf, "timeout_ms", &timeoutMs);
        if (timeoutMs < 100) timeoutMs = 100;
        if (timeoutMs > 30000) timeoutMs = 30000;

        ResetEvent(g_hExecEvent);
        InterlockedExchange(&g_lastStopReason, STOP_NONE);

        bool cmdOk = DbgCmdExec("pause");
        HANDLE hProc = DbgGetProcessHandle();
        if (hProc != nullptr)
        {
            DebugBreakProcess(hProc);
        }

        if (!cmdOk)
        {
            InterlockedExchange(&g_execActive, 0);
            _plugin_logprintf("[x64dbg-MCP] Pause command rejected by x64dbg.\n");
            responseText = "{\"error\":\"Pause command rejected by x64dbg\"}\n";
        }
        else
        {
            HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
            DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

            InterlockedExchange(&g_execActive, 0);

            if (waitRes == WAIT_OBJECT_0)
            {
                _plugin_logprintf("[x64dbg-MCP] Pause cancelled due to shutdown.\n");
                responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
            }
            else
            {
                bool isDbg = DbgIsDebugging();
                bool isRun = isDbg ? DbgIsRunning() : false;

                if (isDbg && !isRun)
                {
                    duint curRip = 0;
                    char safeInstr[128] = { 0 };
                    REGDUMP_AVX512 postDump = { 0 };
                    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
                    {
                        curRip = postDump.regcontext.cip;
                    }
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(curRip, &instr);
                    int dstIdx = 0;
                    for (int s = 0; instr.instruction[s] != '\0' && dstIdx < sizeof(safeInstr) - 2; s++)
                    {
                        if (instr.instruction[s] == '\"' || instr.instruction[s] == '\\')
                        {
                            safeInstr[dstIdx++] = '\\';
                        }
                        safeInstr[dstIdx++] = instr.instruction[s];
                    }

                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"paused\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\"}\n",
                              (unsigned long long)curRip,
                              safeInstr);
                    responseText = responseBuf;
                }
                else if (!isDbg)
                {
                    LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
                    if (reason == STOP_PROCESS_EXITED)
                    {
                        responseText = "{\"status\":\"process_exited\"}\n";
                    }
                    else
                    {
                        responseText = "{\"status\":\"debugger_stopped\"}\n";
                    }
                }
                else
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"status\":\"timeout\",\"is_running\":true,\"error\":\"timed out waiting for debugger to pause\"}\n");
                    responseText = responseBuf;
                }
            }
        }
    }
}

void handle_run_to_address(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (isRunning)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing address parameter\"}}\n";
        return;
    }

    duint targetVA = 0;
    if (!resolve_address(addrStr, &targetVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid target address format\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(targetVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Target address is not valid readable memory\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"busy\",\"message\":\"Another execution control command is already in progress\"}}\n";
        return;
    }

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 60000) timeoutMs = 60000;

    duint beforeRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        beforeRip = regDump.regcontext.cip;
    }

    if (beforeRip == targetVA)
    {
        InterlockedExchange(&g_execActive, 0);
        DISASM_INSTR instr = { 0 };
        DbgDisasmAt(beforeRip, &instr);
        char safeInstr[128] = { 0 };
        escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"target_reached\",\"target_reached\":true,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  (unsigned long long)beforeRip,
                  (unsigned long long)beforeRip,
                  (unsigned long long)beforeRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    bool hadUserBp = is_user_breakpoint(targetVA);
    if (!hadUserBp)
    {
        char bpCmd[64];
        sprintf_s(bpCmd, sizeof(bpCmd), "bp %llX, \"\", ss", (unsigned long long)targetVA);
        if (!DbgCmdExecDirect(bpCmd))
        {
            InterlockedExchange(&g_execActive, 0);
            responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to set temporary breakpoint for run_to_address\"}}\n";
            return;
        }
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    bool cmdOk = DbgCmdExecDirect("run");
    if (!cmdOk)
    {
        if (!hadUserBp)
        {
            char bcCmd[64];
            sprintf_s(bcCmd, sizeof(bcCmd), "bc %llX", (unsigned long long)targetVA);
            DbgCmdExecDirect(bcCmd);
        }
        InterlockedExchange(&g_execActive, 0);
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Run command rejected by x64dbg\"}}\n";
        return;
    }

    HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
    DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

    InterlockedExchange(&g_execActive, 0);

    if (!hadUserBp)
    {
        char bcCmd[64];
        sprintf_s(bcCmd, sizeof(bcCmd), "bc %llX", (unsigned long long)targetVA);
        DbgCmdExecDirect(bcCmd);
    }

    if (waitRes == WAIT_OBJECT_0)
    {
        responseText = "{\"status\":\"shutdown\",\"target_reached\":false,\"error\":\"plugin shutdown signaled\"}\n";
        return;
    }

    if (waitRes == WAIT_OBJECT_0 + 1)
    {
        bool isDbg = DbgIsDebugging();
        bool isRun = isDbg ? DbgIsRunning() : false;
        for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
        {
            Sleep(5);
            isRun = DbgIsRunning();
        }

        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);

        duint afterRip = 0;
        char safeInstr[128] = { 0 };
        if (isDbg && !isRun)
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
            {
                afterRip = postDump.regcontext.cip;
            }
            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(afterRip, &instr);
            escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
        }

        bool targetReached = (afterRip == targetVA);
        const char* statusStr = "paused";
        if (targetReached)
        {
            statusStr = "target_reached";
        }
        else if (reason == STOP_BREAKPOINT_HIT)
        {
            statusStr = "breakpoint_hit";
        }
        else if (reason == STOP_EXCEPTION)
        {
            statusStr = "exception";
        }
        else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging())
        {
            statusStr = "process_exited";
        }

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"%s\",\"target_reached\":%s,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  statusStr,
                  targetReached ? "true" : "false",
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  (unsigned long long)afterRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    if (waitRes == WAIT_TIMEOUT)
    {
        if (DbgIsDebugging() && DbgIsRunning())
        {
            DbgCmdExec("pause");
            HANDLE hProc = DbgGetProcessHandle();
            if (hProc != nullptr)
            {
                DebugBreakProcess(hProc);
            }
            WaitForSingleObject(g_hExecEvent, 1000);
        }

        duint afterRip = 0;
        char safeInstr[128] = { 0 };
        if (DbgIsDebugging() && !DbgIsRunning())
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
            {
                afterRip = postDump.regcontext.cip;
            }
            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(afterRip, &instr);
            escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
        }

        bool targetReached = (afterRip == targetVA);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"target_reached\":%s,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":false}\n",
                  targetReached ? "true" : "false",
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"WaitForMultipleObjects failed\"}}\n";
}

void handle_run_to_user_code(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (isRunning)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"busy\",\"message\":\"Another execution control command is already in progress\"}}\n";
        return;
    }

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 60000) timeoutMs = 60000;

    duint beforeRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        beforeRip = regDump.regcontext.cip;
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    bool cmdOk = DbgCmdExecDirect("RunToUserCode");
    if (!cmdOk)
    {
        InterlockedExchange(&g_execActive, 0);
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"RunToUserCode command rejected by x64dbg\"}}\n";
        return;
    }

    HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
    DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

    InterlockedExchange(&g_execActive, 0);

    if (waitRes == WAIT_OBJECT_0)
    {
        responseText = "{\"status\":\"shutdown\",\"user_code_reached\":false,\"error\":\"plugin shutdown signaled\"}\n";
        return;
    }

    if (waitRes == WAIT_OBJECT_0 + 1)
    {
        bool isDbg = DbgIsDebugging();
        bool isRun = isDbg ? DbgIsRunning() : false;
        for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
        {
            Sleep(5);
            isRun = DbgIsRunning();
        }

        duint afterRip = 0;
        char safeInstr[128] = { 0 };
        if (isDbg && !isRun)
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
            {
                afterRip = postDump.regcontext.cip;
            }
            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(afterRip, &instr);
            escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
        }

        const DBGFUNCTIONS* dbg = DbgFunctions();
        duint modBase = dbg ? dbg->ModBaseFromAddr(afterRip) : 0;
        MODULEPARTY party = (dbg && modBase) ? dbg->ModGetParty(modBase) : mod_user;
        bool userCodeReached = (party == mod_user);

        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
        const char* statusStr = userCodeReached ? "user_code_reached" : "paused";
        if (reason == STOP_BREAKPOINT_HIT) statusStr = "breakpoint_hit";
        else if (reason == STOP_EXCEPTION) statusStr = "exception";
        else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging()) statusStr = "process_exited";

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"%s\",\"user_code_reached\":%s,\"party\":%d,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  statusStr,
                  userCodeReached ? "true" : "false",
                  (int)party,
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  (unsigned long long)afterRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    if (waitRes == WAIT_TIMEOUT)
    {
        if (DbgIsDebugging() && DbgIsRunning())
        {
            DbgCmdExec("pause");
            HANDLE hProc = DbgGetProcessHandle();
            if (hProc != nullptr) DebugBreakProcess(hProc);
            WaitForSingleObject(g_hExecEvent, 1000);
        }

        duint afterRip = 0;
        if (DbgIsDebugging() && !DbgIsRunning())
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump))) afterRip = postDump.regcontext.cip;
        }

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"user_code_reached\":false,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"success\":false}\n",
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"WaitForMultipleObjects failed\"}}\n";
}

static void execute_party_step(const char* cmdName, int targetParty, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (isRunning)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"busy\",\"message\":\"Another execution control command is already in progress\"}}\n";
        return;
    }

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 60000) timeoutMs = 60000;

    duint beforeRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        beforeRip = regDump.regcontext.cip;
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    bool cmdOk = DbgCmdExecDirect(cmdName);
    if (!cmdOk)
    {
        InterlockedExchange(&g_execActive, 0);
        sprintf_s(responseBuf, responseBufSize, "{\"error\":{\"code\":\"api_failure\",\"message\":\"%s command rejected by x64dbg\"}}\n", cmdName);
        responseText = responseBuf;
        return;
    }

    HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
    DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

    InterlockedExchange(&g_execActive, 0);

    if (waitRes == WAIT_OBJECT_0)
    {
        responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
        return;
    }

    if (waitRes == WAIT_OBJECT_0 + 1)
    {
        bool isDbg = DbgIsDebugging();
        bool isRun = isDbg ? DbgIsRunning() : false;
        for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
        {
            Sleep(5);
            isRun = DbgIsRunning();
        }

        duint afterRip = 0;
        char safeInstr[128] = { 0 };
        if (isDbg && !isRun)
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
            {
                afterRip = postDump.regcontext.cip;
            }
            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(afterRip, &instr);
            escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
        }

        const DBGFUNCTIONS* dbg = DbgFunctions();
        duint modBase = dbg ? dbg->ModBaseFromAddr(afterRip) : 0;
        MODULEPARTY party = (dbg && modBase) ? dbg->ModGetParty(modBase) : mod_user;
        bool targetReached = (party == (MODULEPARTY)targetParty);

        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
        const char* statusStr = "step_completed";
        if (reason == STOP_BREAKPOINT_HIT) statusStr = "breakpoint_hit";
        else if (reason == STOP_EXCEPTION) statusStr = "exception";
        else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging()) statusStr = "process_exited";

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"%s\",\"target_party_reached\":%s,\"party\":%d,\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  statusStr,
                  targetReached ? "true" : "false",
                  (int)party,
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  (unsigned long long)afterRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    if (waitRes == WAIT_TIMEOUT)
    {
        if (DbgIsDebugging() && DbgIsRunning())
        {
            DbgCmdExec("pause");
            HANDLE hProc = DbgGetProcessHandle();
            if (hProc != nullptr) DebugBreakProcess(hProc);
            WaitForSingleObject(g_hExecEvent, 1000);
        }

        duint afterRip = 0;
        if (DbgIsDebugging() && !DbgIsRunning())
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump))) afterRip = postDump.regcontext.cip;
        }

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"success\":false}\n",
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"WaitForMultipleObjects failed\"}}\n";
}

void handle_step_user(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_party_step("StepUser", mod_user, readBuf, responseBuf, responseBufSize, responseText);
}

void handle_step_system(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_party_step("StepSystem", mod_system, readBuf, responseBuf, responseBufSize, responseText);
}

void handle_skip_instruction(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running; pause execution first\"}}\n";
        return;
    }

    int count = 1;
    json_get_int(readBuf, "count", &count);
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;

    duint beforeRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        beforeRip = regDump.regcontext.cip;
    }

    char cmd[32] = { 0 };
    if (count > 1)
        sprintf_s(cmd, sizeof(cmd), "skip %d", count);
    else
        strcpy_s(cmd, "skip");

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to execute skip command\"}}\n";
        return;
    }

    duint afterRip = 0;
    REGDUMP_AVX512 postDump = { 0 };
    if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
    {
        afterRip = postDump.regcontext.cip;
    }

    duint instrSize = (afterRip >= beforeRip) ? (afterRip - beforeRip) : 0;

    DISASM_INSTR instr = { 0 };
    DbgDisasmAt(afterRip, &instr);
    char safeInstr[128] = { 0 };
    escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));

    sprintf_s(responseBuf, responseBufSize,
              "{\"old_rip\":\"0x%016llX\",\"new_rip\":\"0x%016llX\",\"instruction_size\":%llu,\"instruction\":\"%s\",\"success\":true}\n",
              (unsigned long long)beforeRip,
              (unsigned long long)afterRip,
              (unsigned long long)instrSize,
              safeInstr);
    responseText = responseBuf;
}

static void execute_exception_pass_step(const char* cmdName, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (isRunning)
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"busy\",\"message\":\"Another execution control command is already in progress\"}}\n";
        return;
    }

    int timeoutMs = 5000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs < 100) timeoutMs = 100;
    if (timeoutMs > 30000) timeoutMs = 30000;

    duint beforeRip = 0;
    REGDUMP_AVX512 regDump = { 0 };
    if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
    {
        beforeRip = regDump.regcontext.cip;
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    bool cmdOk = DbgCmdExecDirect(cmdName);
    if (!cmdOk)
    {
        InterlockedExchange(&g_execActive, 0);
        sprintf_s(responseBuf, responseBufSize, "{\"error\":{\"code\":\"api_failure\",\"message\":\"%s command rejected by x64dbg\"}}\n", cmdName);
        responseText = responseBuf;
        return;
    }

    HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
    DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

    InterlockedExchange(&g_execActive, 0);

    if (waitRes == WAIT_OBJECT_0)
    {
        responseText = "{\"status\":\"shutdown\",\"error\":\"plugin shutdown signaled\"}\n";
        return;
    }

    if (waitRes == WAIT_OBJECT_0 + 1)
    {
        bool isDbg = DbgIsDebugging();
        bool isRun = isDbg ? DbgIsRunning() : false;
        for (int retry = 0; retry < 10 && isDbg && isRun; retry++)
        {
            Sleep(5);
            isRun = DbgIsRunning();
        }

        duint afterRip = 0;
        char safeInstr[128] = { 0 };
        if (isDbg && !isRun)
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump)))
            {
                afterRip = postDump.regcontext.cip;
            }
            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(afterRip, &instr);
            escape_json_string(instr.instruction, safeInstr, sizeof(safeInstr));
        }

        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
        const char* statusStr = "step_completed";
        if (reason == STOP_BREAKPOINT_HIT) statusStr = "breakpoint_hit";
        else if (reason == STOP_EXCEPTION) statusStr = "exception";
        else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging()) statusStr = "process_exited";
        else if (reason == STOP_PAUSED) statusStr = "paused";

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"%s\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  statusStr,
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  (unsigned long long)afterRip,
                  safeInstr);
        responseText = responseBuf;
        return;
    }

    if (waitRes == WAIT_TIMEOUT)
    {
        if (DbgIsDebugging() && DbgIsRunning())
        {
            DbgCmdExec("pause");
            HANDLE hProc = DbgGetProcessHandle();
            if (hProc != nullptr) DebugBreakProcess(hProc);
            WaitForSingleObject(g_hExecEvent, 1000);
        }

        duint afterRip = 0;
        if (DbgIsDebugging() && !DbgIsRunning())
        {
            REGDUMP_AVX512 postDump = { 0 };
            if (DbgGetRegDumpEx(&postDump, sizeof(postDump))) afterRip = postDump.regcontext.cip;
        }

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"success\":false}\n",
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"WaitForMultipleObjects failed\"}}\n";
}

void handle_step_over_pass_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_exception_pass_step("eStepOver", readBuf, responseBuf, responseBufSize, responseText);
}

void handle_step_out_pass_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_exception_pass_step("eStepOut", readBuf, responseBuf, responseBufSize, responseText);
}

