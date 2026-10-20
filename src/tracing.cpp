#include "tracing.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper to escape internal quotes for commands
static void escape_cmd_quotes(const char* src, char* dst, size_t dstSize)
{
    if (!src || !dst || dstSize == 0) return;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d < dstSize - 2; s++)
    {
        if (src[s] == '\"')
        {
            if (d < dstSize - 3)
            {
                dst[d++] = '\\';
                dst[d++] = '\"';
            }
        }
        else
        {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
}

// Common trace execution routine
static void execute_trace_operation(const char* cmd, int timeoutMs, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"Cannot trace: no active debuggee session\"}}\n";
        return;
    }

    if (DbgIsRunning())
    {
        responseText = "{\"error\":{\"code\":\"already_running\",\"message\":\"Cannot start trace when running, pause execution first\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"execution_active\",\"message\":\"Another execution or trace operation is already in progress\"}}\n";
        return;
    }

    duint beforeRip = 0;
    REGDUMP_AVX512 preDump = { 0 };
    if (DbgGetRegDumpEx(&preDump, sizeof(preDump)))
    {
        beforeRip = preDump.regcontext.cip;
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    bool cmdOk = DbgCmdExecDirect(cmd);
    if (!cmdOk)
    {
        InterlockedExchange(&g_execActive, 0);
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"Trace command rejected by x64dbg (e.g. invalid expression, trace already active, or syntax error)\"}}\n";
        return;
    }

    if (timeoutMs <= 0) timeoutMs = 10000;
    if (timeoutMs > 600000) timeoutMs = 600000;

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

        duint steps = DbgValFromString("$tracecounter");
        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
        const char* stopReasonStr = "step_completed";
        if (reason == STOP_BREAKPOINT_HIT) stopReasonStr = "breakpoint_hit";
        else if (reason == STOP_EXCEPTION) stopReasonStr = "exception";
        else if (reason == STOP_PAUSED) stopReasonStr = "paused";
        else if (reason == STOP_PROCESS_EXITED || reason == STOP_DEBUG_ENDED || !DbgIsDebugging()) stopReasonStr = "process_exited";

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"success\",\"stop_reason\":\"%s\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"steps\":%llu,\"trace_active\":false,\"success\":true}\n",
                  stopReasonStr,
                  (unsigned long long)beforeRip,
                  (unsigned long long)afterRip,
                  (unsigned long long)afterRip,
                  safeInstr,
                  (unsigned long long)steps);
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

        duint afterRip = DbgValFromString("cip");
        bool isStillRun = DbgIsDebugging() ? DbgIsRunning() : false;

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"error\":\"trace operation timed out\",\"trace_active\":%s,\"is_running\":%s,\"after_rip\":\"0x%016llX\"}\n",
                  isStillRun ? "true" : "false",
                  isStillRun ? "true" : "false",
                  (unsigned long long)afterRip);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"internal_error\",\"message\":\"Unexpected wait failure during trace\"}}\n";
}

// 1. trace_into_conditional
void handle_trace_into_conditional(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    if (!json_get_string(readBuf, "condition", condition, sizeof(condition)) || condition[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"condition argument is required for trace_into_conditional\"}}\n";
        return;
    }

    duint dummyVal = 0;
    if (DbgFunctions() && DbgFunctions()->ValFromString)
    {
        if (!DbgFunctions()->ValFromString(condition, &dummyVal))
        {
            responseText = "{\"error\":{\"code\":\"invalid_condition\",\"message\":\"Invalid condition expression syntax\"}}\n";
            return;
        }
    }

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char escapedCond[1024] = { 0 };
    escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));

    char cmd[1200] = { 0 };
    if (maxSteps > 0)
    {
        sprintf_s(cmd, sizeof(cmd), "TraceIntoConditional \"%s\", %d", escapedCond, maxSteps);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "TraceIntoConditional \"%s\"", escapedCond);
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 2. trace_over_conditional
void handle_trace_over_conditional(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    if (!json_get_string(readBuf, "condition", condition, sizeof(condition)) || condition[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"condition argument is required for trace_over_conditional\"}}\n";
        return;
    }

    duint dummyVal = 0;
    if (DbgFunctions() && DbgFunctions()->ValFromString)
    {
        if (!DbgFunctions()->ValFromString(condition, &dummyVal))
        {
            responseText = "{\"error\":{\"code\":\"invalid_condition\",\"message\":\"Invalid condition expression syntax\"}}\n";
            return;
        }
    }

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char escapedCond[1024] = { 0 };
    escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));

    char cmd[1200] = { 0 };
    if (maxSteps > 0)
    {
        sprintf_s(cmd, sizeof(cmd), "TraceOverConditional \"%s\", %d", escapedCond, maxSteps);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "TraceOverConditional \"%s\"", escapedCond);
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 3. trace_into_beyond_trace_record
void handle_trace_into_beyond_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    bool hasCond = json_get_string(readBuf, "condition", condition, sizeof(condition)) && condition[0] != '\0';

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char cmd[1200] = { 0 };
    if (hasCond)
    {
        char escapedCond[1024] = { 0 };
        escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tibt \"%s\", %d", escapedCond, maxSteps);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "tibt \"%s\"", escapedCond);
        }
    }
    else
    {
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tibt \"0\", %d", maxSteps);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "tibt");
        }
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 4. trace_over_beyond_trace_record
void handle_trace_over_beyond_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    bool hasCond = json_get_string(readBuf, "condition", condition, sizeof(condition)) && condition[0] != '\0';

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char cmd[1200] = { 0 };
    if (hasCond)
    {
        char escapedCond[1024] = { 0 };
        escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tobt \"%s\", %d", escapedCond, maxSteps);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "tobt \"%s\"", escapedCond);
        }
    }
    else
    {
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tobt \"0\", %d", maxSteps);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "tobt");
        }
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 5. trace_into_trace_record
void handle_trace_into_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    bool hasCond = json_get_string(readBuf, "condition", condition, sizeof(condition)) && condition[0] != '\0';

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char cmd[1200] = { 0 };
    if (hasCond)
    {
        char escapedCond[1024] = { 0 };
        escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tiit \"%s\", %d", escapedCond, maxSteps);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "tiit \"%s\"", escapedCond);
        }
    }
    else
    {
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "tiit \"0\", %d", maxSteps);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "tiit");
        }
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 6. trace_over_trace_record
void handle_trace_over_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char condition[512] = { 0 };
    bool hasCond = json_get_string(readBuf, "condition", condition, sizeof(condition)) && condition[0] != '\0';

    int maxSteps = 0;
    json_get_int(readBuf, "max_steps", &maxSteps);

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);

    char cmd[1200] = { 0 };
    if (hasCond)
    {
        char escapedCond[1024] = { 0 };
        escape_cmd_quotes(condition, escapedCond, sizeof(escapedCond));
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "toit \"%s\", %d", escapedCond, maxSteps);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "toit \"%s\"", escapedCond);
        }
    }
    else
    {
        if (maxSteps > 0)
        {
            sprintf_s(cmd, sizeof(cmd), "toit \"0\", %d", maxSteps);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "toit");
        }
    }

    execute_trace_operation(cmd, timeoutMs, responseBuf, responseBufSize, responseText);
}

// 7. run_to_party
void handle_run_to_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"Cannot run to party: no active debuggee session\"}}\n";
        return;
    }

    if (DbgIsRunning())
    {
        responseText = "{\"error\":{\"code\":\"already_running\",\"message\":\"Cannot run to party when running, pause execution first\"}}\n";
        return;
    }

    int partyNum = -1;
    char partyStr[32] = { 0 };
    if (json_get_string(readBuf, "party", partyStr, sizeof(partyStr)))
    {
        if (_stricmp(partyStr, "user") == 0 || strcmp(partyStr, "0") == 0) partyNum = 0;
        else if (_stricmp(partyStr, "system") == 0 || strcmp(partyStr, "1") == 0) partyNum = 1;
    }
    else
    {
        int pVal = 0;
        if (json_get_int(readBuf, "party", &pVal))
        {
            if (pVal == 0 || pVal == 1) partyNum = pVal;
        }
    }

    if (partyNum == -1)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"party must be 'user' (0) or 'system' (1)\"}}\n";
        return;
    }

    int timeoutMs = 10000;
    json_get_int(readBuf, "timeout_ms", &timeoutMs);
    if (timeoutMs <= 0) timeoutMs = 10000;
    if (timeoutMs > 600000) timeoutMs = 600000;

    if (InterlockedCompareExchange(&g_execActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"execution_active\",\"message\":\"Another execution operation is already in progress\"}}\n";
        return;
    }

    duint beforeRip = 0;
    REGDUMP_AVX512 preDump = { 0 };
    if (DbgGetRegDumpEx(&preDump, sizeof(preDump)))
    {
        beforeRip = preDump.regcontext.cip;
    }

    ResetEvent(g_hExecEvent);
    InterlockedExchange(&g_lastStopReason, STOP_NONE);
    g_lastBpAddr = 0;
    g_lastExceptionCode = 0;

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "RunToParty %d", partyNum);
    bool cmdOk = DbgCmdExecDirect(cmd);
    if (!cmdOk)
    {
        InterlockedExchange(&g_execActive, 0);
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"RunToParty command rejected by x64dbg (e.g. party busy)\"}}\n";
        return;
    }

    HANDLE waitEvents[2] = { g_hStopEvent, g_hExecEvent };
    DWORD waitRes = WaitForMultipleObjects(2, waitEvents, FALSE, (DWORD)timeoutMs);

    InterlockedExchange(&g_execActive, 0);

    if (waitRes == WAIT_OBJECT_0)
    {
        responseText = "{\"status\":\"shutdown\",\"party_reached\":false,\"error\":\"plugin shutdown signaled\"}\n";
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
        MODULEPARTY reachedParty = (dbg && modBase) ? dbg->ModGetParty(modBase) : mod_user;
        bool partyReached = ((int)reachedParty == partyNum);

        LONG reason = InterlockedCompareExchange(&g_lastStopReason, STOP_NONE, STOP_NONE);
        const char* statusStr = partyReached ? "party_reached" : "paused";
        if (reason == STOP_BREAKPOINT_HIT) statusStr = "breakpoint_hit";
        else if (reason == STOP_EXCEPTION) statusStr = "exception";
        else if (reason == STOP_DEBUG_ENDED || reason == STOP_PROCESS_EXITED || !DbgIsDebugging()) statusStr = "process_exited";

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"success\",\"stop_reason\":\"%s\",\"party_reached\":%s,\"party\":%d,\"party_name\":\"%s\",\"before_rip\":\"0x%016llX\",\"after_rip\":\"0x%016llX\",\"rip\":\"0x%016llX\",\"instruction\":\"%s\",\"success\":true}\n",
                  statusStr,
                  partyReached ? "true" : "false",
                  partyNum,
                  (partyNum == 0) ? "user" : "system",
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

        duint afterRip = DbgValFromString("cip");
        bool isStillRun = DbgIsDebugging() ? DbgIsRunning() : false;

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"timeout\",\"party_reached\":false,\"party\":%d,\"error\":\"RunToParty timed out\",\"is_running\":%s,\"after_rip\":\"0x%016llX\"}\n",
                  partyNum,
                  isStillRun ? "true" : "false",
                  (unsigned long long)afterRip);
        responseText = responseBuf;
        return;
    }

    responseText = "{\"error\":{\"code\":\"internal_error\",\"message\":\"Unexpected wait failure during RunToParty\"}}\n";
}

// 8. set_trace_log
void handle_set_trace_log(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char text[512] = { 0 };
    json_get_string(readBuf, "text", text, sizeof(text));

    char cond[256] = { 0 };
    json_get_string(readBuf, "condition", cond, sizeof(cond));

    char escapedText[1024] = { 0 };
    escape_cmd_quotes(text, escapedText, sizeof(escapedText));

    char escapedCond[512] = { 0 };
    escape_cmd_quotes(cond, escapedCond, sizeof(escapedCond));

    if (cond[0] != '\0')
    {
        duint dummyVal = 0;
        if (DbgFunctions() && DbgFunctions()->ValFromString)
        {
            if (!DbgFunctions()->ValFromString(cond, &dummyVal))
            {
                responseText = "{\"error\":{\"code\":\"invalid_condition\",\"message\":\"Invalid condition expression syntax\"}}\n";
                return;
            }
        }
    }

    char cmd[1600] = { 0 };
    if (text[0] == '\0')
    {
        strcpy_s(cmd, sizeof(cmd), "TraceSetLog \"\"");
    }
    else if (cond[0] == '\0')
    {
        sprintf_s(cmd, sizeof(cmd), "TraceSetLog \"%s\", \"1\"", escapedText);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "TraceSetLog \"%s\", \"%s\"", escapedText, escapedCond);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"TraceSetLog command failed or invalid condition expression\"}}\n";
        return;
    }

    char jsonText[1024] = { 0 };
    escape_json_string(text, jsonText, sizeof(jsonText));
    char jsonCond[512] = { 0 };
    escape_json_string(cond, jsonCond, sizeof(jsonCond));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"configured\":true,\"text\":\"%s\",\"condition\":\"%s\"}\n",
              jsonText, jsonCond);
    responseText = responseBuf;
}

// 9. set_trace_command
void handle_set_trace_command(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char command[512] = { 0 };
    json_get_string(readBuf, "command", command, sizeof(command));

    char cond[256] = { 0 };
    json_get_string(readBuf, "condition", cond, sizeof(cond));

    char escapedCmd[1024] = { 0 };
    escape_cmd_quotes(command, escapedCmd, sizeof(escapedCmd));

    char escapedCond[512] = { 0 };
    escape_cmd_quotes(cond, escapedCond, sizeof(escapedCond));

    char cmd[1600] = { 0 };
    if (command[0] == '\0')
    {
        strcpy_s(cmd, sizeof(cmd), "TraceSetCommand \"\"");
    }
    else if (cond[0] == '\0')
    {
        // DEFENSIVE FIX: Pinned x64dbg attempts to read traceCondition->condition.GetExpression()
        // when condition is empty, which causes a null dereference crash because traceCondition
        // is null when tracing is not active. Supplying "1" avoids the null dereference.
        sprintf_s(cmd, sizeof(cmd), "TraceSetCommand \"%s\", \"1\"", escapedCmd);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "TraceSetCommand \"%s\", \"%s\"", escapedCmd, escapedCond);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"TraceSetCommand command failed or invalid condition expression\"}}\n";
        return;
    }

    char jsonCmd[1024] = { 0 };
    escape_json_string(command, jsonCmd, sizeof(jsonCmd));
    char jsonCond[512] = { 0 };
    escape_json_string(cond, jsonCond, sizeof(jsonCond));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"configured\":true,\"command\":\"%s\",\"condition\":\"%s\"}\n",
              jsonCmd, jsonCond);
    responseText = responseBuf;
}

// 10. set_trace_log_file
void handle_set_trace_log_file(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char path[MAX_PATH] = { 0 };
    json_get_string(readBuf, "path", path, sizeof(path));

    char escapedPath[MAX_PATH * 2] = { 0 };
    escape_cmd_quotes(path, escapedPath, sizeof(escapedPath));

    char cmd[MAX_PATH * 2 + 32] = { 0 };
    if (path[0] == '\0')
    {
        strcpy_s(cmd, sizeof(cmd), "TraceSetLogFile \"\"");
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "TraceSetLogFile \"%s\"", escapedPath);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"TraceSetLogFile command failed\"}}\n";
        return;
    }

    char jsonPath[MAX_PATH * 2] = { 0 };
    escape_json_string(path, jsonPath, sizeof(jsonPath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"configured\":true,\"path\":\"%s\",\"file_logging_enabled\":%s}\n",
              jsonPath, (path[0] != '\0') ? "true" : "false");
    responseText = responseBuf;
}

// 11. set_trace_step_filter
void handle_set_trace_step_filter(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char filter[32] = { 0 };
    if (!json_get_string(readBuf, "filter", filter, sizeof(filter)) || filter[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"filter argument is required ('none', 'user', or 'system')\"}}\n";
        return;
    }

    if (_stricmp(filter, "none") != 0 && _stricmp(filter, "user") != 0 && _stricmp(filter, "system") != 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid step filter. Must be 'none', 'user', or 'system'\"}}\n";
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "TraceSetStepFilter %s", filter);
    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"TraceSetStepFilter command failed\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"configured\":true,\"filter\":\"%s\"}\n",
              filter);
    responseText = responseBuf;
}

// 12. start_trace_recording
void handle_start_trace_recording(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"Cannot start trace recording: no active debuggee session\"}}\n";
        return;
    }

    char path[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "path", path, sizeof(path)) || path[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"path argument is required for start_trace_recording\"}}\n";
        return;
    }

    char escapedPath[MAX_PATH * 2] = { 0 };
    escape_cmd_quotes(path, escapedPath, sizeof(escapedPath));

    char cmd[MAX_PATH * 2 + 32] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "StartRunTrace \"%s\"", escapedPath);

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"StartRunTrace command failed (e.g. invalid file path or unable to create file)\"}}\n";
        return;
    }

    char jsonPath[MAX_PATH * 2] = { 0 };
    escape_json_string(path, jsonPath, sizeof(jsonPath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"recording\":true,\"path\":\"%s\"}\n",
              jsonPath);
    responseText = responseBuf;
}

// 13. stop_trace_recording
void handle_stop_trace_recording(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    (void)responseBuf;
    (void)responseBufSize;

    DbgCmdExecDirect("StopRunTrace");
    responseText = "{\"status\":\"success\",\"recording\":false,\"stopped\":true}\n";
}

// Phase 27 Dispatcher
bool dispatch_commands_phase27(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "trace_into_conditional") == 0)
    {
        handle_trace_into_conditional(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "trace_over_conditional") == 0)
    {
        handle_trace_over_conditional(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "trace_into_beyond_trace_record") == 0)
    {
        handle_trace_into_beyond_trace_record(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "trace_over_beyond_trace_record") == 0)
    {
        handle_trace_over_beyond_trace_record(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "trace_into_trace_record") == 0)
    {
        handle_trace_into_trace_record(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "trace_over_trace_record") == 0)
    {
        handle_trace_over_trace_record(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "run_to_party") == 0)
    {
        handle_run_to_party(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_trace_log") == 0)
    {
        handle_set_trace_log(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_trace_command") == 0)
    {
        handle_set_trace_command(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_trace_log_file") == 0)
    {
        handle_set_trace_log_file(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_trace_step_filter") == 0)
    {
        handle_set_trace_step_filter(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "start_trace_recording") == 0)
    {
        handle_start_trace_recording(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "stop_trace_recording") == 0)
    {
        handle_stop_trace_recording(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}
