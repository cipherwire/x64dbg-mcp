#include "session_control.h"

// --------------------------------------------------------------------------
// Session Lifecycle Tracking
// --------------------------------------------------------------------------

static SRWLOCK g_sessionLock = SRWLOCK_INIT;
static char g_sessionType[32] = "none";
static char g_sessionPath[MAX_PATH] = "";
static DWORD g_attachedPid = 0;

void on_session_init_debug(const char* szFileName)
{
    AcquireSRWLockExclusive(&g_sessionLock);
    strncpy_s(g_sessionType, "launched", _TRUNCATE);
    if (szFileName)
    {
        strncpy_s(g_sessionPath, szFileName, _TRUNCATE);
    }
    else
    {
        g_sessionPath[0] = '\0';
    }
    g_attachedPid = 0;
    ReleaseSRWLockExclusive(&g_sessionLock);
}

void on_session_attach(DWORD dwProcessId)
{
    AcquireSRWLockExclusive(&g_sessionLock);
    strncpy_s(g_sessionType, "attached", _TRUNCATE);
    g_attachedPid = dwProcessId;
    g_sessionPath[0] = '\0';
    ReleaseSRWLockExclusive(&g_sessionLock);
}

void on_session_detach()
{
    AcquireSRWLockExclusive(&g_sessionLock);
    strncpy_s(g_sessionType, "none", _TRUNCATE);
    g_sessionPath[0] = '\0';
    g_attachedPid = 0;
    ReleaseSRWLockExclusive(&g_sessionLock);
}

void on_session_stop()
{
    AcquireSRWLockExclusive(&g_sessionLock);
    strncpy_s(g_sessionType, "none", _TRUNCATE);
    g_sessionPath[0] = '\0';
    g_attachedPid = 0;
    ReleaseSRWLockExclusive(&g_sessionLock);
}

// --------------------------------------------------------------------------
// PE Architecture Verification Helper
// --------------------------------------------------------------------------

static bool check_pe_x64(const char* filePath, char* errBuf, size_t errBufSize)
{
    FILE* fp = nullptr;
    if (fopen_s(&fp, filePath, "rb") != 0 || !fp)
    {
        sprintf_s(errBuf, errBufSize, "could not open file: %s", filePath);
        return false;
    }

    IMAGE_DOS_HEADER dos = { 0 };
    if (fread(&dos, 1, sizeof(dos), fp) != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        fclose(fp);
        sprintf_s(errBuf, errBufSize, "file is not a valid PE executable (invalid DOS header)");
        return false;
    }

    if (fseek(fp, dos.e_lfanew, SEEK_SET) != 0)
    {
        fclose(fp);
        sprintf_s(errBuf, errBufSize, "corrupt PE executable (invalid e_lfanew offset)");
        return false;
    }

    DWORD ntSig = 0;
    if (fread(&ntSig, 1, sizeof(ntSig), fp) != sizeof(ntSig) || ntSig != IMAGE_NT_SIGNATURE)
    {
        fclose(fp);
        sprintf_s(errBuf, errBufSize, "file is not a valid PE executable (invalid NT signature)");
        return false;
    }

    IMAGE_FILE_HEADER fileHdr = { 0 };
    if (fread(&fileHdr, 1, sizeof(fileHdr), fp) != sizeof(fileHdr))
    {
        fclose(fp);
        sprintf_s(errBuf, errBufSize, "corrupt PE file header");
        return false;
    }
    fclose(fp);

#ifdef _WIN64
    if (fileHdr.Machine == IMAGE_FILE_MACHINE_I386)
    {
        sprintf_s(errBuf, errBufSize, "architecture mismatch: file is a 32-bit x86 binary. Use x32dbg to debug this executable.");
        return false;
    }
    if (fileHdr.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        sprintf_s(errBuf, errBufSize, "unsupported PE architecture (machine 0x%04X, expected AMD64 0x8664)", fileHdr.Machine);
        return false;
    }
#else
    if (fileHdr.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        sprintf_s(errBuf, errBufSize, "architecture mismatch: file is a 64-bit AMD64 binary. Use x64dbg to debug this executable.");
        return false;
    }
    if (fileHdr.Machine != IMAGE_FILE_MACHINE_I386)
    {
        sprintf_s(errBuf, errBufSize, "unsupported PE architecture (machine 0x%04X, expected I386 0x014C)", fileHdr.Machine);
        return false;
    }
#endif
    return true;
}

// --------------------------------------------------------------------------
// String Helper: Case-Insensitive Substring Match
// --------------------------------------------------------------------------

static bool contains_ignore_case(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return false;
    if (*needle == '\0') return true;

    size_t needleLen = strlen(needle);
    size_t haystackLen = strlen(haystack);
    if (needleLen > haystackLen) return false;

    for (size_t i = 0; i <= haystackLen - needleLen; i++)
    {
        if (_strnicmp(&haystack[i], needle, needleLen) == 0)
        {
            return true;
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// Part A - Process Discovery
// --------------------------------------------------------------------------

void handle_list_processes(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char nameFilter[MAX_PATH] = { 0 };
    bool hasName = json_get_string(readBuf, "name", nameFilter, sizeof(nameFilter)) && nameFilter[0] != '\0';

    int pidFilter = 0;
    bool hasPid = json_get_int(readBuf, "pid", &pidFilter) && pidFilter > 0;

    char cmdFilter[MAX_PATH] = { 0 };
    bool hasCmd = json_get_string(readBuf, "cmdline", cmdFilter, sizeof(cmdFilter)) && cmdFilter[0] != '\0';

    char winFilter[MAX_PATH] = { 0 };
    bool hasWin = json_get_string(readBuf, "window_title", winFilter, sizeof(winFilter)) && winFilter[0] != '\0';

    int offset = 0;
    json_get_int(readBuf, "offset", &offset);
    if (offset < 0) offset = 0;

    int limit = 50;
    json_get_int(readBuf, "limit", &limit);
    if (limit <= 0) limit = 50;
    if (limit > 200) limit = 200;

    DBGPROCESSINFO* entries = nullptr;
    int count = 0;
    bool ok = DbgFunctions()->GetProcessList(&entries, &count);
    if (!ok || count <= 0 || entries == nullptr)
    {
        if (entries) BridgeFree(entries);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"total_matching\":0,\"offset\":%d,\"limit\":%d,\"processes\":[]}\n",
                  offset, limit);
        responseText = responseBuf;
        return;
    }

    std::vector<int> matching;
    matching.reserve(count);

    for (int i = 0; i < count; i++)
    {
        if (hasPid && entries[i].dwProcessId != (DWORD)pidFilter)
        {
            continue;
        }
        if (hasName && !contains_ignore_case(entries[i].szExeFile, nameFilter))
        {
            continue;
        }
        if (hasCmd && !contains_ignore_case(entries[i].szExeArgs, cmdFilter))
        {
            continue;
        }
        if (hasWin && !contains_ignore_case(entries[i].szExeMainWindowTitle, winFilter))
        {
            continue;
        }
        matching.push_back(i);
    }

    int totalMatching = (int)matching.size();
    int startIdx = (offset < totalMatching) ? offset : totalMatching;
    int endIdx = (startIdx + limit < totalMatching) ? (startIdx + limit) : totalMatching;

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"total_matching\":%d,\"offset\":%d,\"limit\":%d,\"processes\":[",
                        totalMatching, offset, limit);

    for (int i = startIdx; i < endIdx; i++)
    {
        int idx = matching[i];
        char escapedName[MAX_PATH * 2] = { 0 };
        char escapedTitle[MAX_PATH * 2] = { 0 };
        char escapedArgs[MAX_PATH * 2] = { 0 };

        escape_json_string(entries[idx].szExeFile, escapedName, sizeof(escapedName));
        escape_json_string(entries[idx].szExeMainWindowTitle, escapedTitle, sizeof(escapedTitle));
        // Truncate long command lines for bounded transport
        char shortArgs[512] = { 0 };
        strncpy_s(shortArgs, entries[idx].szExeArgs, _TRUNCATE);
        escape_json_string(shortArgs, escapedArgs, sizeof(escapedArgs));

        char itemBuf[1536] = { 0 };
        int itemLen = sprintf_s(itemBuf, sizeof(itemBuf),
                                "%s{\"pid\":%u,\"name\":\"%s\",\"main_window_title\":\"%s\",\"command_line\":\"%s\",\"architecture\":\"x64\"}",
                                (i > startIdx) ? "," : "",
                                entries[idx].dwProcessId,
                                escapedName,
                                escapedTitle,
                                escapedArgs);

        if ((size_t)pos + itemLen + 64 >= responseBufSize)
        {
            break;
        }
        memcpy(responseBuf + pos, itemBuf, itemLen);
        pos += itemLen;
        responseBuf[pos] = '\0';
    }

    BridgeFree(entries);

    if ((size_t)pos + 8 < responseBufSize)
    {
        responseBuf[pos++] = ']';
        responseBuf[pos++] = '}';
        responseBuf[pos++] = '\n';
        responseBuf[pos] = '\0';
    }
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part B - Debug Session Lifecycle
// --------------------------------------------------------------------------

void handle_launch_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (DbgIsDebugging())
    {
        responseText = "{\"error\":\"a debug session is already active; stop or detach before launching a new debuggee\"}\n";
        return;
    }

    char path[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "path", path, sizeof(path)) || path[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty path parameter\"}\n";
        return;
    }

    // Check file existence
    DWORD attribs = GetFileAttributesA(path);
    if (attribs == INVALID_FILE_ATTRIBUTES || (attribs & FILE_ATTRIBUTE_DIRECTORY))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"target file does not exist: %s\"}\n", path);
        responseText = responseBuf;
        return;
    }

    // Verify PE architecture compatibility
    char peErr[256] = { 0 };
    if (!check_pe_x64(path, peErr, sizeof(peErr)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", peErr);
        responseText = responseBuf;
        return;
    }

    char cmdLine[MAX_PATH * 2] = { 0 };
    bool hasCmdLine = json_get_string(readBuf, "command_line", cmdLine, sizeof(cmdLine)) && cmdLine[0] != '\0';

    char workDir[MAX_PATH] = { 0 };
    bool hasWorkDir = json_get_string(readBuf, "working_directory", workDir, sizeof(workDir)) && workDir[0] != '\0';

    char cmd[MAX_PATH * 4] = { 0 };
    if (hasCmdLine && hasWorkDir)
    {
        sprintf_s(cmd, sizeof(cmd), "InitDebug \"%s\", \"%s\", \"%s\"", path, cmdLine, workDir);
    }
    else if (hasCmdLine)
    {
        sprintf_s(cmd, sizeof(cmd), "InitDebug \"%s\", \"%s\"", path, cmdLine);
    }
    else if (hasWorkDir)
    {
        sprintf_s(cmd, sizeof(cmd), "InitDebug \"%s\", \"\", \"%s\"", path, workDir);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "InitDebug \"%s\"", path);
    }

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":\"failed to execute InitDebug command\"}\n";
        return;
    }

    // Bounded wait for debugger initialization (up to 10 seconds)
    bool initialized = false;
    for (int i = 0; i < 200; i++)
    {
        if (DbgIsDebugging())
        {
            initialized = true;
            break;
        }
        Sleep(50);
    }

    if (!initialized)
    {
        responseText = "{\"error\":\"timed out waiting for debuggee initialization\"}\n";
        return;
    }

    // Wait briefly for initial break or running state to stabilize
    for (int i = 0; i < 40; i++)
    {
        if (!DbgIsRunning())
        {
            break;
        }
        Sleep(50);
    }

    DWORD pid = DbgGetProcessId();
    char escapedPath[MAX_PATH * 2] = { 0 };
    escape_json_string(path, escapedPath, sizeof(escapedPath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"path\":\"%s\",\"pid\":%u,\"is_debugging\":%s,\"is_running\":%s,\"success\":true}\n",
              escapedPath,
              pid,
              DbgIsDebugging() ? "true" : "false",
              DbgIsRunning() ? "true" : "false");
    responseText = responseBuf;
}

void handle_attach_process(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    int pidInt = 0;
    if (!json_get_int(readBuf, "pid", &pidInt) || pidInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid pid parameter (must be positive integer)\"}\n";
        return;
    }
    DWORD targetPid = (DWORD)pidInt;

    if (targetPid == 0 || targetPid == 4)
    {
        responseText = "{\"error\":\"cannot attach to system or idle process\"}\n";
        return;
    }

    if (targetPid == GetCurrentProcessId())
    {
        responseText = "{\"error\":\"cannot attach to debugger host process\"}\n";
        return;
    }

    if (DbgIsDebugging())
    {
        DWORD curPid = DbgGetProcessId();
        if (curPid == targetPid)
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"pid\":%u,\"attached\":true,\"already_attached\":true,\"is_debugging\":true,\"is_running\":%s,\"success\":true}\n",
                      targetPid,
                      DbgIsRunning() ? "true" : "false");
            responseText = responseBuf;
            return;
        }
        else
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"a debug session is already active on PID %u; stop or detach first\"}\n",
                      curPid);
            responseText = responseBuf;
            return;
        }
    }

    // Probe process existence and architecture
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
    if (!hProcess)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    }
    if (!hProcess)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"process %u not found or insufficient privileges to query\"}\n",
                  targetPid);
        responseText = responseBuf;
        return;
    }

    DWORD exitCode = STILL_ACTIVE;
    if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE)
    {
        CloseHandle(hProcess);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"process %u has already exited (exit code %u)\"}\n",
                  targetPid, exitCode);
        responseText = responseBuf;
        return;
    }

    BOOL wow64 = FALSE, meWow64 = FALSE;
    if (IsWow64Process(hProcess, &wow64) && IsWow64Process(GetCurrentProcess(), &meWow64))
    {
        if (meWow64 != wow64)
        {
            CloseHandle(hProcess);
#ifdef _WIN64
            responseText = "{\"error\":\"architecture mismatch: target process is 32-bit (WOW64). Use x32dbg to attach.\"}\n";
#else
            responseText = "{\"error\":\"architecture mismatch: target process is 64-bit. Use x64dbg to attach.\"}\n";
#endif
            return;
        }
    }

    BOOL debuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(hProcess, &debuggerPresent) && debuggerPresent)
    {
        CloseHandle(hProcess);
        responseText = "{\"error\":\"target process is already being debugged by another debugger\"}\n";
        return;
    }
    CloseHandle(hProcess);

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "attach .%u", targetPid);

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":\"failed to execute attach command\"}\n";
        return;
    }

    // Bounded wait for attach to complete
    bool attached = false;
    for (int i = 0; i < 200; i++)
    {
        if (DbgIsDebugging() && DbgGetProcessId() == targetPid)
        {
            attached = true;
            break;
        }
        Sleep(50);
    }

    if (!attached)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"timed out waiting to attach to process %u\"}\n",
                  targetPid);
        responseText = responseBuf;
        return;
    }

    // Wait briefly for initial pause state
    for (int i = 0; i < 40; i++)
    {
        if (!DbgIsRunning())
        {
            break;
        }
        Sleep(50);
    }

    char modPath[MAX_PATH] = { 0 };
    duint mainBase = DbgValFromString("mod.main()");
    if (mainBase != 0)
    {
        DbgFunctions()->ModPathFromAddr(mainBase, modPath, sizeof(modPath));
    }
    char escapedPath[MAX_PATH * 2] = { 0 };
    escape_json_string(modPath, escapedPath, sizeof(escapedPath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"pid\":%u,\"path\":\"%s\",\"attached\":true,\"is_debugging\":true,\"is_running\":%s,\"success\":true}\n",
              targetPid,
              escapedPath,
              DbgIsRunning() ? "true" : "false");
    responseText = responseBuf;
}

void handle_detach_process(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee is currently attached\"}\n";
        return;
    }

    DWORD prevPid = DbgGetProcessId();

    if (!DbgCmdExecDirect("detach"))
    {
        responseText = "{\"error\":\"failed to execute detach command\"}\n";
        return;
    }

    // Bounded wait for detach completion
    for (int i = 0; i < 100; i++)
    {
        if (!DbgIsDebugging())
        {
            break;
        }
        Sleep(50);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"pid\":%u,\"detached\":true,\"is_debugging\":%s,\"breakpoints_cleared\":true,\"success\":true}\n",
              prevPid,
              DbgIsDebugging() ? "true" : "false");
    responseText = responseBuf;
}

void handle_stop_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee is currently active\"}\n";
        return;
    }

    DWORD prevPid = DbgGetProcessId();

    if (!DbgCmdExecDirect("stop"))
    {
        responseText = "{\"error\":\"failed to execute stop command\"}\n";
        return;
    }

    // Bounded wait for debug session termination
    for (int i = 0; i < 100; i++)
    {
        if (!DbgIsDebugging())
        {
            break;
        }
        Sleep(50);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"pid\":%u,\"stopped\":true,\"is_debugging\":%s,\"termination_note\":\"The debug session was terminated. x64dbg stops the debug loop and forcibly terminates the target process if it does not exit within 300ms.\",\"success\":true}\n",
              prevPid,
              DbgIsDebugging() ? "true" : "false");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part C - Thread Suspension / Resumption / Termination
// --------------------------------------------------------------------------

static bool is_thread_valid_in_debuggee(DWORD tid)
{
    THREADLIST list = { 0 };
    DbgGetThreadList(&list);
    bool found = false;
    if (list.list != nullptr && list.count > 0)
    {
        for (int i = 0; i < list.count; i++)
        {
            if (list.list[i].BasicInfo.ThreadId == tid)
            {
                found = true;
                break;
            }
        }
        BridgeFree(list.list);
    }
    return found;
}

void handle_suspend_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    int tidInt = 0;
    if (!json_get_int(readBuf, "thread_id", &tidInt) || tidInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid thread_id parameter (must be positive integer)\"}\n";
        return;
    }
    DWORD tid = (DWORD)tidInt;

    if (!is_thread_valid_in_debuggee(tid))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"thread %u not found in debuggee\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "suspendthread .%u", tid);
    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to suspend thread %u\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"suspended\":true,\"success\":true}\n",
              tid);
    responseText = responseBuf;
}

void handle_resume_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    int tidInt = 0;
    if (!json_get_int(readBuf, "thread_id", &tidInt) || tidInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid thread_id parameter (must be positive integer)\"}\n";
        return;
    }
    DWORD tid = (DWORD)tidInt;

    if (!is_thread_valid_in_debuggee(tid))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"thread %u not found in debuggee\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "resumethread .%u", tid);
    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to resume thread %u\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"resumed\":true,\"success\":true}\n",
              tid);
    responseText = responseBuf;
}

void handle_suspend_all_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    THREADLIST list = { 0 };
    DbgGetThreadList(&list);
    int totalCount = list.count;
    if (list.list) BridgeFree(list.list);

    if (!DbgCmdExecDirect("suspendallthreads"))
    {
        responseText = "{\"error\":\"failed to execute suspendallthreads command\"}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"total_threads\":%d,\"operation\":\"suspend_all\",\"success\":true}\n",
              totalCount);
    responseText = responseBuf;
}

void handle_resume_all_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    THREADLIST list = { 0 };
    DbgGetThreadList(&list);
    int totalCount = list.count;
    if (list.list) BridgeFree(list.list);

    if (!DbgCmdExecDirect("resumeallthreads"))
    {
        responseText = "{\"error\":\"failed to execute resumeallthreads command\"}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"total_threads\":%d,\"operation\":\"resume_all\",\"success\":true}\n",
              totalCount);
    responseText = responseBuf;
}

void handle_kill_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Destructive operation: you must set 'confirm': true to terminate a thread.\"}\n";
        return;
    }

    int tidInt = 0;
    if (!json_get_int(readBuf, "thread_id", &tidInt) || tidInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid thread_id parameter (must be positive integer)\"}\n";
        return;
    }
    DWORD tid = (DWORD)tidInt;

    if (!is_thread_valid_in_debuggee(tid))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"thread %u not found in debuggee\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "killthread .%u", tid);
    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to terminate thread %u\"}\n", tid);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"thread_id\":%u,\"killed\":true,\"success\":true}\n",
              tid);
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part D - Process / Session State Enhancement
// --------------------------------------------------------------------------

void handle_get_debug_session_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"is_debugging\":false,\"is_running\":false,\"session_type\":\"none\",\"pid\":0,\"main_module_path\":\"\",\"main_module_name\":\"\",\"main_module_base\":\"0x0\",\"active_thread_id\":0,\"active_thread_rip\":\"0x0\",\"thread_count\":0,\"architecture\":\"x64\",\"cached\":false,\"success\":true}\n");
        responseText = responseBuf;
        return;
    }

    DWORD pid = DbgGetProcessId();

    char sessType[32] = { 0 };
    char sessPath[MAX_PATH] = { 0 };
    AcquireSRWLockShared(&g_sessionLock);
    strncpy_s(sessType, g_sessionType, _TRUNCATE);
    strncpy_s(sessPath, g_sessionPath, _TRUNCATE);
    ReleaseSRWLockShared(&g_sessionLock);

    // If session type is "none" but we are debugging, mark as active
    if (strcmp(sessType, "none") == 0)
    {
        strncpy_s(sessType, "active", _TRUNCATE);
    }

    duint mainBase = DbgValFromString("mod.main()");
    char mainName[MAX_PATH] = { 0 };
    char mainPath[MAX_PATH] = { 0 };
    if (mainBase != 0)
    {
        DbgFunctions()->ModNameFromAddr(mainBase, mainName, true);
        DbgFunctions()->ModPathFromAddr(mainBase, mainPath, sizeof(mainPath));
    }
    if (mainPath[0] == '\0' && sessPath[0] != '\0')
    {
        strncpy_s(mainPath, sessPath, _TRUNCATE);
    }

    DWORD activeTid = DbgGetThreadId();
    duint activeRip = DbgValFromString("CIP");

    THREADLIST tList = { 0 };
    DbgGetThreadList(&tList);
    int threadCount = tList.count;
    if (tList.list) BridgeFree(tList.list);

    char escPath[MAX_PATH * 2] = { 0 };
    char escName[MAX_PATH * 2] = { 0 };
    escape_json_string(mainPath, escPath, sizeof(escPath));
    escape_json_string(mainName, escName, sizeof(escName));

    sprintf_s(responseBuf, responseBufSize,
              "{\"is_debugging\":true,\"is_running\":%s,\"session_type\":\"%s\",\"pid\":%u,\"main_module_path\":\"%s\",\"main_module_name\":\"%s\",\"main_module_base\":\"0x%llX\",\"active_thread_id\":%u,\"active_thread_rip\":\"0x%llX\",\"thread_count\":%d,\"architecture\":\"x64\",\"cached\":false,\"success\":true}\n",
              isRunning ? "true" : "false",
              sessType,
              pid,
              escPath,
              escName,
              (unsigned long long)mainBase,
              activeTid,
              (unsigned long long)activeRip,
              threadCount);
    responseText = responseBuf;
}

void handle_restart_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session to restart\"}}\n";
        return;
    }

    char mainPath[MAX_PATH] = { 0 };
    duint mainBase = DbgValFromString("mod.main()");
    if (mainBase != 0)
    {
        DbgFunctions()->ModPathFromAddr(mainBase, mainPath, sizeof(mainPath));
    }

    if (mainPath[0] == '\0')
    {
        AcquireSRWLockShared(&g_sessionLock);
        strncpy_s(mainPath, g_sessionPath, _TRUNCATE);
        ReleaseSRWLockShared(&g_sessionLock);
    }

    if (mainPath[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Could not determine main module path for restart\"}}\n";
        return;
    }

    char errBuf[256] = { 0 };
    if (!check_pe_x64(mainPath, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":{\"code\":\"invalid_binary\",\"message\":\"%s\"}}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    DWORD oldPid = DbgGetProcessId();

    char cmd[MAX_PATH + 32] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "InitDebug \"%s\"", mainPath);

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to execute InitDebug command for restart\"}}\n";
        return;
    }

    // Bounded wait for debugger initialization (up to 10 seconds)
    bool initialized = false;
    for (int i = 0; i < 200; i++)
    {
        if (DbgIsDebugging())
        {
            initialized = true;
            break;
        }
        Sleep(50);
    }

    if (!initialized)
    {
        responseText = "{\"error\":{\"code\":\"timeout\",\"message\":\"Timed out waiting for debuggee initialization during restart\"}}\n";
        return;
    }

    // Wait briefly for initial pause state to stabilize
    for (int i = 0; i < 40; i++)
    {
        if (!DbgIsRunning())
        {
            break;
        }
        Sleep(50);
    }

    DWORD newPid = DbgGetProcessId();
    DWORD newTid = DbgGetThreadId();
    duint newRip = DbgValFromString("CIP");
    duint newBase = DbgValFromString("mod.main()");

    char escPath[MAX_PATH * 2] = { 0 };
    escape_json_string(mainPath, escPath, sizeof(escPath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"restarted\":true,\"old_pid\":%u,\"pid\":%u,\"thread_id\":%u,\"rip\":\"0x%016llX\",\"module_base\":\"0x%016llX\",\"path\":\"%s\",\"is_debugging\":%s,\"is_running\":%s,\"success\":true}\n",
              oldPid,
              newPid,
              newTid,
              (unsigned long long)newRip,
              (unsigned long long)newBase,
              escPath,
              DbgIsDebugging() ? "true" : "false",
              DbgIsRunning() ? "true" : "false");
    responseText = responseBuf;
}

