#include "environment.h"
#include <stddef.h>

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union

#pragma pack(push, 8)
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
} PEB, *PPEB;
#pragma pack(pop)
#pragma warning(pop)

static_assert(offsetof(PEB, BeingDebugged) == 0x02, "PEB BeingDebugged offset mismatch");
static_assert(offsetof(PEB, ImageBaseAddress) == 0x10, "PEB ImageBaseAddress offset mismatch");
static_assert(offsetof(PEB, ProcessHeap) == 0x30, "PEB ProcessHeap offset mismatch");
static_assert(offsetof(PEB, NtGlobalFlag) == 0xBC, "PEB NtGlobalFlag offset mismatch");

static_assert(offsetof(NT_TIB, StackBase) == 0x08, "NT_TIB StackBase offset mismatch");
static_assert(offsetof(NT_TIB, StackLimit) == 0x10, "NT_TIB StackLimit offset mismatch");
static_assert(offsetof(NT_TIB, Self) == 0x30, "NT_TIB Self offset mismatch");

void handle_get_peb_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;
    bool isExecActive = (InterlockedCompareExchange(&g_execActive, 0, 0) != 0);

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] get_peb_info: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (isRunning || isExecActive)
    {
        _plugin_logprintf("[x64dbg-MCP] get_peb_info: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    DWORD pid = DbgGetProcessId();
    duint pebAddr = DbgGetPebAddress(pid);
    if (pebAddr == 0)
    {
        _plugin_logprintf("[x64dbg-MCP] get_peb_info: failed to get PEB address for PID %u.\n", (unsigned int)pid);
        responseText = "{\"error\":\"failed to retrieve PEB address\"}\n";
        return;
    }

    BYTE beingDebugged = 0;
    DbgMemRead(pebAddr + offsetof(PEB, BeingDebugged), &beingDebugged, sizeof(beingDebugged));

    ULONG ntGlobalFlag = 0;
    DbgMemRead(pebAddr + offsetof(PEB, NtGlobalFlag), &ntGlobalFlag, sizeof(ntGlobalFlag));

    duint processHeap = 0;
    DbgMemRead(pebAddr + offsetof(PEB, ProcessHeap), &processHeap, sizeof(processHeap));

    duint imageBase = 0;
    DbgMemRead(pebAddr + offsetof(PEB, ImageBaseAddress), &imageBase, sizeof(imageBase));

    sprintf_s(responseBuf, responseBufSize,
        "{\"process_id\":%u,\"peb_address\":\"0x%016llX\","
        "\"being_debugged\":%u,\"nt_global_flag\":\"0x%08X\","
        "\"process_heap\":\"0x%016llX\",\"image_base_address\":\"0x%016llX\"}\n",
        (unsigned int)pid,
        (unsigned long long)pebAddr,
        (unsigned int)beingDebugged,
        (unsigned int)ntGlobalFlag,
        (unsigned long long)processHeap,
        (unsigned long long)imageBase);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_peb_info: PID=%u PEB=0x%llX BeingDebugged=%u NtGlobalFlag=0x%X\n",
                      (unsigned int)pid, (unsigned long long)pebAddr,
                      (unsigned int)beingDebugged, (unsigned int)ntGlobalFlag);
}

void handle_get_teb_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;
    bool isExecActive = (InterlockedCompareExchange(&g_execActive, 0, 0) != 0);

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] get_teb_info: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (isRunning || isExecActive)
    {
        _plugin_logprintf("[x64dbg-MCP] get_teb_info: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    THREADLIST threadList = { 0 };
    DbgGetThreadList(&threadList);

    if (threadList.list == nullptr || threadList.count <= 0)
    {
        _plugin_logprintf("[x64dbg-MCP] get_teb_info: failed to get thread list.\n");
        responseText = "{\"error\":\"failed to retrieve thread list\"}\n";
        return;
    }

    DWORD targetTid = 0;
    int parsedTid = 0;
    bool hasExplicitTid = json_get_int(readBuf, "thread_id", &parsedTid);

    if (hasExplicitTid)
    {
        if (parsedTid <= 0)
        {
            if (threadList.list != nullptr) BridgeFree(threadList.list);
            responseText = "{\"error\":\"invalid thread_id: must be a positive integer\"}\n";
            return;
        }
        targetTid = (DWORD)parsedTid;
        bool found = false;
        for (int i = 0; i < threadList.count; i++)
        {
            if (threadList.list[i].BasicInfo.ThreadId == targetTid)
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            if (threadList.list != nullptr) BridgeFree(threadList.list);
            sprintf_s(responseBuf, responseBufSize,
                "{\"error\":\"thread not found\",\"thread_id\":%u}\n",
                (unsigned int)targetTid);
            responseText = responseBuf;
            return;
        }
    }
    else
    {
        if (threadList.CurrentThread >= 0 && threadList.CurrentThread < threadList.count)
        {
            targetTid = (DWORD)threadList.list[threadList.CurrentThread].BasicInfo.ThreadId;
        }
        else
        {
            targetTid = (DWORD)threadList.list[0].BasicInfo.ThreadId;
        }
    }

    if (threadList.list != nullptr)
    {
        BridgeFree(threadList.list);
        threadList.list = nullptr;
    }

    duint tebAddr = DbgGetTebAddress(targetTid);
    if (tebAddr == 0)
    {
        _plugin_logprintf("[x64dbg-MCP] get_teb_info: failed to get TEB address for TID %u.\n", (unsigned int)targetTid);
        sprintf_s(responseBuf, responseBufSize,
            "{\"error\":\"failed to retrieve TEB address\",\"thread_id\":%u}\n",
            (unsigned int)targetTid);
        responseText = responseBuf;
        return;
    }

    duint stackBase = 0;
    DbgMemRead(tebAddr + offsetof(NT_TIB, StackBase), &stackBase, sizeof(stackBase));

    duint stackLimit = 0;
    DbgMemRead(tebAddr + offsetof(NT_TIB, StackLimit), &stackLimit, sizeof(stackLimit));

    duint selfPtr = 0;
    DbgMemRead(tebAddr + offsetof(NT_TIB, Self), &selfPtr, sizeof(selfPtr));

    sprintf_s(responseBuf, responseBufSize,
        "{\"thread_id\":%u,\"teb_address\":\"0x%016llX\","
        "\"stack_base\":\"0x%016llX\",\"stack_limit\":\"0x%016llX\","
        "\"self\":\"0x%016llX\"}\n",
        (unsigned int)targetTid,
        (unsigned long long)tebAddr,
        (unsigned long long)stackBase,
        (unsigned long long)stackLimit,
        (unsigned long long)selfPtr);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_teb_info: TID=%u TEB=0x%llX StackBase=0x%llX StackLimit=0x%llX\n",
                      (unsigned int)targetTid, (unsigned long long)tebAddr,
                      (unsigned long long)stackBase, (unsigned long long)stackLimit);
}

void handle_get_command_line(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_command_line: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetCmdline == nullptr)
    {
        responseText = "{\"error\":\"GetCmdline API not available\"}\n";
        return;
    }

    size_t size = 0;
    dbg->GetCmdline(nullptr, &size);
    if (size == 0)
    {
        responseText = "{\"command_line\":\"\"}\n";
        return;
    }

    std::vector<char> cmdBuf(size + 1, 0);
    dbg->GetCmdline(cmdBuf.data(), &size);

    std::vector<char> safeBuf((size + 1) * 2, 0);
    escape_json_string(cmdBuf.data(), safeBuf.data(), safeBuf.size());

    sprintf_s(responseBuf, responseBufSize, "{\"command_line\":\"%s\"}\n", safeBuf.data());
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_command_line retrieved (%zu bytes).\n", size);
}

void handle_set_command_line(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] set_command_line: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    bool isRunning = DbgIsRunning();
    bool isExecActive = (InterlockedCompareExchange(&g_execActive, 0, 0) != 0);
    if (isRunning || isExecActive)
    {
        _plugin_logprintf("[x64dbg-MCP] set_command_line: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
        return;
    }

    char cmdLine[MAX_COMMAND_LINE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "command_line", cmdLine, sizeof(cmdLine)))
    {
        if (!json_get_string(readBuf, "cmdline", cmdLine, sizeof(cmdLine)))
        {
            responseText = "{\"error\":\"missing command_line parameter\"}\n";
            return;
        }
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->SetCmdline == nullptr)
    {
        responseText = "{\"error\":\"SetCmdline API not available\"}\n";
        return;
    }

    bool ok = dbg->SetCmdline(cmdLine);
    if (!ok)
    {
        char cmdBuf[MAX_COMMAND_LINE_SIZE + 32] = { 0 };
        sprintf_s(cmdBuf, sizeof(cmdBuf), "setcmdline \"%s\"", cmdLine);
        ok = DbgCmdExecDirect(cmdBuf);
        if (!ok)
        {
            responseText = "{\"error\":\"failed to set command line\"}\n";
            return;
        }
    }

    size_t size = 0;
    if (dbg->GetCmdline != nullptr)
    {
        dbg->GetCmdline(nullptr, &size);
    }

    std::vector<char> currentCmd(size + 1, 0);
    if (size > 0 && dbg->GetCmdline != nullptr)
    {
        dbg->GetCmdline(currentCmd.data(), &size);
    }
    else
    {
        strcpy_s(currentCmd.data(), currentCmd.size(), cmdLine);
    }

    std::vector<char> safeBuf((size + 1) * 2 + 64, 0);
    escape_json_string(currentCmd.data(), safeBuf.data(), safeBuf.size());

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"command_line\":\"%s\"}\n",
              safeBuf.data());
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] set_command_line successfully set: %s\n", currentCmd.data());
}


void handle_get_security_mitigations(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_security_mitigations: no debuggee active.\n");
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    bool depEnabled = false;
    if (dbg != nullptr && dbg->IsDepEnabled != nullptr)
    {
        depEnabled = dbg->IsDepEnabled();
    }

    bool isElevated = BridgeIsProcessElevated();
    bool isArm64Emulated = BridgeIsARM64Emulated();
    unsigned int ntBuild = BridgeGetNtBuildNumber();

    sprintf_s(responseBuf, responseBufSize,
              "{\"dep_enabled\":%s,\"process_elevated\":%s,\"arm64_emulated\":%s,\"nt_build_number\":%u,\"architecture\":\"x64\",\"success\":true}\n",
              depEnabled ? "true" : "false",
              isElevated ? "true" : "false",
              isArm64Emulated ? "true" : "false",
              ntBuild);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_security_mitigations: DEP=%d Elevated=%d ARM64=%d Build=%u\n",
                      depEnabled ? 1 : 0, isElevated ? 1 : 0, isArm64Emulated ? 1 : 0, ntBuild);
}
