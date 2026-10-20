#include "breakpoints.h"

bool find_breakpoint_at_address(duint va, BRIDGEBP* outBp)
{
    BPMAP bpMap = { 0 };
    int count = DbgGetBpList(bp_none, &bpMap);
    bool found = false;
    if (count > 0 && bpMap.bp != nullptr)
    {
        // 1. Check software breakpoints first
        for (int i = 0; i < bpMap.count; i++)
        {
            if (!(bpMap.bp[i].type & (bp_hardware | bp_memory | bp_dll | bp_exception)) && bpMap.bp[i].addr == va)
            {
                if (outBp)
                {
                    *outBp = bpMap.bp[i];
                }
                found = true;
                break;
            }
        }

        // 2. Check hardware breakpoints
        if (!found)
        {
            for (int i = 0; i < bpMap.count; i++)
            {
                if ((bpMap.bp[i].type & bp_hardware) && bpMap.bp[i].addr == va)
                {
                    if (outBp)
                    {
                        *outBp = bpMap.bp[i];
                    }
                    found = true;
                    break;
                }
            }
        }

        // 3. Check memory breakpoints (range enclosing va)
        if (!found)
        {
            for (int i = 0; i < bpMap.count; i++)
            {
                if (bpMap.bp[i].type & bp_memory)
                {
                    duint start = bpMap.bp[i].addr;
                    duint size = 0;
                    if (DbgFunctions() && DbgFunctions()->MemBpSize)
                    {
                        size = DbgFunctions()->MemBpSize(start);
                    }
                    if (size == 0)
                    {
                        size = 4096;
                    }
                    if (va >= start && va < start + size)
                    {
                        if (outBp)
                        {
                            *outBp = bpMap.bp[i];
                        }
                        found = true;
                        break;
                    }
                }
            }
        }

        BridgeFree(bpMap.bp);
    }
    return found;
}

void handle_set_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] set_breakpoint: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] set_breakpoint: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        char addrStr[64] = { 0 };
        if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)))
        {
            responseText = "{\"error\":\"missing address parameter\"}\n";
        }
        else
        {
            duint va = 0;
            if (!resolve_address(addrStr, &va))
            {
                responseText = "{\"error\":\"invalid address format\"}\n";
            }
            else if (!DbgMemIsValidReadPtr(va))
            {
                _plugin_logprintf("[x64dbg-MCP] set_breakpoint: unmapped address 0x%016llX\n", (unsigned long long)va);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"address 0x%016llX is not mapped or readable\"}\n",
                          (unsigned long long)va);
                responseText = responseBuf;
            }
            else if (find_breakpoint_at_address(va, nullptr))
            {
                _plugin_logprintf("[x64dbg-MCP] set_breakpoint: breakpoint already exists at 0x%016llX\n", (unsigned long long)va);
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"breakpoint already exists at address 0x%016llX\"}\n",
                          (unsigned long long)va);
                responseText = responseBuf;
            }
            else
            {
                bool ok = Script::Debug::SetBreakpoint(va);
                if (!ok || !find_breakpoint_at_address(va, nullptr))
                {
                    _plugin_logprintf("[x64dbg-MCP] set_breakpoint failed at 0x%016llX\n", (unsigned long long)va);
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"error\":\"failed to set breakpoint at address 0x%016llX\"}\n",
                              (unsigned long long)va);
                    responseText = responseBuf;
                }
                else
                {
                    _plugin_logprintf("[x64dbg-MCP] Breakpoint set at 0x%016llX\n", (unsigned long long)va);
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"address\":\"0x%016llX\",\"type\":\"software\",\"success\":true}\n",
                              (unsigned long long)va);
                    responseText = responseBuf;
                }
            }
        }
    }
}

void handle_list_breakpoints(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] list_breakpoints: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        BPMAP bpMap = { 0 };
        DbgGetBpList(bp_none, &bpMap);

        int offset = sprintf_s(responseBuf, responseBufSize,
                               "{\"count\":%d,\"breakpoints\":[", bpMap.count);

        for (int i = 0; i < bpMap.count; i++)
        {
            const char* typeStr = "software";
            if (bpMap.bp[i].type & bp_hardware) typeStr = "hardware";
            else if (bpMap.bp[i].type & bp_memory) typeStr = "memory";
            else if (bpMap.bp[i].type & bp_dll) typeStr = "dll";
            else if (bpMap.bp[i].type & bp_exception) typeStr = "exception";

            char safeMod[MAX_MODULE_SIZE] = { 0 };
            strncpy_s(safeMod, sizeof(safeMod), bpMap.bp[i].mod, _TRUNCATE);

            char safeName[MAX_BREAKPOINT_SIZE] = { 0 };
            strncpy_s(safeName, sizeof(safeName), bpMap.bp[i].name, _TRUNCATE);

            offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                "%s{\"address\":\"0x%016llX\",\"enabled\":%s,\"active\":%s,\"hit_count\":%u,\"type\":\"%s\",\"module\":\"%s\",\"name\":\"%s\"}",
                (i > 0 ? "," : ""),
                (unsigned long long)bpMap.bp[i].addr,
                bpMap.bp[i].enabled ? "true" : "false",
                bpMap.bp[i].active ? "true" : "false",
                bpMap.bp[i].hitCount,
                typeStr,
                safeMod,
                safeName);
        }

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
        responseText = responseBuf;

        if (bpMap.bp != nullptr)
        {
            BridgeFree(bpMap.bp);
        }

        _plugin_logprintf("[x64dbg-MCP] Listed %d breakpoints.\n", bpMap.count);
    }
}

void handle_delete_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] delete_breakpoint: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] delete_breakpoint: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        char addrStr[64] = { 0 };
        if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)))
        {
            responseText = "{\"error\":\"missing address parameter\"}\n";
        }
        else
        {
            duint va = 0;
            if (!resolve_address(addrStr, &va))
            {
                responseText = "{\"error\":\"invalid address format\"}\n";
            }
            else
            {
                BRIDGEBP existingBp = { 0 };
                if (!find_breakpoint_at_address(va, &existingBp))
                {
                    _plugin_logprintf("[x64dbg-MCP] delete_breakpoint: no breakpoint at 0x%016llX\n", (unsigned long long)va);
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"error\":\"breakpoint not found at address 0x%016llX\"}\n",
                              (unsigned long long)va);
                    responseText = responseBuf;
                }
                else
                {
                    bool ok = false;
                    if (existingBp.type & bp_hardware)
                    {
                        char cmd[128] = { 0 };
                        sprintf_s(cmd, sizeof(cmd), "DeleteHardwareBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
                        ok = DbgCmdExecDirect(cmd);
                    }
                    else if (existingBp.type & bp_memory)
                    {
                        char cmd[128] = { 0 };
                        sprintf_s(cmd, sizeof(cmd), "DeleteMemoryBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
                        ok = DbgCmdExecDirect(cmd);
                    }
                    else
                    {
                        ok = Script::Debug::DeleteBreakpoint(va);
                    }

                    if (!ok || find_breakpoint_at_address(va, nullptr))
                    {
                        _plugin_logprintf("[x64dbg-MCP] delete_breakpoint failed at 0x%016llX\n", (unsigned long long)va);
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"error\":\"failed to delete breakpoint at address 0x%016llX\"}\n",
                                  (unsigned long long)va);
                        responseText = responseBuf;
                    }
                    else
                    {
                        _plugin_logprintf("[x64dbg-MCP] Breakpoint deleted at 0x%016llX\n", (unsigned long long)va);
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"address\":\"0x%016llX\",\"deleted\":true}\n",
                                  (unsigned long long)va);
                        responseText = responseBuf;
                    }
                }
            }
        }
    }
}

void handle_enable_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] enable_breakpoint: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address parameter\"}\n";
        return;
    }

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":\"invalid address format\"}\n";
        return;
    }

    BRIDGEBP existingBp = { 0 };
    if (!find_breakpoint_at_address(va, &existingBp))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"breakpoint not found at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    bool enabled = true;
    bool parsedVal = false;
    if (json_get_bool(readBuf, "enabled", &parsedVal))
    {
        enabled = parsedVal;
    }

    char cmd[128] = { 0 };
    if (existingBp.type & bp_hardware)
    {
        if (enabled)
            sprintf_s(cmd, sizeof(cmd), "EnableHardwareBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
        else
            sprintf_s(cmd, sizeof(cmd), "DisableHardwareBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
    }
    else if (existingBp.type & bp_memory)
    {
        if (enabled)
            sprintf_s(cmd, sizeof(cmd), "EnableMemoryBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
        else
            sprintf_s(cmd, sizeof(cmd), "DisableMemoryBreakpoint 0x%llX", (unsigned long long)existingBp.addr);
    }
    else
    {
        if (enabled)
        {
            sprintf_s(cmd, sizeof(cmd), "be 0x%llX", (unsigned long long)existingBp.addr);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "bd 0x%llX", (unsigned long long)existingBp.addr);
        }
    }

    bool cmdOk = DbgCmdExecDirect(cmd);

    BRIDGEBP updatedBp = { 0 };
    bool stillExists = find_breakpoint_at_address(va, &updatedBp);
    bool confirmedEnabled = stillExists ? updatedBp.enabled : false;

    if (!cmdOk && (confirmedEnabled != enabled))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to toggle breakpoint state at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"enabled\":%s}\n",
              (unsigned long long)va, confirmedEnabled ? "true" : "false");
    responseText = responseBuf;
}

