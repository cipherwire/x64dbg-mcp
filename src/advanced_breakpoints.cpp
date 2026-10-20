#include "advanced_breakpoints.h"

// Helper to resolve breakpoint type string to enum
static BPXTYPE parse_bpx_type(const char* typeStr)
{
    if (!typeStr || typeStr[0] == '\0') return bp_none;
    if (_stricmp(typeStr, "software") == 0 || _stricmp(typeStr, "normal") == 0) return bp_normal;
    if (_stricmp(typeStr, "hardware") == 0) return bp_hardware;
    if (_stricmp(typeStr, "memory") == 0) return bp_memory;
    if (_stricmp(typeStr, "dll") == 0) return bp_dll;
    if (_stricmp(typeStr, "exception") == 0) return bp_exception;
    return bp_none;
}

// Find breakpoint reference and BRIDGEBP info using authoritative BPMAP enumeration
static bool find_target_breakpoint(
    const char* addrStr,
    const char* modStr,
    const char* typeStr,
    BP_REF* outRef,
    BRIDGEBP* outBridgeBp)
{
    BPXTYPE reqType = parse_bpx_type(typeStr);

    BPMAP bpMap = { 0 };
    int total = DbgGetBpList(bp_none, &bpMap);
    if (total <= 0 || bpMap.bp == nullptr)
    {
        return false;
    }

    bool matched = false;
    BRIDGEBP foundBp = { 0 };

    // 1. DLL breakpoint lookup
    if ((modStr && modStr[0] != '\0') || reqType == bp_dll)
    {
        const char* targetMod = (modStr && modStr[0] != '\0') ? modStr : addrStr;
        if (targetMod && targetMod[0] != '\0')
        {
            for (int i = 0; i < bpMap.count; i++)
            {
                if (bpMap.bp[i].type & bp_dll)
                {
                    if (_stricmp(bpMap.bp[i].mod, targetMod) == 0 || _stricmp(bpMap.bp[i].name, targetMod) == 0)
                    {
                        foundBp = bpMap.bp[i];
                        matched = true;
                        break;
                    }
                }
            }
        }
    }

    // 2. Address-based or Exception-code lookup
    if (!matched && addrStr && addrStr[0] != '\0')
    {
        if (reqType == bp_exception)
        {
            char* endPtr = nullptr;
            const char* p = addrStr;
            int base = 10;
            if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { p += 2; base = 16; }
            duint code = (duint)_strtoui64(p, &endPtr, base);

            for (int i = 0; i < bpMap.count; i++)
            {
                if ((bpMap.bp[i].type & bp_exception) && bpMap.bp[i].addr == code)
                {
                    foundBp = bpMap.bp[i];
                    matched = true;
                    break;
                }
            }
        }
        else
        {
            duint va = 0;
            if (resolve_address(addrStr, &va))
            {
                // If specific type requested
                if (reqType == bp_normal)
                {
                    for (int i = 0; i < bpMap.count; i++)
                    {
                        if (!(bpMap.bp[i].type & (bp_hardware | bp_memory | bp_dll | bp_exception)) && bpMap.bp[i].addr == va)
                        {
                            foundBp = bpMap.bp[i];
                            matched = true;
                            break;
                        }
                    }
                }
                else if (reqType == bp_hardware)
                {
                    for (int i = 0; i < bpMap.count; i++)
                    {
                        if ((bpMap.bp[i].type & bp_hardware) && bpMap.bp[i].addr == va)
                        {
                            foundBp = bpMap.bp[i];
                            matched = true;
                            break;
                        }
                    }
                }
                else if (reqType == bp_memory)
                {
                    for (int i = 0; i < bpMap.count; i++)
                    {
                        if (bpMap.bp[i].type & bp_memory)
                        {
                            duint start = bpMap.bp[i].addr;
                            duint size = DbgFunctions()->MemBpSize(start);
                            if (size == 0) size = 4096;
                            if (va >= start && va < start + size)
                            {
                                foundBp = bpMap.bp[i];
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                else
                {
                    // No type specified: try software, hardware, memory in priority order
                    for (int i = 0; i < bpMap.count; i++)
                    {
                        if (!(bpMap.bp[i].type & (bp_hardware | bp_memory | bp_dll | bp_exception)) && bpMap.bp[i].addr == va)
                        {
                            foundBp = bpMap.bp[i];
                            matched = true;
                            break;
                        }
                    }
                    if (!matched)
                    {
                        for (int i = 0; i < bpMap.count; i++)
                        {
                            if ((bpMap.bp[i].type & bp_hardware) && bpMap.bp[i].addr == va)
                            {
                                foundBp = bpMap.bp[i];
                                matched = true;
                                break;
                            }
                        }
                    }
                    if (!matched)
                    {
                        for (int i = 0; i < bpMap.count; i++)
                        {
                            if (bpMap.bp[i].type & bp_memory)
                            {
                                duint start = bpMap.bp[i].addr;
                                duint size = DbgFunctions()->MemBpSize(start);
                                if (size == 0) size = 4096;
                                if (va >= start && va < start + size)
                                {
                                    foundBp = bpMap.bp[i];
                                    matched = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    BridgeFree(bpMap.bp);

    if (matched)
    {
        if (outBridgeBp) *outBridgeBp = foundBp;
        if (outRef)
        {
            memset(outRef, 0, sizeof(BP_REF));
            if (foundBp.type & bp_dll)
            {
                DbgFunctions()->BpRefDll(outRef, foundBp.mod);
            }
            else if (foundBp.type & bp_exception)
            {
                DbgFunctions()->BpRefException(outRef, (unsigned int)foundBp.addr);
            }
            else if (foundBp.type & bp_hardware)
            {
                DbgFunctions()->BpRefVa(outRef, bp_hardware, foundBp.addr);
            }
            else if (foundBp.type & bp_memory)
            {
                DbgFunctions()->BpRefVa(outRef, bp_memory, foundBp.addr);
            }
            else
            {
                DbgFunctions()->BpRefVa(outRef, bp_normal, foundBp.addr);
            }
        }
        return true;
    }

    return false;
}

// --------------------------------------------------------------------------
// Part A - Hardware Breakpoints
// --------------------------------------------------------------------------

void handle_set_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    char typeStr[32] = { 0 };
    char typeChar = 'x';
    const char* hwTypeDesc = "execute";
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (_stricmp(typeStr, "execute") == 0 || _stricmp(typeStr, "x") == 0)
        {
            typeChar = 'x';
            hwTypeDesc = "execute";
        }
        else if (_stricmp(typeStr, "write") == 0 || _stricmp(typeStr, "w") == 0)
        {
            typeChar = 'w';
            hwTypeDesc = "write";
        }
        else if (_stricmp(typeStr, "access") == 0 || _stricmp(typeStr, "readwrite") == 0 || _stricmp(typeStr, "r") == 0)
        {
            typeChar = 'r';
            hwTypeDesc = "access";
        }
        else
        {
            responseText = "{\"error\":\"invalid hardware breakpoint type: must be execute, write, or access\"}\n";
            return;
        }
    }

    int size = 1;
    int parsedSize = 0;
    if (json_get_int(readBuf, "size", &parsedSize))
    {
        if (parsedSize == 1 || parsedSize == 2 || parsedSize == 4 || parsedSize == 8)
        {
            size = parsedSize;
        }
        else
        {
            responseText = "{\"error\":\"invalid hardware breakpoint size: must be 1, 2, 4, or 8\"}\n";
            return;
        }
    }

    // Alignment verification
    if ((va % (duint)size) != 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"address 0x%016llX is not aligned to size %d\"}\n",
                  (unsigned long long)va, size);
        responseText = responseBuf;
        return;
    }

    // Check hardware breakpoint list
    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_hardware, &bpMap);
    bool alreadyExists = false;
    int hwCount = bpMap.count;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (bpMap.bp[i].addr == va)
        {
            alreadyExists = true;
            break;
        }
    }
    if (bpMap.bp != nullptr)
    {
        BridgeFree(bpMap.bp);
    }

    if (alreadyExists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"hardware breakpoint already exists at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    if (hwCount >= 4)
    {
        responseText = "{\"error\":\"hardware breakpoint registers exhausted (maximum 4)\"}\n";
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetHardwareBreakpoint 0x%llX, %c, %d",
              (unsigned long long)va, typeChar, size);

    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set hardware breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    // Retrieve created hardware breakpoint details
    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_hardware, &checkMap);
    bool found = false;
    BRIDGEBP createdBp = { 0 };
    for (int i = 0; i < checkMap.count; i++)
    {
        if (checkMap.bp[i].addr == va)
        {
            createdBp = checkMap.bp[i];
            found = true;
            break;
        }
    }
    if (checkMap.bp != nullptr)
    {
        BridgeFree(checkMap.bp);
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to verify hardware breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"type\":\"hardware\",\"hw_type\":\"%s\",\"size\":%d,\"slot\":%u,\"enabled\":%s,\"success\":true}\n",
              (unsigned long long)va,
              hwTypeDesc,
              size,
              (unsigned int)createdBp.slot,
              createdBp.enabled ? "true" : "false");
    responseText = responseBuf;
}

void handle_delete_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_hardware, &bpMap);
    bool exists = false;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (bpMap.bp[i].addr == va)
        {
            exists = true;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    if (!exists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"hardware breakpoint not found at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "DeleteHardwareBreakpoint 0x%llX", (unsigned long long)va);
    DbgCmdExecDirect(cmd);

    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_hardware, &checkMap);
    bool stillExists = false;
    for (int i = 0; i < checkMap.count; i++)
    {
        if (checkMap.bp[i].addr == va)
        {
            stillExists = true;
            break;
        }
    }
    if (checkMap.bp) BridgeFree(checkMap.bp);

    if (stillExists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to delete hardware breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"type\":\"hardware\",\"deleted\":true}\n",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_enable_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_hardware, &bpMap);
    bool exists = false;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (bpMap.bp[i].addr == va)
        {
            exists = true;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    if (!exists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"hardware breakpoint not found at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    bool enable = true;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "enabled", &parsedBool))
    {
        enable = parsedBool;
    }

    char cmd[128] = { 0 };
    if (enable)
    {
        sprintf_s(cmd, sizeof(cmd), "EnableHardwareBreakpoint 0x%llX", (unsigned long long)va);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "DisableHardwareBreakpoint 0x%llX", (unsigned long long)va);
    }

    DbgCmdExecDirect(cmd);

    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_hardware, &checkMap);
    bool isEnabled = enable;
    for (int i = 0; i < checkMap.count; i++)
    {
        if (checkMap.bp[i].addr == va)
        {
            isEnabled = checkMap.bp[i].enabled;
            break;
        }
    }
    if (checkMap.bp) BridgeFree(checkMap.bp);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"type\":\"hardware\",\"enabled\":%s,\"success\":true}\n",
              (unsigned long long)va,
              isEnabled ? "true" : "false");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part B - Memory Breakpoints
// --------------------------------------------------------------------------

void handle_set_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    if (!DbgMemIsValidReadPtr(va))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"address 0x%016llX is not mapped or readable\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char typeStr[32] = { 0 };
    char typeChar = 'a';
    const char* memTypeDesc = "access";
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (_stricmp(typeStr, "access") == 0 || _stricmp(typeStr, "a") == 0)
        {
            typeChar = 'a';
            memTypeDesc = "access";
        }
        else if (_stricmp(typeStr, "read") == 0 || _stricmp(typeStr, "r") == 0)
        {
            typeChar = 'r';
            memTypeDesc = "read";
        }
        else if (_stricmp(typeStr, "write") == 0 || _stricmp(typeStr, "w") == 0)
        {
            typeChar = 'w';
            memTypeDesc = "write";
        }
        else if (_stricmp(typeStr, "execute") == 0 || _stricmp(typeStr, "x") == 0)
        {
            typeChar = 'x';
            memTypeDesc = "execute";
        }
        else
        {
            responseText = "{\"error\":\"invalid memory breakpoint type: must be access, read, write, or execute\"}\n";
            return;
        }
    }

    bool singleshoot = false;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "singleshoot", &parsedBool))
    {
        singleshoot = parsedBool;
    }

    int restoreVal = singleshoot ? 0 : 1;
    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetMemoryBPX 0x%llX, %d, %c",
              (unsigned long long)va, restoreVal, typeChar);

    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set memory breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    // Find the newly created memory breakpoint from BPMAP
    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_memory, &bpMap);
    duint baseAddr = va;
    duint bpSize = 4096;
    bool bpSingleshoot = singleshoot;
    bool bpEnabled = true;

    for (int i = 0; i < bpMap.count; i++)
    {
        duint start = bpMap.bp[i].addr;
        duint size = DbgFunctions()->MemBpSize(start);
        if (size == 0) size = 4096;
        if (va >= start && va < start + size)
        {
            baseAddr = start;
            bpSize = size;
            bpSingleshoot = bpMap.bp[i].singleshoot;
            bpEnabled = bpMap.bp[i].enabled;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"base\":\"0x%016llX\",\"size\":%llu,\"type\":\"%s\",\"singleshoot\":%s,\"enabled\":%s,\"success\":true}\n",
              (unsigned long long)va,
              (unsigned long long)baseAddr,
              (unsigned long long)bpSize,
              memTypeDesc,
              bpSingleshoot ? "true" : "false",
              bpEnabled ? "true" : "false");
    responseText = responseBuf;
}

void handle_set_memory_range_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address parameter\"}\n";
        return;
    }

    duint startVa = 0;
    if (!resolve_address(addrStr, &startVa))
    {
        responseText = "{\"error\":\"invalid address format\"}\n";
        return;
    }

    int rangeSizeInt = 0;
    if (!json_get_int(readBuf, "size", &rangeSizeInt) || rangeSizeInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid size parameter (must be positive integer)\"}\n";
        return;
    }
    duint rangeSize = (duint)rangeSizeInt;
    if (rangeSize > 0x04000000) // 64 MB maximum
    {
        responseText = "{\"error\":\"size exceeds maximum allowed range (64MB)\"}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(startVa))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"address 0x%016llX is not mapped or readable\"}\n",
                  (unsigned long long)startVa);
        responseText = responseBuf;
        return;
    }

    char typeStr[32] = { 0 };
    char typeArg[8] = "a";
    const char* memTypeDesc = "access";
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (_stricmp(typeStr, "access") == 0 || _stricmp(typeStr, "a") == 0)
        {
            strcpy_s(typeArg, "a");
            memTypeDesc = "access";
        }
        else if (_stricmp(typeStr, "read") == 0 || _stricmp(typeStr, "r") == 0)
        {
            strcpy_s(typeArg, "r");
            memTypeDesc = "read";
        }
        else if (_stricmp(typeStr, "write") == 0 || _stricmp(typeStr, "w") == 0)
        {
            strcpy_s(typeArg, "w");
            memTypeDesc = "write";
        }
        else if (_stricmp(typeStr, "execute") == 0 || _stricmp(typeStr, "x") == 0)
        {
            strcpy_s(typeArg, "x");
            memTypeDesc = "execute";
        }
        else
        {
            responseText = "{\"error\":\"invalid memory breakpoint type: must be access, read, write, or execute\"}\n";
            return;
        }
    }

    bool singleshoot = false;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "singleshoot", &parsedBool) && parsedBool)
    {
        singleshoot = true;
        strcat_s(typeArg, "ss");
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetMemoryRangeBPX 0x%llX, 0x%llX, %s",
              (unsigned long long)startVa, (unsigned long long)rangeSize, typeArg);

    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set memory range breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)startVa);
        responseText = responseBuf;
        return;
    }

    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_memory, &bpMap);
    bool bpSingleshoot = singleshoot;
    bool bpEnabled = true;

    for (int i = 0; i < bpMap.count; i++)
    {
        if (bpMap.bp[i].addr == startVa)
        {
            bpSingleshoot = bpMap.bp[i].singleshoot;
            bpEnabled = bpMap.bp[i].enabled;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"size\":%llu,\"type\":\"%s\",\"singleshoot\":%s,\"enabled\":%s,\"success\":true}\n",
              (unsigned long long)startVa,
              (unsigned long long)rangeSize,
              memTypeDesc,
              bpSingleshoot ? "true" : "false",
              bpEnabled ? "true" : "false");
    responseText = responseBuf;
}

void handle_delete_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    // Find the memory breakpoint interval covering this address
    BPMAP bpMap = { 0 };
    int count = DbgGetBpList(bp_memory, &bpMap);
    duint targetBase = 0;
    bool found = false;
    if (count > 0 && bpMap.bp != nullptr)
    {
        for (int i = 0; i < bpMap.count; i++)
        {
            duint start = bpMap.bp[i].addr;
            duint size = DbgFunctions()->MemBpSize(start);
            if (size == 0) size = 4096;
            if (va >= start && va < start + size)
            {
                targetBase = start;
                found = true;
                break;
            }
        }
        BridgeFree(bpMap.bp);
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"memory breakpoint not found at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "DeleteMemoryBPX 0x%llX", (unsigned long long)targetBase);
    DbgCmdExecDirect(cmd);

    // Verify deletion
    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_memory, &checkMap);
    bool stillExists = false;
    for (int i = 0; i < checkMap.count; i++)
    {
        if (checkMap.bp[i].addr == targetBase)
        {
            stillExists = true;
            break;
        }
    }
    if (checkMap.bp) BridgeFree(checkMap.bp);

    if (stillExists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to delete memory breakpoint at address 0x%016llX\"}\n",
                  (unsigned long long)targetBase);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"type\":\"memory\",\"deleted\":true}\n",
              (unsigned long long)targetBase);
    responseText = responseBuf;
}

void handle_enable_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    BPMAP bpMap = { 0 };
    int count = DbgGetBpList(bp_memory, &bpMap);
    duint targetBase = 0;
    bool found = false;
    if (count > 0 && bpMap.bp != nullptr)
    {
        for (int i = 0; i < bpMap.count; i++)
        {
            duint start = bpMap.bp[i].addr;
            duint size = DbgFunctions()->MemBpSize(start);
            if (size == 0) size = 4096;
            if (va >= start && va < start + size)
            {
                targetBase = start;
                found = true;
                break;
            }
        }
        BridgeFree(bpMap.bp);
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"memory breakpoint not found at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    bool enable = true;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "enabled", &parsedBool))
    {
        enable = parsedBool;
    }

    char cmd[128] = { 0 };
    if (enable)
    {
        sprintf_s(cmd, sizeof(cmd), "EnableMemoryBreakpoint 0x%llX", (unsigned long long)targetBase);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "DisableMemoryBreakpoint 0x%llX", (unsigned long long)targetBase);
    }

    DbgCmdExecDirect(cmd);

    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_memory, &checkMap);
    bool isEnabled = enable;
    for (int i = 0; i < checkMap.count; i++)
    {
        if (checkMap.bp[i].addr == targetBase)
        {
            isEnabled = checkMap.bp[i].enabled;
            break;
        }
    }
    if (checkMap.bp) BridgeFree(checkMap.bp);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"type\":\"memory\",\"enabled\":%s,\"success\":true}\n",
              (unsigned long long)targetBase,
              isEnabled ? "true" : "false");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part C - DLL / Librarian Breakpoints
// --------------------------------------------------------------------------

void handle_set_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    char typeStr[32] = { 0 };
    char typeChar = 'a';
    const char* dllTypeDesc = "all";
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (_stricmp(typeStr, "all") == 0 || _stricmp(typeStr, "a") == 0)
        {
            typeChar = 'a';
            dllTypeDesc = "all";
        }
        else if (_stricmp(typeStr, "load") == 0 || _stricmp(typeStr, "l") == 0)
        {
            typeChar = 'l';
            dllTypeDesc = "load";
        }
        else if (_stricmp(typeStr, "unload") == 0 || _stricmp(typeStr, "u") == 0)
        {
            typeChar = 'u';
            dllTypeDesc = "unload";
        }
        else
        {
            responseText = "{\"error\":\"invalid dll breakpoint type: must be all, load, or unload\"}\n";
            return;
        }
    }

    bool singleshoot = false;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "singleshoot", &parsedBool))
    {
        singleshoot = parsedBool;
    }

    // Check if DLL breakpoint already exists in BPMAP
    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_dll, &bpMap);
    bool alreadyExists = false;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (_stricmp(bpMap.bp[i].mod, modStr) == 0 || _stricmp(bpMap.bp[i].name, modStr) == 0)
        {
            alreadyExists = true;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    if (alreadyExists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"DLL breakpoint already exists for module %s\"}\n",
                  modStr);
        responseText = responseBuf;
        return;
    }

    char cmd[128] = { 0 };
    if (singleshoot)
    {
        sprintf_s(cmd, sizeof(cmd), "LibrarianSetBreakpoint %s, %c, 1", modStr, typeChar);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "LibrarianSetBreakpoint %s, %c", modStr, typeChar);
    }

    if (!DbgCmdExecDirect(cmd))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set DLL breakpoint on module %s\"}\n",
                  modStr);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"type\":\"%s\",\"singleshoot\":%s,\"enabled\":true,\"success\":true}\n",
              modStr, dllTypeDesc, singleshoot ? "true" : "false");
    responseText = responseBuf;
}

void handle_delete_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_dll, &bpMap);
    bool exists = false;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (_stricmp(bpMap.bp[i].mod, modStr) == 0 || _stricmp(bpMap.bp[i].name, modStr) == 0)
        {
            exists = true;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    if (!exists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"DLL breakpoint not found for module %s\"}\n",
                  modStr);
        responseText = responseBuf;
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "LibrarianRemoveBreakpoint %s", modStr);
    DbgCmdExecDirect(cmd);

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"deleted\":true}\n",
              modStr);
    responseText = responseBuf;
}

void handle_enable_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    BPMAP bpMap = { 0 };
    DbgGetBpList(bp_dll, &bpMap);
    bool exists = false;
    for (int i = 0; i < bpMap.count; i++)
    {
        if (_stricmp(bpMap.bp[i].mod, modStr) == 0 || _stricmp(bpMap.bp[i].name, modStr) == 0)
        {
            exists = true;
            break;
        }
    }
    if (bpMap.bp) BridgeFree(bpMap.bp);

    if (!exists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"DLL breakpoint not found for module %s\"}\n",
                  modStr);
        responseText = responseBuf;
        return;
    }

    bool enable = true;
    bool parsedBool = false;
    if (json_get_bool(readBuf, "enabled", &parsedBool))
    {
        enable = parsedBool;
    }

    char cmd[128] = { 0 };
    if (enable)
    {
        sprintf_s(cmd, sizeof(cmd), "LibrarianEnableBreakpoint %s", modStr);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "LibrarianDisableBreakpoint %s", modStr);
    }

    DbgCmdExecDirect(cmd);

    BPMAP checkMap = { 0 };
    DbgGetBpList(bp_dll, &checkMap);
    bool isEnabled = enable;
    for (int i = 0; i < checkMap.count; i++)
    {
        if (_stricmp(checkMap.bp[i].mod, modStr) == 0 || _stricmp(checkMap.bp[i].name, modStr) == 0)
        {
            isEnabled = checkMap.bp[i].enabled;
            break;
        }
    }
    if (checkMap.bp) BridgeFree(checkMap.bp);

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"enabled\":%s,\"success\":true}\n",
              modStr, isEnabled ? "true" : "false");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part D - Breakpoint Properties & Details
// --------------------------------------------------------------------------

void handle_get_breakpoint_details(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    json_get_string(readBuf, "address", addrStr, sizeof(addrStr));

    char modStr[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modStr, sizeof(modStr));

    char typeStr[32] = { 0 };
    json_get_string(readBuf, "type", typeStr, sizeof(typeStr));

    if (addrStr[0] == '\0' && modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address or module parameter\"}\n";
        return;
    }

    BP_REF ref = { bp_none };
    BRIDGEBP bp = { 0 };
    if (!find_target_breakpoint(addrStr, modStr, typeStr, &ref, &bp))
    {
        responseText = "{\"error\":\"breakpoint not found\"}\n";
        return;
    }

    const char* bpTypeStr = "software";
    if (bp.type & bp_hardware) bpTypeStr = "hardware";
    else if (bp.type & bp_memory) bpTypeStr = "memory";
    else if (bp.type & bp_dll) bpTypeStr = "dll";
    else if (bp.type & bp_exception) bpTypeStr = "exception";

    char safeName[MAX_BREAKPOINT_SIZE * 2] = { 0 };
    escape_json_string(bp.name, safeName, sizeof(safeName));

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(bp.mod, safeMod, sizeof(safeMod));

    char safeBreakCond[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(bp.breakCondition, safeBreakCond, sizeof(safeBreakCond));

    char safeLogText[MAX_CONDITIONAL_TEXT_SIZE * 2] = { 0 };
    escape_json_string(bp.logText, safeLogText, sizeof(safeLogText));

    char safeLogCond[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(bp.logCondition, safeLogCond, sizeof(safeLogCond));

    char safeCmdText[MAX_CONDITIONAL_TEXT_SIZE * 2] = { 0 };
    escape_json_string(bp.commandText, safeCmdText, sizeof(safeCmdText));

    char safeCmdCond[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(bp.commandCondition, safeCmdCond, sizeof(safeCmdCond));

    int offset = sprintf_s(responseBuf, responseBufSize,
        "{\"type\":\"%s\",\"enabled\":%s,\"singleshoot\":%s,\"active\":%s,\"silent\":%s,\"fast_resume\":%s,\"hit_count\":%u,"
        "\"name\":\"%s\",\"module\":\"%s\",\"break_condition\":\"%s\",\"log_text\":\"%s\",\"log_condition\":\"%s\","
        "\"command_text\":\"%s\",\"command_condition\":\"%s\"",
        bpTypeStr,
        bp.enabled ? "true" : "false",
        bp.singleshoot ? "true" : "false",
        bp.active ? "true" : "false",
        bp.silent ? "true" : "false",
        bp.fastResume ? "true" : "false",
        bp.hitCount,
        safeName,
        safeMod,
        safeBreakCond,
        safeLogText,
        safeLogCond,
        safeCmdText,
        safeCmdCond);

    if (bp.type & bp_hardware)
    {
        const char* hwTypeStr = "execute";
        if (bp.typeEx == hw_write) hwTypeStr = "write";
        else if (bp.typeEx == hw_access) hwTypeStr = "access";

        int hwSize = 1;
        if (bp.hwSize == hw_word) hwSize = 2;
        else if (bp.hwSize == hw_dword) hwSize = 4;
        else if (bp.hwSize == hw_qword) hwSize = 8;

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            ",\"address\":\"0x%016llX\",\"hw_type\":\"%s\",\"hw_size\":%d,\"slot\":%u",
            (unsigned long long)bp.addr, hwTypeStr, hwSize, (unsigned int)bp.slot);
    }
    else if (bp.type & bp_memory)
    {
        const char* memTypeStr = "access";
        if (bp.typeEx == mem_read) memTypeStr = "read";
        else if (bp.typeEx == mem_write) memTypeStr = "write";
        else if (bp.typeEx == mem_execute) memTypeStr = "execute";

        duint memSize = DbgFunctions()->MemBpSize(bp.addr);
        if (memSize == 0) memSize = 4096;
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            ",\"address\":\"0x%016llX\",\"mem_type\":\"%s\",\"mem_size\":%llu",
            (unsigned long long)bp.addr, memTypeStr, (unsigned long long)memSize);
    }
    else if (bp.type & bp_dll)
    {
        const char* dllTypeStr = "all";
        if (bp.typeEx == dll_load) dllTypeStr = "load";
        else if (bp.typeEx == dll_unload) dllTypeStr = "unload";

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            ",\"dll_type\":\"%s\"", dllTypeStr);
    }
    else if (bp.type & bp_exception)
    {
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            ",\"exception_code\":\"0x%08X\"", (unsigned int)bp.addr);
    }
    else
    {
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            ",\"address\":\"0x%016llX\"", (unsigned long long)bp.addr);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, ",\"success\":true}\n");
    responseText = responseBuf;
}

void handle_configure_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    json_get_string(readBuf, "address", addrStr, sizeof(addrStr));

    char modStr[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modStr, sizeof(modStr));

    char typeStr[32] = { 0 };
    json_get_string(readBuf, "type", typeStr, sizeof(typeStr));

    if (addrStr[0] == '\0' && modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address or module parameter\"}\n";
        return;
    }

    BP_REF ref = { bp_none };
    BRIDGEBP bp = { 0 };
    if (!find_target_breakpoint(addrStr, modStr, typeStr, &ref, &bp))
    {
        responseText = "{\"error\":\"breakpoint not found\"}\n";
        return;
    }

    char valStr[MAX_CONDITIONAL_TEXT_SIZE] = { 0 };
    bool boolVal = false;

    // singleshoot
    if (json_get_bool(readBuf, "singleshoot", &boolVal))
    {
        ref.SetField(bpf_singleshoot, (duint)(boolVal ? 1 : 0));
    }

    // silent
    if (json_get_bool(readBuf, "silent", &boolVal))
    {
        ref.SetField(bpf_silent, (duint)(boolVal ? 1 : 0));
    }

    // fast_resume
    if (json_get_bool(readBuf, "fast_resume", &boolVal))
    {
        ref.SetField(bpf_fastresume, (duint)(boolVal ? 1 : 0));
    }

    // name
    if (json_get_string(readBuf, "name", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_name, std::string(valStr));
    }

    // break_condition
    if (json_get_string(readBuf, "break_condition", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_breakcondition, std::string(valStr));
    }

    // log_text
    if (json_get_string(readBuf, "log_text", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_logtext, std::string(valStr));
    }

    // log_condition
    if (json_get_string(readBuf, "log_condition", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_logcondition, std::string(valStr));
    }

    // command_text
    if (json_get_string(readBuf, "command_text", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_commandtext, std::string(valStr));
    }

    // command_condition
    if (json_get_string(readBuf, "command_condition", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_commandcondition, std::string(valStr));
    }

    // log_file
    if (json_get_string(readBuf, "log_file", valStr, sizeof(valStr)))
    {
        ref.SetField(bpf_logfile, std::string(valStr));
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"target\":\"%s\",\"configured\":true,\"success\":true}\n",
              (modStr[0] != '\0') ? modStr : addrStr);
    responseText = responseBuf;
}

void handle_reset_breakpoint_hit_count(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    json_get_string(readBuf, "address", addrStr, sizeof(addrStr));

    char modStr[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modStr, sizeof(modStr));

    char typeStr[32] = { 0 };
    json_get_string(readBuf, "type", typeStr, sizeof(typeStr));

    if (addrStr[0] == '\0' && modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address or module parameter\"}\n";
        return;
    }

    BP_REF ref = { bp_none };
    BRIDGEBP bp = { 0 };
    if (!find_target_breakpoint(addrStr, modStr, typeStr, &ref, &bp))
    {
        responseText = "{\"error\":\"breakpoint not found\"}\n";
        return;
    }

    // Direct update via BP_REF API
    ref.SetField(bpf_hitcount, 0);

    // Command dispatch defense in depth
    char cmd[128] = { 0 };
    if (bp.type & bp_hardware)
    {
        sprintf_s(cmd, sizeof(cmd), "ResetHardwareBreakpointHitCount 0x%llX", (unsigned long long)bp.addr);
    }
    else if (bp.type & bp_memory)
    {
        sprintf_s(cmd, sizeof(cmd), "ResetMemoryBreakpointHitCount 0x%llX", (unsigned long long)bp.addr);
    }
    else if (bp.type & bp_dll)
    {
        sprintf_s(cmd, sizeof(cmd), "ResetLibrarianBreakpointHitCount %s", bp.mod);
    }
    else if (bp.type & bp_exception)
    {
        sprintf_s(cmd, sizeof(cmd), "ResetExceptionBreakpointHitCount 0x%X", (unsigned int)bp.addr);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "ResetBreakpointHitCount 0x%llX", (unsigned long long)bp.addr);
    }
    DbgCmdExecDirect(cmd);

    sprintf_s(responseBuf, responseBufSize,
              "{\"target\":\"%s\",\"hit_count\":0,\"success\":true}\n",
              (modStr[0] != '\0') ? modStr : addrStr);
    responseText = responseBuf;
}
