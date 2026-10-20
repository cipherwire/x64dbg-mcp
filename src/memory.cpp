#include "memory.h"

// Strict parser for memory region address parameter (supports strict hex and paused register aliases)
bool parse_memory_region_address(const char* addrStr, duint* outVa)
{
    if (addrStr == nullptr) return false;
    while (*addrStr == ' ' || *addrStr == '\t') addrStr++;
    if (*addrStr == '\0') return false;

    // Reject negative addresses explicitly
    if (*addrStr == '-') return false;

    const char* pHex = addrStr;
    bool has0x = false;
    if (pHex[0] == '0' && (pHex[1] == 'x' || pHex[1] == 'X'))
    {
        pHex += 2;
        has0x = true;
    }

    if (has0x)
    {
        if (*pHex == '\0') return false; // "0x"
        const char* p = pHex;
        while (*p)
        {
            if (!isxdigit((unsigned char)*p))
                return false; // e.g. "0x1234garbage"
            p++;
        }
        const char* pTrimmed = pHex;
        while (*pTrimmed == '0' && *(pTrimmed + 1) != '\0') pTrimmed++;
        if (strlen(pTrimmed) > 16) return false;

        char* endPtr = nullptr;
        errno = 0;
        unsigned __int64 val = _strtoui64(pHex, &endPtr, 16);
        if (errno == ERANGE || endPtr == pHex || *endPtr != '\0')
            return false;

        *outVa = (duint)val;
        return true;
    }

    // Bare hex without 0x
    bool allHex = true;
    const char* p = pHex;
    while (*p)
    {
        if (!isxdigit((unsigned char)*p))
        {
            allHex = false;
            break;
        }
        p++;
    }

    if (allHex && *pHex != '\0')
    {
        const char* pTrimmed = pHex;
        while (*pTrimmed == '0' && *(pTrimmed + 1) != '\0') pTrimmed++;
        if (strlen(pTrimmed) > 16) return false;

        char* endPtr = nullptr;
        errno = 0;
        unsigned __int64 val = _strtoui64(pHex, &endPtr, 16);
        if (errno == ERANGE || endPtr == pHex || *endPtr != '\0')
            return false;

        *outVa = (duint)val;
        return true;
    }

    // Register aliases ("rip", "rsp", etc.) only when paused
    if (DbgIsDebugging() && !DbgIsRunning())
    {
        if (_stricmp(addrStr, "rip") == 0 || _stricmp(addrStr, "rsp") == 0 ||
            _stricmp(addrStr, "rax") == 0 || _stricmp(addrStr, "rbx") == 0 ||
            _stricmp(addrStr, "rcx") == 0 || _stricmp(addrStr, "rdx") == 0 ||
            _stricmp(addrStr, "rbp") == 0 || _stricmp(addrStr, "rsi") == 0 ||
            _stricmp(addrStr, "rdi") == 0)
        {
            return resolve_address(addrStr, outVa);
        }
    }

    return false;
}

// Helper to decode a Windows page protection DWORD into string and raw integer representation
void decode_protection_string(DWORD protect, char* outStr, size_t outStrSize, char* outRawStr, size_t outRawStrSize)
{
    char protDesc[128] = { 0 };
    DWORD baseProt = protect & 0xFF;
    switch (baseProt)
    {
    case PAGE_NOACCESS:          strcpy_s(protDesc, "PAGE_NOACCESS"); break;
    case PAGE_READONLY:          strcpy_s(protDesc, "PAGE_READONLY"); break;
    case PAGE_READWRITE:         strcpy_s(protDesc, "PAGE_READWRITE"); break;
    case PAGE_WRITECOPY:         strcpy_s(protDesc, "PAGE_WRITECOPY"); break;
    case PAGE_EXECUTE:           strcpy_s(protDesc, "PAGE_EXECUTE"); break;
    case PAGE_EXECUTE_READ:      strcpy_s(protDesc, "PAGE_EXECUTE_READ"); break;
    case PAGE_EXECUTE_READWRITE: strcpy_s(protDesc, "PAGE_EXECUTE_READWRITE"); break;
    case PAGE_EXECUTE_WRITECOPY: strcpy_s(protDesc, "PAGE_EXECUTE_WRITECOPY"); break;
    default:
        if (baseProt == 0) strcpy_s(protDesc, "PAGE_NOACCESS");
        else sprintf_s(protDesc, sizeof(protDesc), "0x%02X", baseProt);
        break;
    }

    if (protect & PAGE_GUARD)        strcat_s(protDesc, " | PAGE_GUARD");
    if (protect & PAGE_NOCACHE)      strcat_s(protDesc, " | PAGE_NOCACHE");
    if (protect & PAGE_WRITECOMBINE) strcat_s(protDesc, " | PAGE_WRITECOMBINE");

    sprintf_s(outStr, outStrSize, "\"%s\"", protDesc);
    sprintf_s(outRawStr, outRawStrSize, "%u", (unsigned int)protect);
}

// Formats a single region entry for list_memory_regions matching Phase 9D schema
void format_memory_region_entry(const MEMORY_BASIC_INFORMATION& mbi, char* buf, size_t bufSize)
{
    const char* stateStr = "UNKNOWN";
    if (mbi.State == MEM_COMMIT)       stateStr = "MEM_COMMIT";
    else if (mbi.State == MEM_RESERVE) stateStr = "MEM_RESERVE";
    else if (mbi.State == MEM_FREE)    stateStr = "MEM_FREE";

    char allocBaseStr[32] = "null";
    if (mbi.State != MEM_FREE)
    {
        sprintf_s(allocBaseStr, sizeof(allocBaseStr), "\"0x%016llX\"", (unsigned long long)mbi.AllocationBase);
    }

    char typeStr[32] = "null";
    char typeRawStr[32] = "null";
    if (mbi.State != MEM_FREE)
    {
        if (mbi.Type == MEM_IMAGE)        strcpy_s(typeStr, "\"MEM_IMAGE\"");
        else if (mbi.Type == MEM_MAPPED)  strcpy_s(typeStr, "\"MEM_MAPPED\"");
        else if (mbi.Type == MEM_PRIVATE) strcpy_s(typeStr, "\"MEM_PRIVATE\"");
        else                              strcpy_s(typeStr, "\"UNKNOWN\"");
        sprintf_s(typeRawStr, sizeof(typeRawStr), "%u", (unsigned int)mbi.Type);
    }

    char allocProtStr[128] = "null";
    char allocProtRawStr[32] = "null";
    if (mbi.State != MEM_FREE && mbi.AllocationProtect != 0)
    {
        decode_protection_string(mbi.AllocationProtect, allocProtStr, sizeof(allocProtStr), allocProtRawStr, sizeof(allocProtRawStr));
    }

    char protectStr[128] = "null";
    char protectRawStr[32] = "null";
    if (mbi.State == MEM_COMMIT)
    {
        decode_protection_string(mbi.Protect, protectStr, sizeof(protectStr), protectRawStr, sizeof(protectRawStr));
    }

    sprintf_s(buf, bufSize,
        "{"
        "\"base\":\"0x%016llX\","
        "\"allocation_base\":%s,"
        "\"size\":%llu,"
        "\"state\":\"%s\","
        "\"state_raw\":%u,"
        "\"allocation_protect\":%s,"
        "\"allocation_protect_raw\":%s,"
        "\"protect\":%s,"
        "\"protect_raw\":%s,"
        "\"type\":%s,"
        "\"type_raw\":%s"
        "}",
        (unsigned long long)mbi.BaseAddress,
        allocBaseStr,
        (unsigned long long)mbi.RegionSize,
        stateStr,
        (unsigned int)mbi.State,
        allocProtStr,
        allocProtRawStr,
        protectStr,
        protectRawStr,
        typeStr,
        typeRawStr);
}

// Formats a MEMORY_BASIC_INFORMATION struct into JSON matching Phase 9C specifications
void format_memory_region_json(duint va, const MEMORY_BASIC_INFORMATION& mbi, char* buf, size_t bufSize)
{
    const char* stateStr = "UNKNOWN";
    if (mbi.State == MEM_COMMIT)       stateStr = "MEM_COMMIT";
    else if (mbi.State == MEM_RESERVE) stateStr = "MEM_RESERVE";
    else if (mbi.State == MEM_FREE)    stateStr = "MEM_FREE";

    char allocBaseStr[32] = "null";
    if (mbi.State != MEM_FREE)
    {
        sprintf_s(allocBaseStr, sizeof(allocBaseStr), "\"0x%016llX\"", (unsigned long long)mbi.AllocationBase);
    }

    char typeStr[32] = "null";
    char typeRawStr[32] = "null";
    if (mbi.State != MEM_FREE)
    {
        if (mbi.Type == MEM_IMAGE)        strcpy_s(typeStr, "\"MEM_IMAGE\"");
        else if (mbi.Type == MEM_MAPPED)  strcpy_s(typeStr, "\"MEM_MAPPED\"");
        else if (mbi.Type == MEM_PRIVATE) strcpy_s(typeStr, "\"MEM_PRIVATE\"");
        else                              strcpy_s(typeStr, "\"UNKNOWN\"");
        sprintf_s(typeRawStr, sizeof(typeRawStr), "%u", (unsigned int)mbi.Type);
    }

    char protectStr[128] = "null";
    char protectRawStr[32] = "null";
    if (mbi.State == MEM_COMMIT)
    {
        decode_protection_string(mbi.Protect, protectStr, sizeof(protectStr), protectRawStr, sizeof(protectRawStr));
    }

    sprintf_s(buf, bufSize,
        "{\"address\":\"0x%016llX\",\"region\":{"
        "\"base\":\"0x%016llX\","
        "\"allocation_base\":%s,"
        "\"size\":%llu,"
        "\"state\":\"%s\","
        "\"state_raw\":%u,"
        "\"protect\":%s,"
        "\"protect_raw\":%s,"
        "\"type\":%s,"
        "\"type_raw\":%s"
        "}}\n",
        (unsigned long long)va,
        (unsigned long long)mbi.BaseAddress,
        allocBaseStr,
        (unsigned long long)mbi.RegionSize,
        stateStr,
        (unsigned int)mbi.State,
        protectStr,
        protectRawStr,
        typeStr,
        typeRawStr);
}

void handle_read_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] read_memory: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] read_memory: debuggee is currently running.\n");
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
                int size = 64;
                json_get_int(readBuf, "size", &size);

                if (size <= 0 || size > 4096)
                {
                    responseText = "{\"error\":\"invalid size: must be between 1 and 4096 bytes\"}\n";
                }
                else
                {
                    unsigned char memBuf[4096] = { 0 };
                    bool memReadOk = DbgMemRead(va, memBuf, (duint)size);
                    if (!memReadOk)
                    {
                        _plugin_logprintf("[x64dbg-MCP] DbgMemRead failed at 0x%016llX (size %d)\n",
                                          (unsigned long long)va, size);
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"error\":\"memory read failed at address 0x%016llX\"}\n",
                                  (unsigned long long)va);
                        responseText = responseBuf;
                    }
                    else
                    {
                        int headerLen = sprintf_s(responseBuf, responseBufSize,
                            "{\"address\":\"0x%016llX\",\"size\":%d,\"hex\":\"",
                            (unsigned long long)va, size);

                        static const char hexChars[] = "0123456789abcdef";
                        char* dst = responseBuf + headerLen;
                        for (int i = 0; i < size; i++)
                        {
                            *dst++ = hexChars[(memBuf[i] >> 4) & 0x0F];
                            *dst++ = hexChars[memBuf[i] & 0x0F];
                        }
                        *dst++ = '\"';
                        *dst++ = '}';
                        *dst++ = '\n';
                        *dst = '\0';
                        responseText = responseBuf;

                        _plugin_logprintf("[x64dbg-MCP] Memory read success: 0x%016llX (%d bytes)\n",
                                          (unsigned long long)va, size);
                    }
                }
            }
        }
    }
}

void handle_get_memory_region(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_memory_region: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        char addrStr[64] = { 0 };
        if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
        {
            responseText = "{\"error\":\"missing address parameter\"}\n";
        }
        else
        {
            duint va = 0;
            if (!parse_memory_region_address(addrStr, &va))
            {
                responseText = "{\"error\":\"invalid address format\"}\n";
            }
            else
            {
                HANDLE hProcess = DbgGetProcessHandle();
                if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE)
                {
                    responseText = "{\"error\":\"invalid process handle\"}\n";
                }
                else
                {
                    MEMORY_BASIC_INFORMATION mbi = { 0 };
                    SIZE_T queried = VirtualQueryEx(hProcess, (LPCVOID)va, &mbi, sizeof(mbi));
                    if (queried == 0)
                    {
                        sprintf_s(responseBuf, responseBufSize,
                                  "{\"error\":\"memory query failed\",\"address\":\"0x%016llX\"}\n",
                                  (unsigned long long)va);
                        responseText = responseBuf;
                    }
                    else
                    {
                        format_memory_region_json(va, mbi, responseBuf, responseBufSize);
                        responseText = responseBuf;

                        _plugin_logprintf("[x64dbg-MCP] get_memory_region for 0x%016llX: base=0x%p size=%llu state=0x%X\n",
                                          (unsigned long long)va, mbi.BaseAddress,
                                          (unsigned long long)mbi.RegionSize, (unsigned int)mbi.State);
                    }
                }
            }
        }
    }
}

void handle_list_memory_regions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_memory_regions: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        HANDLE hProcess = DbgGetProcessHandle();
        if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE)
        {
            responseText = "{\"error\":\"invalid process handle\"}\n";
        }
        else
        {
            char addrStr[64] = { 0 };
            duint startAddr = 0;
            bool hasStartAddr = false;

            if (json_get_string(readBuf, "start_address", addrStr, sizeof(addrStr)))
            {
                if (addrStr[0] == '\0' || !parse_memory_region_address(addrStr, &startAddr))
                {
                    responseText = "{\"error\":\"invalid address format\"}\n";
                }
                else
                {
                    hasStartAddr = true;
                }
            }

            int limit = 256;
            int parsedLimit = 0;
            if (responseText == nullptr && json_get_int(readBuf, "limit", &parsedLimit))
            {
                if (parsedLimit <= 0 || parsedLimit > 1024)
                {
                    responseText = "{\"error\":\"invalid limit: must be between 1 and 1024\"}\n";
                }
                else
                {
                    limit = parsedLimit;
                }
            }

            bool includeFree = false;
            json_get_bool(readBuf, "include_free", &includeFree);

            if (responseText == nullptr)
            {
                std::vector<MEMORY_BASIC_INFORMATION> regionList;
                regionList.reserve(min((size_t)limit, (size_t)256));

                duint current = startAddr;
                bool has_more = false;
                duint next_address = 0;
                bool traversalError = false;

                // Max regions that safely fit into responseBuf (65536) without any truncation
                const size_t maxRegionsFit = 180;
                size_t effectiveLimit = min((size_t)limit, maxRegionsFit);

                size_t iterations = 0;
                const size_t MAX_ITERATIONS = 100000;

                while (regionList.size() < effectiveLimit && iterations++ < MAX_ITERATIONS)
                {
                    if (!DbgIsDebugging())
                    {
                        responseText = "{\"error\":\"debuggee detached during enumeration\"}\n";
                        traversalError = true;
                        break;
                    }

                    MEMORY_BASIC_INFORMATION mbi = { 0 };
                    SIZE_T numBytes = VirtualQueryEx(hProcess, (LPCVOID)current, &mbi, sizeof(mbi));

                    if (numBytes == 0)
                    {
                        DWORD queryErr = GetLastError();
                        if (!DbgIsDebugging() || queryErr == ERROR_INVALID_HANDLE)
                        {
                            responseText = "{\"error\":\"debuggee process unavailable\"}\n";
                            traversalError = true;
                            break;
                        }
                        else if (queryErr == ERROR_INVALID_PARAMETER)
                        {
                            // If this query failed on the initial requested start address, treat as query error
                            if (hasStartAddr && iterations == 1 && regionList.empty())
                            {
                                sprintf_s(responseBuf, responseBufSize,
                                          "{\"error\":\"memory query failed\",\"address\":\"0x%016llX\"}\n",
                                          (unsigned long long)current);
                                responseText = responseBuf;
                                traversalError = true;
                                break;
                            }
                            // Normal end of user space traversal
                            has_more = false;
                            next_address = 0;
                            break;
                        }
                        else
                        {
                            sprintf_s(responseBuf, responseBufSize,
                                      "{\"error\":\"memory query failed during traversal\",\"code\":%u}\n", queryErr);
                            responseText = responseBuf;
                            traversalError = true;
                            break;
                        }
                    }

                    duint regionBase = (duint)mbi.BaseAddress;
                    duint regionSize = (duint)mbi.RegionSize;

                    if (regionSize == 0 || (regionBase + regionSize) <= regionBase || (regionBase + regionSize) <= current)
                    {
                        responseText = "{\"error\":\"traversal anomaly: invalid region progression\"}\n";
                        traversalError = true;
                        break;
                    }

                    duint next = regionBase + regionSize;

                    if (mbi.State != MEM_FREE || includeFree)
                    {
                        regionList.push_back(mbi);
                    }

                    current = next;
                }

                if (!traversalError)
                {
                    if (regionList.size() >= effectiveLimit)
                    {
                        if (includeFree)
                        {
                            MEMORY_BASIC_INFORMATION probeMbi = { 0 };
                            if (VirtualQueryEx(hProcess, (LPCVOID)current, &probeMbi, sizeof(probeMbi)) != 0)
                            {
                                has_more = true;
                                next_address = current;
                            }
                            else
                            {
                                has_more = false;
                                next_address = 0;
                            }
                        }
                        else
                        {
                            duint probeAddr = current;
                            bool foundNonFree = false;
                            size_t probeIter = 0;
                            while (probeAddr != 0 && probeIter++ < 10000)
                            {
                                MEMORY_BASIC_INFORMATION probeMbi = { 0 };
                                if (VirtualQueryEx(hProcess, (LPCVOID)probeAddr, &probeMbi, sizeof(probeMbi)) == 0)
                                    break;

                                if (probeMbi.State != MEM_FREE)
                                {
                                    foundNonFree = true;
                                    break;
                                }

                                duint probeNext = (duint)probeMbi.BaseAddress + (duint)probeMbi.RegionSize;
                                if (probeNext <= probeAddr || probeNext <= (duint)probeMbi.BaseAddress)
                                    break;

                                probeAddr = probeNext;
                            }

                            if (foundNonFree)
                            {
                                has_more = true;
                                next_address = current;
                            }
                            else
                            {
                                has_more = false;
                                next_address = 0;
                            }
                        }
                    }

                    char nextAddrStr[32] = "null";
                    if (has_more)
                    {
                        sprintf_s(nextAddrStr, sizeof(nextAddrStr), "\"0x%016llX\"", (unsigned long long)next_address);
                    }

                    int written = sprintf_s(responseBuf, responseBufSize,
                        "{\"start_address\":\"0x%016llX\",\"count\":%zu,\"has_more\":%s,\"next_address\":%s,\"regions\":[",
                        (unsigned long long)startAddr,
                        regionList.size(),
                        has_more ? "true" : "false",
                        nextAddrStr);
                    (void)written;

                    for (size_t i = 0; i < regionList.size(); ++i)
                    {
                        char regionJson[384] = { 0 };
                        format_memory_region_entry(regionList[i], regionJson, sizeof(regionJson));

                        if (i > 0)
                        {
                            strcat_s(responseBuf, responseBufSize, ",");
                        }
                        strcat_s(responseBuf, responseBufSize, regionJson);
                    }

                    strcat_s(responseBuf, responseBufSize, "]}\n");
                    responseText = responseBuf;

                    _plugin_logprintf("[x64dbg-MCP] list_memory_regions: returned %zu regions (has_more=%d, next=%s)\n",
                                      regionList.size(), has_more ? 1 : 0, nextAddrStr);
                }
            }
        }
    }
}

bool parse_hex_bytes(const char* hexStr, unsigned char* outBuf, size_t maxLen, size_t* outLen)
{
    if (!hexStr || !outBuf || !outLen || maxLen == 0)
        return false;

    *outLen = 0;
    const char* p = hexStr;
    size_t count = 0;

    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    while (*p)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',')
            p++;
        if (*p == '\0')
            break;

        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
        }

        int h1 = hexVal(*p++);
        if (h1 < 0) return false;

        if (*p == '\0' || *p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',')
        {
            if (count >= maxLen) return false;
            outBuf[count++] = (unsigned char)h1;
            continue;
        }

        int h2 = hexVal(*p++);
        if (h2 < 0) return false;

        if (count >= maxLen) return false;
        outBuf[count++] = (unsigned char)((h1 << 4) | h2);
    }

    if (count == 0)
        return false;

    *outLen = count;
    return true;
}

void handle_write_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] write_memory: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] write_memory: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        char addrStr[64] = { 0 };
        if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
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
                char dataStr[8192] = { 0 };
                if (!json_get_string(readBuf, "data", dataStr, sizeof(dataStr)) || dataStr[0] == '\0')
                {
                    responseText = "{\"error\":\"missing or empty data parameter\"}\n";
                }
                else
                {
                    unsigned char bytes[4096] = { 0 };
                    size_t byteCount = 0;
                    if (!parse_hex_bytes(dataStr, bytes, sizeof(bytes), &byteCount))
                    {
                        responseText = "{\"error\":\"invalid hex bytes in data parameter\"}\n";
                    }
                    else if (byteCount == 0 || byteCount > 4096)
                    {
                        responseText = "{\"error\":\"data size must be between 1 and 4096 bytes\"}\n";
                    }
                    else
                    {
                        bool verify = true;
                        bool parsedVerify = false;
                        if (json_get_bool(readBuf, "verify", &parsedVerify))
                        {
                            verify = parsedVerify;
                        }

                        bool writeOk = DbgMemWrite(va, bytes, (duint)byteCount);
                        if (!writeOk)
                        {
                            _plugin_logprintf("[x64dbg-MCP] DbgMemWrite failed at 0x%016llX (size %zu)\n",
                                              (unsigned long long)va, byteCount);
                            sprintf_s(responseBuf, responseBufSize,
                                      "{\"error\":\"memory write failed at address 0x%016llX\"}\n",
                                      (unsigned long long)va);
                            responseText = responseBuf;
                        }
                        else
                        {
                            bool verified = true;
                            const char* verifyErr = nullptr;

                            if (verify)
                            {
                                unsigned char readback[4096] = { 0 };
                                bool readOk = DbgMemRead(va, readback, (duint)byteCount);
                                if (!readOk)
                                {
                                    verified = false;
                                    verifyErr = "readback failed after write";
                                }
                                else if (memcmp(bytes, readback, byteCount) != 0)
                                {
                                    verified = false;
                                    verifyErr = "readback verification failed: memory content does not match written data";
                                }
                            }

                            // Format written_hex string
                            static const char hexChars[] = "0123456789abcdef";
                            char writtenHex[8192] = { 0 };
                            if (byteCount * 2 < sizeof(writtenHex))
                            {
                                for (size_t i = 0; i < byteCount; i++)
                                {
                                    writtenHex[i * 2] = hexChars[(bytes[i] >> 4) & 0x0F];
                                    writtenHex[i * 2 + 1] = hexChars[bytes[i] & 0x0F];
                                }
                                writtenHex[byteCount * 2] = '\0';
                            }

                            if (!verified)
                            {
                                sprintf_s(responseBuf, responseBufSize,
                                    "{\"address\":\"0x%016llX\",\"bytes_written\":%zu,\"verified\":false,\"verify_error\":\"%s\"}\n",
                                    (unsigned long long)va, byteCount, verifyErr);
                            }
                            else
                            {
                                sprintf_s(responseBuf, responseBufSize,
                                    "{\"address\":\"0x%016llX\",\"bytes_written\":%zu,\"written_hex\":\"%s\",\"verified\":true}\n",
                                    (unsigned long long)va, byteCount, writtenHex);
                            }
                            responseText = responseBuf;

                            _plugin_logprintf("[x64dbg-MCP] write_memory success at 0x%016llX (%zu bytes, verified=%d)\n",
                                              (unsigned long long)va, byteCount, verified ? 1 : 0);
                        }
                    }
                }
            }
        }
    }
}

void handle_test_raw_memread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    // Experimental check of raw DbgMemRead return behavior without state guard
    unsigned char dummy[16] = { 0 };
    bool rawOk = DbgMemRead(0x140000000, dummy, sizeof(dummy));
    sprintf_s(responseBuf, responseBufSize,
              "{\"raw_return\":%s}\n", rawOk ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_page_rights(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_page_rights: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char addrStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing or invalid 'address' parameter\"}\n";
        return;
    }

    duint va = 0;
    if (!parse_memory_region_address(addrStr, &va) && !resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":\"invalid address format\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetPageRights == nullptr)
    {
        responseText = "{\"error\":\"GetPageRights API not available\"}\n";
        return;
    }

    char rights[64] = { 0 };
    bool ok = dbg->GetPageRights(va, rights);

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    HANDLE hProc = DbgGetProcessHandle();
    SIZE_T qRet = (hProc != NULL) ? VirtualQueryEx(hProc, (LPCVOID)va, &mbi, sizeof(mbi)) : 0;
    bool mapped = (qRet != 0 && mbi.State != MEM_FREE);

    if (!ok && !mapped)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"address\":\"0x%016llX\",\"found\":false}\n",
            (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char allocProtStr[128] = "\"null\"";
    char allocProtRawStr[32] = "0";
    if (mbi.AllocationProtect != 0)
    {
        decode_protection_string(mbi.AllocationProtect, allocProtStr, sizeof(allocProtStr), allocProtRawStr, sizeof(allocProtRawStr));
    }

    char protectStr[128] = "\"null\"";
    char protectRawStr[32] = "0";
    if (mbi.State == MEM_COMMIT)
    {
        decode_protection_string(mbi.Protect, protectStr, sizeof(protectStr), protectRawStr, sizeof(protectRawStr));
    }

    char safeRights[128] = { 0 };
    escape_json_string(rights, safeRights, sizeof(safeRights));

    sprintf_s(responseBuf, responseBufSize,
        "{\"address\":\"0x%016llX\",\"found\":true,\"page_rights\":\"%s\","
        "\"allocation_protect\":%s,\"allocation_protect_raw\":%s,"
        "\"protect\":%s,\"protect_raw\":%s}\n",
        (unsigned long long)va,
        safeRights,
        allocProtStr, allocProtRawStr,
        protectStr, protectRawStr);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_page_rights at 0x%016llX: %s\n", (unsigned long long)va, safeRights);
}

void handle_list_heaps(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_heaps: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] list_heaps: debuggee is running.\n");
        responseText = "{\"error\":\"debuggee is running; heaps only available when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumHeaps == nullptr)
    {
        responseText = "{\"error\":\"EnumHeaps API not available\"}\n";
        return;
    }

    BridgeList<HEAPINFO> heapList;
    bool ok = dbg->EnumHeaps(&heapList);
    int count = ok ? heapList.Count() : 0;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"heaps\":[", count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 512; i++)
    {
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            "%s{\"address\":\"0x%016llX\",\"size\":%llu,\"flags\":\"0x%08llX\"}",
            (i > 0 ? "," : ""),
            (unsigned long long)heapList[i].addr,
            (unsigned long long)heapList[i].size,
            (unsigned long long)heapList[i].flags);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;

    heapList.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] list_heaps: %d heaps enumerated.\n", count);
}

void handle_set_page_rights(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing address parameter\"}}\n";
        return;
    }

    duint targetVA = 0;
    if (!parse_memory_region_address(addrStr, &targetVA) && !resolve_address(addrStr, &targetVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    char rightsStr[64] = { 0 };
    if (!json_get_string(readBuf, "rights", rightsStr, sizeof(rightsStr)) || rightsStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing rights parameter\"}}\n";
        return;
    }

    bool guard = false;
    json_get_bool(readBuf, "guard", &guard);

    char fullRights[64] = { 0 };
    if (guard && rightsStr[0] != 'G' && rightsStr[0] != 'g')
    {
        sprintf_s(fullRights, sizeof(fullRights), "G%s", rightsStr);
    }
    else
    {
        strncpy_s(fullRights, rightsStr, _TRUNCATE);
    }

    // Align to page boundary
    duint pageBase = targetVA & ~((duint)0xFFF);

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetPageRights == nullptr || dbg->SetPageRights == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Page rights API not available\"}}\n";
        return;
    }

    char prevRights[64] = { 0 };
    dbg->GetPageRights(pageBase, prevRights);

    MEMORY_BASIC_INFORMATION prevMbi = { 0 };
    HANDLE hProc = DbgGetProcessHandle();
    if (hProc)
    {
        VirtualQueryEx(hProc, (LPCVOID)pageBase, &prevMbi, sizeof(prevMbi));
    }

    if (prevMbi.State == MEM_FREE)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Cannot set page rights on unallocated MEM_FREE memory\"}}\n";
        return;
    }

    bool ok = dbg->SetPageRights(pageBase, fullRights);
    if (!ok)
    {
        char cmd[128];
        sprintf_s(cmd, sizeof(cmd), "setpagerights 0x%llX, \"%s\"", (unsigned long long)pageBase, fullRights);
        ok = DbgCmdExecDirect(cmd);
    }

    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to set page rights; check requested rights syntax\"}}\n";
        return;
    }

    if (dbg->MemUpdateMap)
    {
        dbg->MemUpdateMap();
    }
    GuiUpdateMemoryView();

    char newRights[64] = { 0 };
    dbg->GetPageRights(pageBase, newRights);

    MEMORY_BASIC_INFORMATION newMbi = { 0 };
    if (hProc)
    {
        VirtualQueryEx(hProc, (LPCVOID)pageBase, &newMbi, sizeof(newMbi));
    }

    char protectStr[128] = "\"null\"";
    char protectRawStr[32] = "0";
    if (newMbi.Protect != 0)
    {
        decode_protection_string(newMbi.Protect, protectStr, sizeof(protectStr), protectRawStr, sizeof(protectRawStr));
    }

    char safePrev[128] = { 0 };
    char safeNew[128] = { 0 };
    escape_json_string(prevRights, safePrev, sizeof(safePrev));
    escape_json_string(newRights, safeNew, sizeof(safeNew));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"page_base\":\"0x%016llX\",\"previous_rights\":\"%s\",\"new_rights\":\"%s\",\"protect\":%s,\"protect_raw\":%s,\"success\":true}\n",
              (unsigned long long)targetVA,
              (unsigned long long)pageBase,
              safePrev,
              safeNew,
              protectStr,
              protectRawStr);
    responseText = responseBuf;
}

void handle_allocate_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    int sizeInt = 0x1000;
    json_get_int(readBuf, "size", &sizeInt);
    if (sizeInt <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Allocation size must be positive\"}}\n";
        return;
    }
    if (sizeInt > 64 * 1024 * 1024)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Allocation size exceeds 64MB limit\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    duint requestedAddr = 0;
    bool hasAddr = json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0';
    if (hasAddr && !resolve_address(addrStr, &requestedAddr))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid requested address format\"}}\n";
        return;
    }

    char cmd[128] = { 0 };
    if (hasAddr)
    {
        sprintf_s(cmd, sizeof(cmd), "alloc 0x%llX, 0x%llX", (unsigned long long)sizeInt, (unsigned long long)requestedAddr);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "alloc 0x%llX", (unsigned long long)sizeInt);
    }

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to execute alloc command\"}}\n";
        return;
    }

    duint allocatedBase = DbgValFromString("$res");
    if (allocatedBase == 0)
    {
        allocatedBase = DbgValFromString("$lastalloc");
    }

    if (allocatedBase == 0)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"VirtualAllocEx failed to allocate remote memory\"}}\n";
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    HANDLE hProc = DbgGetProcessHandle();
    if (hProc)
    {
        VirtualQueryEx(hProc, (LPCVOID)allocatedBase, &mbi, sizeof(mbi));
    }

    char protectStr[128] = "\"null\"";
    char protectRawStr[32] = "0";
    if (mbi.Protect != 0)
    {
        decode_protection_string(mbi.Protect, protectStr, sizeof(protectStr), protectRawStr, sizeof(protectRawStr));
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"requested_address\":\"0x%016llX\",\"size\":%d,\"region_size\":%llu,\"allocation_base\":\"0x%016llX\",\"protect\":%s,\"protect_raw\":%s,\"state\":\"MEM_COMMIT\",\"success\":true}\n",
              (unsigned long long)allocatedBase,
              (unsigned long long)requestedAddr,
              sizeInt,
              (unsigned long long)mbi.RegionSize,
              (unsigned long long)mbi.AllocationBase,
              protectStr,
              protectRawStr);
    responseText = responseBuf;
}

void handle_free_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
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
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    HANDLE hProc = DbgGetProcessHandle();
    if (hProc && VirtualQueryEx(hProc, (LPCVOID)targetVA, &mbi, sizeof(mbi)) != 0)
    {
        if (mbi.State == MEM_FREE)
        {
            responseText = "{\"error\":{\"code\":\"already_free\",\"message\":\"Memory address is already free\"}}\n";
            return;
        }
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "free 0x%llX", (unsigned long long)targetVA);

    if (!DbgCmdExecDirect(cmd))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to execute free command\"}}\n";
        return;
    }

    duint resVal = DbgValFromString("$res");
    bool freedOk = (resVal != 0);

    bool verifiedReleased = false;
    if (hProc)
    {
        MEMORY_BASIC_INFORMATION postMbi = { 0 };
        if (VirtualQueryEx(hProc, (LPCVOID)targetVA, &postMbi, sizeof(postMbi)) != 0)
        {
            if (postMbi.State == MEM_FREE || (duint)postMbi.AllocationBase != (duint)mbi.AllocationBase)
            {
                verifiedReleased = true;
            }
        }
    }

    if (!freedOk && !verifiedReleased)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"VirtualFreeEx failed to release memory region\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"freed\":true,\"verified_released\":%s,\"success\":true}\n",
              (unsigned long long)targetVA,
              verifiedReleased ? "true" : "false");
    responseText = responseBuf;
}

void handle_fill_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
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
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int sizeInt = 0;
    if (!json_get_int(readBuf, "size", &sizeInt) || sizeInt <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Size must be a positive integer\"}}\n";
        return;
    }
    if (sizeInt > 16 * 1024 * 1024)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Size exceeds 16MB limit\"}}\n";
        return;
    }

    int valueInt = 0;
    json_get_int(readBuf, "value", &valueInt);
    if (valueInt < 0 || valueInt > 255)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Value must be a byte between 0 and 255\"}}\n";
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    HANDLE hProc = DbgGetProcessHandle();
    if (!hProc || VirtualQueryEx(hProc, (LPCVOID)targetVA, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Address does not belong to committed memory\"}}\n";
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "Fill 0x%llX, 0x%02X, 0x%llX",
              (unsigned long long)targetVA, (unsigned int)(valueInt & 0xFF), (unsigned long long)sizeInt);

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        std::vector<unsigned char> fillData(sizeInt, (unsigned char)(valueInt & 0xFF));
        ok = DbgMemWrite(targetVA, fillData.data(), fillData.size());
    }

    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to fill memory; memory might not be writable\"}}\n";
        return;
    }

    size_t verifyLen = (size_t)min(sizeInt, 4096);
    std::vector<unsigned char> readBack(verifyLen, 0);
    bool verified = false;
    if (DbgMemRead(targetVA, readBack.data(), verifyLen))
    {
        verified = true;
        unsigned char expected = (unsigned char)(valueInt & 0xFF);
        for (size_t i = 0; i < verifyLen; i++)
        {
            if (readBack[i] != expected)
            {
                verified = false;
                break;
            }
        }
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"size\":%d,\"value\":%d,\"bytes_written\":%d,\"verified\":%s,\"success\":true}\n",
              (unsigned long long)targetVA,
              sizeInt,
              valueInt,
              sizeInt,
              verified ? "true" : "false");
    responseText = responseBuf;
}

void handle_copy_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char srcStr[64] = { 0 };
    char dstStr[64] = { 0 };
    if (!json_get_string(readBuf, "source", srcStr, sizeof(srcStr)) || srcStr[0] == '\0' ||
        !json_get_string(readBuf, "destination", dstStr, sizeof(dstStr)) || dstStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing source or destination parameter\"}}\n";
        return;
    }

    duint srcVA = 0, dstVA = 0;
    if (!resolve_address(srcStr, &srcVA) || !resolve_address(dstStr, &dstVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid source or destination address format\"}}\n";
        return;
    }

    int sizeInt = 0;
    if (!json_get_int(readBuf, "size", &sizeInt) || sizeInt <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Size must be a positive integer\"}}\n";
        return;
    }
    if (sizeInt > 16 * 1024 * 1024)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Size exceeds 16MB limit\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(srcVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Source address is not readable memory\"}}\n";
        return;
    }

    // Read source bytes first (safely handles overlapping ranges)
    std::vector<unsigned char> buffer(sizeInt);
    if (!DbgMemRead(srcVA, buffer.data(), sizeInt))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to read source memory range\"}}\n";
        return;
    }

    if (!DbgMemWrite(dstVA, buffer.data(), sizeInt))
    {
        char cmd[128] = { 0 };
        sprintf_s(cmd, sizeof(cmd), "memcpy 0x%llX, 0x%llX, 0x%llX",
                  (unsigned long long)dstVA, (unsigned long long)srcVA, (unsigned long long)sizeInt);
        if (!DbgCmdExecDirect(cmd))
        {
            responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to write to destination memory range\"}}\n";
            return;
        }
    }

    size_t verifyLen = (size_t)min(sizeInt, 4096);
    std::vector<unsigned char> verifyBuf(verifyLen);
    bool verified = false;
    if (DbgMemRead(dstVA, verifyBuf.data(), verifyLen))
    {
        verified = (memcmp(buffer.data(), verifyBuf.data(), verifyLen) == 0);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"source\":\"0x%016llX\",\"destination\":\"0x%016llX\",\"size\":%d,\"bytes_copied\":%d,\"verified\":%s,\"success\":true}\n",
              (unsigned long long)srcVA,
              (unsigned long long)dstVA,
              sizeInt,
              sizeInt,
              verified ? "true" : "false");
    responseText = responseBuf;
}

// ------------------------------------------------------------------------------------------------
// Phase 30: Data Encoding Maps
// ------------------------------------------------------------------------------------------------

static const char* encode_type_to_string(ENCODETYPE type)
{
    switch (type)
    {
    case enc_unknown: return "unknown";
    case enc_byte: return "byte";
    case enc_word: return "word";
    case enc_dword: return "dword";
    case enc_fword: return "fword";
    case enc_qword: return "qword";
    case enc_tbyte: return "tbyte";
    case enc_oword: return "oword";
    case enc_mmword: return "mmword";
    case enc_xmmword: return "xmmword";
    case enc_ymmword: return "ymmword";
    case enc_zmmword: return "zmmword";
    case enc_real4: return "real4";
    case enc_real8: return "real8";
    case enc_real10: return "real10";
    case enc_ascii: return "ascii";
    case enc_unicode: return "unicode";
    case enc_code: return "code";
    case enc_junk: return "junk";
    case enc_middle: return "middle";
    default: return "unknown";
    }
}

static bool string_to_encode_type(const char* str, ENCODETYPE* outType)
{
    if (!str || !outType) return false;
    if (_stricmp(str, "unknown") == 0) { *outType = enc_unknown; return true; }
    if (_stricmp(str, "byte") == 0) { *outType = enc_byte; return true; }
    if (_stricmp(str, "word") == 0) { *outType = enc_word; return true; }
    if (_stricmp(str, "dword") == 0) { *outType = enc_dword; return true; }
    if (_stricmp(str, "fword") == 0) { *outType = enc_fword; return true; }
    if (_stricmp(str, "qword") == 0) { *outType = enc_qword; return true; }
    if (_stricmp(str, "tbyte") == 0) { *outType = enc_tbyte; return true; }
    if (_stricmp(str, "oword") == 0) { *outType = enc_oword; return true; }
    if (_stricmp(str, "mmword") == 0) { *outType = enc_mmword; return true; }
    if (_stricmp(str, "xmmword") == 0) { *outType = enc_xmmword; return true; }
    if (_stricmp(str, "ymmword") == 0) { *outType = enc_ymmword; return true; }
    if (_stricmp(str, "zmmword") == 0) { *outType = enc_zmmword; return true; }
    if (_stricmp(str, "real4") == 0 || _stricmp(str, "float") == 0) { *outType = enc_real4; return true; }
    if (_stricmp(str, "real8") == 0 || _stricmp(str, "double") == 0) { *outType = enc_real8; return true; }
    if (_stricmp(str, "real10") == 0 || _stricmp(str, "longdouble") == 0) { *outType = enc_real10; return true; }
    if (_stricmp(str, "ascii") == 0) { *outType = enc_ascii; return true; }
    if (_stricmp(str, "unicode") == 0) { *outType = enc_unicode; return true; }
    if (_stricmp(str, "code") == 0) { *outType = enc_code; return true; }
    if (_stricmp(str, "junk") == 0) { *outType = enc_junk; return true; }
    if (_stricmp(str, "middle") == 0) { *outType = enc_middle; return true; }

    char* endp = nullptr;
    long val = strtol(str, &endp, 0);
    if (endp && *endp == '\0' && val >= 0 && val <= (long)enc_middle)
    {
        *outType = (ENCODETYPE)val;
        return true;
    }
    return false;
}

void handle_get_data_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }
    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int sizeInt = 1;
    json_get_int(readBuf, "size", &sizeInt);
    if (sizeInt <= 0) sizeInt = 1;
    duint size = (duint)sizeInt;

    ENCODETYPE type = DbgGetEncodeTypeAt(va, size);
    const char* typeName = encode_type_to_string(type);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%llX\",\"size\":%llu,\"type\":%d,\"type_name\":\"%s\",\"success\":true}\n",
              (unsigned long long)va, (unsigned long long)size, (int)type, typeName);
    responseText = responseBuf;
}

void handle_get_data_size(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }
    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int codeSizeInt = 16;
    json_get_int(readBuf, "code_size", &codeSizeInt);
    if (codeSizeInt <= 0) codeSizeInt = 1;
    duint codeSize = (duint)codeSizeInt;

    duint dataSize = DbgGetEncodeSizeAt(va, codeSize);
    ENCODETYPE type = DbgGetEncodeTypeAt(va, codeSize);
    const char* typeName = encode_type_to_string(type);

    duint mapSize = 0;
    void* buffer = DbgGetEncodeTypeBuffer(va, &mapSize);
    bool hasEntry = (buffer != nullptr);
    if (buffer)
    {
        DbgReleaseEncodeTypeBuffer(buffer);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%llX\",\"code_size\":%llu,\"data_size\":%llu,\"type\":%d,\"type_name\":\"%s\",\"has_map_entry\":%s,\"success\":true}\n",
              (unsigned long long)va, (unsigned long long)codeSize, (unsigned long long)dataSize, (int)type, typeName, hasEntry ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_data_map(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }
    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int maxBytesInt = 256;
    json_get_int(readBuf, "max_bytes", &maxBytesInt);
    if (maxBytesInt <= 0) maxBytesInt = 256;
    if (maxBytesInt > 4096) maxBytesInt = 4096;

    duint segSize = 0;
    duint segBase = DbgMemFindBaseAddr(va, &segSize);

    duint mapSize = 0;
    void* rawBuf = DbgGetEncodeTypeBuffer(va, &mapSize);

    if (!rawBuf || mapSize == 0)
    {
        if (rawBuf) DbgReleaseEncodeTypeBuffer(rawBuf);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%llX\",\"segment_base\":\"0x%llX\",\"segment_size\":%llu,\"map_size\":0,\"has_map\":false,\"spans\":[],\"success\":true}\n",
                  (unsigned long long)va, (unsigned long long)segBase, (unsigned long long)segSize);
        responseText = responseBuf;
        return;
    }

    const uint8_t* mapBytes = (const uint8_t*)rawBuf;
    duint offset = (segBase != 0 && va >= segBase) ? (va - segBase) : 0;
    if (offset > mapSize) offset = mapSize;

    duint count = (duint)maxBytesInt;
    if (offset + count > mapSize)
        count = mapSize - offset;

    struct Span {
        duint startOffset;
        duint length;
        uint8_t encType;
    };
    std::vector<Span> spans;
    for (duint i = 0; i < count; )
    {
        uint8_t curType = mapBytes[offset + i];
        duint runLen = 1;
        while (i + runLen < count && mapBytes[offset + i + runLen] == curType)
            runLen++;
        spans.push_back({ offset + i, runLen, curType });
        i += runLen;
    }

    DbgReleaseEncodeTypeBuffer(rawBuf);

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"address\":\"0x%llX\",\"segment_base\":\"0x%llX\",\"segment_size\":%llu,\"map_size\":%llu,\"query_offset\":%llu,\"count\":%llu,\"has_map\":true,\"spans\":[",
                        (unsigned long long)va, (unsigned long long)segBase, (unsigned long long)segSize,
                        (unsigned long long)mapSize, (unsigned long long)offset, (unsigned long long)count);

    for (size_t i = 0; i < spans.size() && pos < (int)responseBufSize - 256; i++)
    {
        pos += sprintf_s(responseBuf + pos, responseBufSize - pos,
                         "%s{\"offset\":%llu,\"size\":%llu,\"type\":%d,\"type_name\":\"%s\"}",
                         (i > 0 ? "," : ""),
                         (unsigned long long)spans[i].startOffset,
                         (unsigned long long)spans[i].length,
                         (int)spans[i].encType,
                         encode_type_to_string((ENCODETYPE)spans[i].encType));
    }
    pos += sprintf_s(responseBuf + pos, responseBufSize - pos, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_set_data_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }
    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int sizeInt = 1;
    json_get_int(readBuf, "size", &sizeInt);
    if (sizeInt <= 0) sizeInt = 1;
    duint size = (duint)sizeInt;

    char typeStr[64] = { 0 };
    ENCODETYPE encType = enc_unknown;
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (!string_to_encode_type(typeStr, &encType))
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid or unrecognized 'type'\"}}\n";
            return;
        }
    }
    else
    {
        int typeInt = 0;
        if (json_get_int(readBuf, "type", &typeInt) && typeInt >= 0 && typeInt <= (int)enc_middle)
        {
            encType = (ENCODETYPE)typeInt;
        }
        else
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'type' parameter\"}}\n";
            return;
        }
    }

    duint segSize = 0;
    duint segBase = DbgMemFindBaseAddr(va, &segSize);
    if (!segBase)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Address is outside mapped memory segments\"}}\n";
        return;
    }

    duint effectiveSize = size;
    if (va - segBase + size > segSize)
    {
        effectiveSize = segSize - (va - segBase);
    }

    bool ok = DbgSetEncodeType(va, effectiveSize, encType);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"DbgSetEncodeType failed\"}}\n";
        return;
    }

    GuiUpdateDisassemblyView();

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%llX\",\"requested_size\":%llu,\"effective_size\":%llu,\"type\":%d,\"type_name\":\"%s\",\"success\":true}\n",
              (unsigned long long)va, (unsigned long long)size, (unsigned long long)effectiveSize, (int)encType, encode_type_to_string(encType));
    responseText = responseBuf;
}

void handle_clear_data_type_range(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char startStr[64] = { 0 };
    char endStr[64] = { 0 };
    if (!json_get_string(readBuf, "start_address", startStr, sizeof(startStr)) || startStr[0] == '\0' ||
        !json_get_string(readBuf, "end_address", endStr, sizeof(endStr)) || endStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing start_address or end_address\"}}\n";
        return;
    }

    duint startVA = 0, endVA = 0;
    if (!resolve_address(startStr, &startVA) || !resolve_address(endStr, &endVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid start_address or end_address format\"}}\n";
        return;
    }

    if (endVA < startVA)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"end_address must be >= start_address\"}}\n";
        return;
    }

    DbgDelEncodeTypeRange(startVA, endVA);
    GuiUpdateDisassemblyView();

    duint clearedBytes = endVA - startVA + 1;
    sprintf_s(responseBuf, responseBufSize,
              "{\"start_address\":\"0x%llX\",\"end_address\":\"0x%llX\",\"cleared_bytes\":%llu,\"success\":true}\n",
              (unsigned long long)startVA, (unsigned long long)endVA, (unsigned long long)clearedBytes);
    responseText = responseBuf;
}

void handle_clear_data_type_segment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }
    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    duint segSize = 0;
    duint segBase = DbgMemFindBaseAddr(va, &segSize);

    DbgDelEncodeTypeSegment(va);
    GuiUpdateDisassemblyView();

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%llX\",\"segment_base\":\"0x%llX\",\"segment_size\":%llu,\"success\":true}\n",
              (unsigned long long)va, (unsigned long long)segBase, (unsigned long long)segSize);
    responseText = responseBuf;
}

void handle_is_code_page(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"no_debuggee\",\"message\":\"No active debug session\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'address' parameter\"}}\n";
        return;
    }

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    bool skipCache = false;
    json_get_bool(readBuf, "skip_cache", &skipCache);
    if (!skipCache)
    {
        json_get_bool(readBuf, "refresh", &skipCache);
    }

    bool isCode = DbgFunctions()->MemIsCodePage(va, skipCache);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"is_code_page\":%s,\"skip_cache\":%s,\"success\":true}\n",
              (unsigned long long)va,
              isCode ? "true" : "false",
              skipCache ? "true" : "false");
    responseText = responseBuf;
}

