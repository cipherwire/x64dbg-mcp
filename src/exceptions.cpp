#include "exceptions.h"
#include <ctype.h>
#include <stdlib.h>

struct LastExceptionData
{
    bool valid;
    DWORD code;
    DWORD flags;
    duint address;
    bool firstChance;
    DWORD threadId;
    char name[128];
    DWORD numParams;
    duint params[EXCEPTION_MAXIMUM_PARAMETERS];
};

static LastExceptionData g_lastExceptionData = { 0 };
static SRWLOCK g_lastExLock = SRWLOCK_INIT;

// Case-insensitive substring search helper
static bool stristr(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return false;
    if (!*needle) return true;

    for (; *haystack; ++haystack)
    {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n)))
        {
            ++h;
            ++n;
        }
        if (!*n) return true;
    }
    return false;
}

// Case-insensitive string equality helper
static bool stricmp_custom(const char* s1, const char* s2)
{
    if (!s1 || !s2) return false;
    while (*s1 && *s2)
    {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2))
            return false;
        ++s1;
        ++s2;
    }
    return *s1 == *s2;
}

// Exception code resolver from string (hex, dec, or symbolic name)
static bool resolve_exception_code(const char* input, unsigned int* outCode)
{
    if (!input || input[0] == '\0' || !outCode)
        return false;

    // Skip whitespace
    while (isspace((unsigned char)*input)) input++;

    // Try hex (0x prefix or standard hex format)
    char* endPtr = nullptr;
    if (input[0] == '0' && (input[1] == 'x' || input[1] == 'X'))
    {
        unsigned long long val = _strtoui64(input + 2, &endPtr, 16);
        if (endPtr != input + 2 && (*endPtr == '\0' || isspace((unsigned char)*endPtr)))
        {
            *outCode = (unsigned int)val;
            return true;
        }
    }

    // Try pure hex if it contains A-F
    bool hasHexAlpha = false;
    for (const char* p = input; *p; p++)
    {
        if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))
        {
            hasHexAlpha = true;
            break;
        }
    }

    if (hasHexAlpha)
    {
        unsigned long long val = _strtoui64(input, &endPtr, 16);
        if (endPtr != input && (*endPtr == '\0' || isspace((unsigned char)*endPtr)))
        {
            *outCode = (unsigned int)val;
            return true;
        }
    }

    // Try pure decimal
    bool isAllDigits = true;
    for (const char* p = input; *p; p++)
    {
        if (!isdigit((unsigned char)*p))
        {
            isAllDigits = false;
            break;
        }
    }
    if (isAllDigits)
    {
        unsigned long long val = _strtoui64(input, &endPtr, 10);
        if (endPtr != input && (*endPtr == '\0' || isspace((unsigned char)*endPtr)))
        {
            *outCode = (unsigned int)val;
            return true;
        }
    }

    // Lookup by name in x64dbg exception database
    auto dbg = DbgFunctions();
    if (dbg && dbg->EnumExceptions)
    {
        BridgeList<CONSTANTINFO> exList;
        dbg->EnumExceptions(&exList);
        int total = exList.Count();
        for (int i = 0; i < total; i++)
        {
            if (exList[i].name && stricmp_custom(exList[i].name, input))
            {
                *outCode = (unsigned int)exList[i].value;
                return true;
            }
        }
    }

    return false;
}

void record_last_exception(const PLUG_CB_EXCEPTION* info)
{
    if (!info || !info->Exception) return;

    AcquireSRWLockExclusive(&g_lastExLock);

    const EXCEPTION_RECORD& rec = info->Exception->ExceptionRecord;
    g_lastExceptionData.valid = true;
    g_lastExceptionData.code = rec.ExceptionCode;
    g_lastExceptionData.flags = rec.ExceptionFlags;
    g_lastExceptionData.address = (duint)rec.ExceptionAddress;
    g_lastExceptionData.firstChance = (info->Exception->dwFirstChance != 0);
    g_lastExceptionData.threadId = DbgGetThreadId();
    g_lastExceptionData.name[0] = '\0';

    // Copy parameters
    DWORD numP = rec.NumberParameters;
    if (numP > EXCEPTION_MAXIMUM_PARAMETERS) numP = EXCEPTION_MAXIMUM_PARAMETERS;
    g_lastExceptionData.numParams = numP;
    for (DWORD i = 0; i < numP; i++)
    {
        g_lastExceptionData.params[i] = (duint)rec.ExceptionInformation[i];
    }

    // Lookup exception name
    auto dbg = DbgFunctions();
    if (dbg && dbg->EnumExceptions)
    {
        BridgeList<CONSTANTINFO> exList;
        dbg->EnumExceptions(&exList);
        int total = exList.Count();
        for (int i = 0; i < total; i++)
        {
            if (exList[i].value == rec.ExceptionCode && exList[i].name)
            {
                strncpy_s(g_lastExceptionData.name, sizeof(g_lastExceptionData.name), exList[i].name, _TRUNCATE);
                break;
            }
        }
    }

    ReleaseSRWLockExclusive(&g_lastExLock);
}

void reset_last_exception()
{
    AcquireSRWLockExclusive(&g_lastExLock);
    g_lastExceptionData.valid = false;
    ReleaseSRWLockExclusive(&g_lastExLock);
}

void handle_list_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    auto dbg = DbgFunctions();
    if (!dbg || !dbg->EnumExceptions)
    {
        responseText = "{\"error\":\"EnumExceptions API not available\"}\n";
        return;
    }

    int offsetVal = 0;
    int limitVal = 100;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":\"invalid offset: must be non-negative\"}\n";
        return;
    }
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":\"invalid limit: must be positive\"}\n";
        return;
    }
    if (limitVal > 200) limitVal = 200;

    char filterStr[128] = { 0 };
    bool hasFilter = json_get_string(readBuf, "filter", filterStr, sizeof(filterStr)) && filterStr[0] != '\0';

    BridgeList<CONSTANTINFO> exList;
    dbg->EnumExceptions(&exList);
    int totalCount = exList.Count();

    // Filter into matching indices if filter supplied
    std::vector<int> matchingIndices;
    matchingIndices.reserve(totalCount);

    for (int i = 0; i < totalCount; i++)
    {
        const char* name = exList[i].name ? exList[i].name : "";
        if (hasFilter)
        {
            char codeHex[32];
            sprintf_s(codeHex, sizeof(codeHex), "0x%08X", (unsigned int)exList[i].value);
            if (!stristr(name, filterStr) && !stristr(codeHex, filterStr))
            {
                continue;
            }
        }
        matchingIndices.push_back(i);
    }

    int filteredTotal = (int)matchingIndices.size();
    int startIdx = offsetVal;
    if (startIdx > filteredTotal) startIdx = filteredTotal;
    int endIdx = startIdx + limitVal;
    if (endIdx > filteredTotal) endIdx = filteredTotal;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"total\":%d,\"offset\":%d,\"limit\":%d,\"exceptions\":[",
                           filteredTotal, startIdx, limitVal);

    for (int i = startIdx; i < endIdx; i++)
    {
        int exIdx = matchingIndices[i];
        const char* name = exList[exIdx].name ? exList[exIdx].name : "";
        char escName[256];
        escape_json_string(name, escName, sizeof(escName));

        char itemBuf[384];
        sprintf_s(itemBuf, sizeof(itemBuf),
                  "%s{\"code\":\"0x%08X\",\"name\":\"%s\"}",
                  (i > startIdx ? "," : ""),
                  (unsigned int)exList[exIdx].value,
                  escName);

        if ((size_t)offset + strlen(itemBuf) + 32 >= responseBufSize)
        {
            break;
        }
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "%s", itemBuf);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;
}

void handle_get_exception_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char exParam[128] = { 0 };
    if (!json_get_string(readBuf, "exception", exParam, sizeof(exParam)) || exParam[0] == '\0')
    {
        int codeInt = 0;
        if (json_get_int(readBuf, "exception", &codeInt))
        {
            sprintf_s(exParam, sizeof(exParam), "0x%X", (unsigned int)codeInt);
        }
        else
        {
            responseText = "{\"error\":\"missing exception parameter\"}\n";
            return;
        }
    }

    unsigned int exCode = 0;
    if (!resolve_exception_code(exParam, &exCode))
    {
        responseText = "{\"error\":\"could not resolve exception code or name\"}\n";
        return;
    }

    auto dbg = DbgFunctions();
    std::string primaryName = "";
    std::vector<std::string> aliases;

    if (dbg && dbg->EnumExceptions)
    {
        BridgeList<CONSTANTINFO> exList;
        dbg->EnumExceptions(&exList);
        int total = exList.Count();
        for (int i = 0; i < total; i++)
        {
            if (exList[i].value == exCode && exList[i].name)
            {
                if (primaryName.empty())
                {
                    primaryName = exList[i].name;
                }
                aliases.push_back(exList[i].name);
            }
        }
    }

    // Check breakpoint status if API available
    bool bpSet = false;
    bool bpEnabled = false;
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        if (dbg->BpRefExists(&ref))
        {
            bpSet = true;
            duint enVal = 0;
            if (dbg->BpGetFieldNumber && dbg->BpGetFieldNumber(&ref, bpf_enabled, &enVal))
            {
                bpEnabled = (enVal != 0);
            }
        }
    }

    char escPrimary[256] = { 0 };
    escape_json_string(primaryName.c_str(), escPrimary, sizeof(escPrimary));

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"code\":\"0x%08X\",\"name\":\"%s\",\"breakpoint_set\":%s,\"breakpoint_enabled\":%s,\"aliases\":[",
                           exCode, escPrimary,
                           bpSet ? "true" : "false",
                           bpEnabled ? "true" : "false");

    for (size_t i = 0; i < aliases.size(); i++)
    {
        char escAlias[256];
        escape_json_string(aliases[i].c_str(), escAlias, sizeof(escAlias));
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s\"%s\"", (i > 0 ? "," : ""), escAlias);
    }
    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;
}

void handle_set_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    char codeStr[128] = { 0 };
    if (!json_get_string(readBuf, "code", codeStr, sizeof(codeStr)) || codeStr[0] == '\0')
    {
        int codeInt = 0;
        if (json_get_int(readBuf, "code", &codeInt))
        {
            sprintf_s(codeStr, sizeof(codeStr), "0x%X", (unsigned int)codeInt);
        }
        else
        {
            responseText = "{\"error\":\"missing code parameter\"}\n";
            return;
        }
    }

    unsigned int exCode = 0;
    if (!resolve_exception_code(codeStr, &exCode))
    {
        responseText = "{\"error\":\"invalid exception code\"}\n";
        return;
    }

    char chanceStr[32] = "first";
    char chanceInput[32] = { 0 };
    if (json_get_string(readBuf, "chance", chanceInput, sizeof(chanceInput)) && chanceInput[0] != '\0')
    {
        if (stricmp_custom(chanceInput, "first") || stricmp_custom(chanceInput, "second") || stricmp_custom(chanceInput, "all"))
        {
            strncpy_s(chanceStr, sizeof(chanceStr), chanceInput, _TRUNCATE);
        }
        else
        {
            responseText = "{\"error\":\"invalid chance: must be first, second, or all\"}\n";
            return;
        }
    }

    auto dbg = DbgFunctions();
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        if (dbg->BpRefExists(&ref))
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"exception breakpoint 0x%08X already exists\"}\n",
                      exCode);
            responseText = responseBuf;
            return;
        }
    }

    char cmd[128];
    sprintf_s(cmd, sizeof(cmd), "SetExceptionBPX 0x%X, %s", exCode, chanceStr);
    DbgCmdExecDirect(cmd);

    // Verify breakpoint was created
    bool created = false;
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        created = dbg->BpRefExists(&ref);
    }

    if (!created)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set exception breakpoint for 0x%08X\"}\n",
                  exCode);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"code\":\"0x%08X\",\"chance\":\"%s\",\"success\":true}\n",
              exCode, chanceStr);
    responseText = responseBuf;
}

void handle_delete_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    char codeStr[128] = { 0 };
    if (!json_get_string(readBuf, "code", codeStr, sizeof(codeStr)) || codeStr[0] == '\0')
    {
        int codeInt = 0;
        if (json_get_int(readBuf, "code", &codeInt))
        {
            sprintf_s(codeStr, sizeof(codeStr), "0x%X", (unsigned int)codeInt);
        }
        else
        {
            responseText = "{\"error\":\"missing code parameter\"}\n";
            return;
        }
    }

    unsigned int exCode = 0;
    if (!resolve_exception_code(codeStr, &exCode))
    {
        responseText = "{\"error\":\"invalid exception code\"}\n";
        return;
    }

    auto dbg = DbgFunctions();
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        if (!dbg->BpRefExists(&ref))
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"exception breakpoint 0x%08X not found\"}\n",
                      exCode);
            responseText = responseBuf;
            return;
        }
    }

    char cmd[128];
    sprintf_s(cmd, sizeof(cmd), "DeleteExceptionBPX 0x%X", exCode);
    DbgCmdExecDirect(cmd);

    // Verify deletion
    bool stillExists = false;
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        stillExists = dbg->BpRefExists(&ref);
    }

    if (stillExists)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to delete exception breakpoint for 0x%08X\"}\n",
                  exCode);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"code\":\"0x%08X\",\"deleted\":true}\n",
              exCode);
    responseText = responseBuf;
}

void handle_enable_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    char codeStr[128] = { 0 };
    if (!json_get_string(readBuf, "code", codeStr, sizeof(codeStr)) || codeStr[0] == '\0')
    {
        int codeInt = 0;
        if (json_get_int(readBuf, "code", &codeInt))
        {
            sprintf_s(codeStr, sizeof(codeStr), "0x%X", (unsigned int)codeInt);
        }
        else
        {
            responseText = "{\"error\":\"missing code parameter\"}\n";
            return;
        }
    }

    unsigned int exCode = 0;
    if (!resolve_exception_code(codeStr, &exCode))
    {
        responseText = "{\"error\":\"invalid exception code\"}\n";
        return;
    }

    auto dbg = DbgFunctions();
    if (dbg && dbg->BpRefException && dbg->BpRefExists)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        if (!dbg->BpRefExists(&ref))
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"exception breakpoint 0x%08X not found\"}\n",
                      exCode);
            responseText = responseBuf;
            return;
        }
    }

    bool enabled = true;
    bool parsedVal = false;
    if (json_get_bool(readBuf, "enabled", &parsedVal))
    {
        enabled = parsedVal;
    }

    char cmd[128];
    if (enabled)
    {
        sprintf_s(cmd, sizeof(cmd), "EnableExceptionBPX 0x%X", exCode);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "DisableExceptionBPX 0x%X", exCode);
    }
    DbgCmdExecDirect(cmd);

    // Also update field directly via BpRef if available
    if (dbg && dbg->BpRefException && dbg->BpSetFieldNumber)
    {
        BP_REF ref;
        dbg->BpRefException(&ref, exCode);
        dbg->BpSetFieldNumber(&ref, bpf_enabled, enabled ? 1 : 0);
    }
    GuiUpdateAllViews();

    sprintf_s(responseBuf, responseBufSize,
              "{\"code\":\"0x%08X\",\"enabled\":%s}\n",
              exCode, enabled ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_last_exception(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    AcquireSRWLockShared(&g_lastExLock);
    if (!g_lastExceptionData.valid)
    {
        ReleaseSRWLockShared(&g_lastExLock);
        responseText = "{\"has_exception\":false}\n";
        return;
    }

    LastExceptionData dataCopy = g_lastExceptionData;
    ReleaseSRWLockShared(&g_lastExLock);

    char escName[256];
    escape_json_string(dataCopy.name, escName, sizeof(escName));

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"has_exception\":true,\"code\":\"0x%08X\",\"name\":\"%s\",\"address\":\"0x%016llX\",\"first_chance\":%s,\"flags\":\"0x%08X\",\"thread_id\":%u,\"parameters\":[",
                           dataCopy.code,
                           escName,
                           (unsigned long long)dataCopy.address,
                           dataCopy.firstChance ? "true" : "false",
                           dataCopy.flags,
                           dataCopy.threadId);

    for (DWORD i = 0; i < dataCopy.numParams; i++)
    {
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s\"0x%016llX\"", (i > 0 ? "," : ""), (unsigned long long)dataCopy.params[i]);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;
}
