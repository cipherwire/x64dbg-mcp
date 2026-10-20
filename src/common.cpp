#include "common.h"

// Global plugin handle assigned by the debugger
int g_pluginHandle = 0;

// Worker thread and shutdown handles
HANDLE g_hWorkerThread = nullptr;
HANDLE g_hStopEvent = nullptr;
HANDLE g_hExecEvent = nullptr;

// Execution control event tracking
volatile LONG g_lastStopReason = STOP_NONE;
volatile duint g_lastBpAddr = 0;
volatile DWORD g_lastExceptionCode = 0;
volatile LONG g_execActive = 0;

void log_lifecycle(const char* message)
{
    FILE* f = nullptr;
    if (fopen_s(&f, "D:\\x64dbg-MCP\\plugin_lifecycle.log", "a") == 0 && f != nullptr)
    {
        fputs(message, f);
        fclose(f);
    }
}

void escape_json_string(const char* src, char* dst, size_t dstSize)
{
    if (!src || !dst || dstSize == 0) return;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d < dstSize - 6; s++)
    {
        unsigned char c = (unsigned char)src[s];
        if (c == '\"')
        {
            dst[d++] = '\\';
            dst[d++] = '\"';
        }
        else if (c == '\\')
        {
            dst[d++] = '\\';
            dst[d++] = '\\';
        }
        else if (c == '\b')
        {
            dst[d++] = '\\';
            dst[d++] = 'b';
        }
        else if (c == '\f')
        {
            dst[d++] = '\\';
            dst[d++] = 'f';
        }
        else if (c == '\n')
        {
            dst[d++] = '\\';
            dst[d++] = 'n';
        }
        else if (c == '\r')
        {
            dst[d++] = '\\';
            dst[d++] = 'r';
        }
        else if (c == '\t')
        {
            dst[d++] = '\\';
            dst[d++] = 't';
        }
        else if (c < 0x20)
        {
            d += sprintf_s(dst + d, dstSize - d, "\\u%04x", c);
        }
        else
        {
            dst[d++] = (char)c;
        }
    }
    dst[d] = '\0';
}

bool json_get_string(const char* json, const char* key, char* out, size_t outSize)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);
    const char* p = strstr(json, searchKey);
    if (!p) return false;
    p += strlen(searchKey);
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '\"') return false;
    p++;

    const char* end = p;
    while (*end != '\0')
    {
        if (*end == '\\')
        {
            if (*(end + 1) != '\0')
            {
                end += 2;
                continue;
            }
        }
        else if (*end == '\"')
        {
            break;
        }
        end++;
    }
    if (*end != '\"') return false;

    size_t outIdx = 0;
    for (const char* cur = p; cur < end && outIdx + 1 < outSize; cur++)
    {
        if (*cur == '\\' && (cur + 1 < end))
        {
            cur++;
            if (*cur == '\"') out[outIdx++] = '\"';
            else if (*cur == '\\') out[outIdx++] = '\\';
            else if (*cur == '/') out[outIdx++] = '/';
            else if (*cur == 'b') out[outIdx++] = '\b';
            else if (*cur == 'f') out[outIdx++] = '\f';
            else if (*cur == 'n') out[outIdx++] = '\n';
            else if (*cur == 'r') out[outIdx++] = '\r';
            else if (*cur == 't') out[outIdx++] = '\t';
            else out[outIdx++] = *cur;
        }
        else
        {
            out[outIdx++] = *cur;
        }
    }
    out[outIdx] = '\0';
    return true;
}

bool json_get_int(const char* json, const char* key, int* out)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);
    const char* p = strstr(json, searchKey);
    if (!p) return false;
    p += strlen(searchKey);
    while (*p == ' ' || *p == '\t') p++;
    char* endPtr = nullptr;
    long val = strtol(p, &endPtr, 10);
    if (endPtr == p) return false;
    *out = (int)val;
    return true;
}

bool json_get_bool(const char* json, const char* key, bool* out)
{
    char searchKey[64];
    sprintf_s(searchKey, sizeof(searchKey), "\"%s\":", key);
    const char* p = strstr(json, searchKey);
    if (!p) return false;
    p += strlen(searchKey);
    while (*p == ' ' || *p == '\t') p++;
    if (_strnicmp(p, "true", 4) == 0)
    {
        *out = true;
        return true;
    }
    if (_strnicmp(p, "false", 5) == 0)
    {
        *out = false;
        return true;
    }
    return false;
}

bool resolve_address(const char* addrStr, duint* outVa)
{
    if (addrStr == nullptr || addrStr[0] == '\0' || _stricmp(addrStr, "rip") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cip;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rsp") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.csp;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rax") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cax;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rbx") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cbx;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rcx") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.ccx;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rdx") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cdx;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rbp") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cbp;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rsi") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.csi;
            return true;
        }
        return false;
    }

    if (_stricmp(addrStr, "rdi") == 0)
    {
        REGDUMP_AVX512 regDump = { 0 };
        if (DbgGetRegDumpEx(&regDump, sizeof(regDump)))
        {
            *outVa = regDump.regcontext.cdi;
            return true;
        }
        return false;
    }

    // Check if module name
    duint modBase = DbgModBaseFromName(addrStr);
    if (modBase != 0)
    {
        *outVa = modBase;
        return true;
    }

    // Try hex parsing
    const char* pAddr = addrStr;
    if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X'))
    {
        pAddr += 2;
    }
    char* endPtr = nullptr;
    duint val = (duint)_strtoui64(pAddr, &endPtr, 16);
    if (endPtr != pAddr && *endPtr == '\0')
    {
        *outVa = val;
        return true;
    }

    return false;
}

bool is_user_breakpoint(duint addr)
{
    BPMAP bpMap = { 0 };
    int count = DbgGetBpList(bp_none, &bpMap);
    bool found = false;
    if (count > 0 && bpMap.bp != nullptr)
    {
        for (int i = 0; i < bpMap.count; i++)
        {
            if (bpMap.bp[i].addr == addr && bpMap.bp[i].active && bpMap.bp[i].enabled)
            {
                found = true;
                break;
            }
        }
        BridgeFree(bpMap.bp);
    }
    return found;
}
