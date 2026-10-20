#include "patches.h"
#include "memory.h"

static const duint MAX_PATCH_RANGE_SPAN = 65536;

void handle_patch_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] patch_memory: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] patch_memory: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running; patching only permitted when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->MemPatch == nullptr)
    {
        responseText = "{\"error\":\"MemPatch API not available\"}\n";
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

    char dataStr[8192] = { 0 };
    if (!json_get_string(readBuf, "data", dataStr, sizeof(dataStr)) || dataStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty data parameter\"}\n";
        return;
    }

    unsigned char newBytes[4096] = { 0 };
    size_t byteCount = 0;
    if (!parse_hex_bytes(dataStr, newBytes, sizeof(newBytes), &byteCount))
    {
        responseText = "{\"error\":\"invalid hex bytes in data parameter\"}\n";
        return;
    }
    if (byteCount == 0 || byteCount > 4096)
    {
        responseText = "{\"error\":\"data size must be between 1 and 4096 bytes\"}\n";
        return;
    }

    unsigned char oldBytes[4096] = { 0 };
    if (!DbgMemRead(va, oldBytes, (duint)byteCount))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to read memory before patching at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    if (!dbg->MemPatch(va, newBytes, (duint)byteCount))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"MemPatch failed at address 0x%016llX\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    GuiUpdatePatches();

    char oldHex[8192] = { 0 };
    char newHex[8192] = { 0 };
    for (size_t i = 0; i < byteCount && i < 2048; i++)
    {
        sprintf_s(oldHex + i * 2, sizeof(oldHex) - i * 2, "%02x", oldBytes[i]);
        sprintf_s(newHex + i * 2, sizeof(newHex) - i * 2, "%02x", newBytes[i]);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"bytes_patched\":%llu,\"old_bytes\":\"%s\",\"new_bytes\":\"%s\",\"patched\":true}\n",
              (unsigned long long)va, (unsigned long long)byteCount, oldHex, newHex);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] patch_memory: applied %llu bytes at 0x%llX\n",
                      (unsigned long long)byteCount, (unsigned long long)va);
}

void handle_list_patches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_patches: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->PatchEnum == nullptr)
    {
        responseText = "{\"error\":\"PatchEnum API not available\"}\n";
        return;
    }

    int offsetVal = 0;
    json_get_int(readBuf, "offset", &offsetVal);
    if (offsetVal < 0) offsetVal = 0;

    int limitVal = 100;
    json_get_int(readBuf, "limit", &limitVal);
    if (limitVal <= 0) limitVal = 100;
    if (limitVal > 500) limitVal = 500;

    size_t cbSize = 0;
    dbg->PatchEnum(nullptr, &cbSize);

    size_t totalCount = cbSize / sizeof(DBGPATCHINFO);

    if (totalCount == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"total_count\":0,\"offset\":%d,\"limit\":%d,\"patches\":[]}\n",
                  offsetVal, limitVal);
        responseText = responseBuf;
        return;
    }

    std::vector<DBGPATCHINFO> patchList(totalCount);
    if (!dbg->PatchEnum(patchList.data(), &cbSize))
    {
        responseText = "{\"error\":\"PatchEnum enumeration failed\"}\n";
        return;
    }

    int startIdx = offsetVal;
    if (startIdx > (int)totalCount) startIdx = (int)totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > (int)totalCount) endIdx = (int)totalCount;

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"total_count\":%llu,\"offset\":%d,\"limit\":%d,\"patches\":[",
        (unsigned long long)totalCount, offsetVal, limitVal);

    for (int i = startIdx; i < endIdx && bufOffset < (int)responseBufSize - 1024; i++)
    {
        char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(patchList[i].mod, safeMod, sizeof(safeMod));

        bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
            "%s{\"module\":\"%s\",\"address\":\"0x%016llX\",\"old_byte\":\"0x%02X\",\"new_byte\":\"0x%02X\"}",
            (i > startIdx ? "," : ""),
            safeMod,
            (unsigned long long)patchList[i].addr,
            (unsigned int)patchList[i].oldbyte,
            (unsigned int)patchList[i].newbyte);
    }

    bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] list_patches: total=%llu, slice %d..%d\n",
                      (unsigned long long)totalCount, startIdx, endIdx);
}

void handle_get_patch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_patch: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->PatchGetEx == nullptr)
    {
        responseText = "{\"error\":\"PatchGetEx API not available\"}\n";
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

    DBGPATCHINFO patch = { 0 };
    bool found = dbg->PatchGetEx(va, &patch);

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":false}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(patch.mod, safeMod, sizeof(safeMod));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"found\":true,\"module\":\"%s\",\"old_byte\":\"0x%02X\",\"new_byte\":\"0x%02X\"}\n",
              (unsigned long long)patch.addr,
              safeMod,
              (unsigned int)patch.oldbyte,
              (unsigned int)patch.newbyte);
    responseText = responseBuf;
}

void handle_restore_patch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] restore_patch: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] restore_patch: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running; patch restore only permitted when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->PatchRestore == nullptr || dbg->PatchGetEx == nullptr)
    {
        responseText = "{\"error\":\"PatchRestore API not available\"}\n";
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

    DBGPATCHINFO info = { 0 };
    bool found = dbg->PatchGetEx(va, &info);

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":false,\"restored\":false,\"message\":\"no patch found at specified address\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    bool ok = dbg->PatchRestore(va);
    GuiUpdatePatches();

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(info.mod, safeMod, sizeof(safeMod));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"found\":true,\"restored\":%s,\"module\":\"%s\",\"restored_byte\":\"0x%02X\",\"previous_byte\":\"0x%02X\"}\n",
              (unsigned long long)va,
              ok ? "true" : "false",
              safeMod,
              (unsigned int)info.oldbyte,
              (unsigned int)info.newbyte);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] restore_patch: restored patch at 0x%llX (restored: %d)\n",
                      (unsigned long long)va, ok ? 1 : 0);
}

void handle_restore_patches_range(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] restore_patches_range: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] restore_patches_range: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running; patch restore only permitted when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->PatchRestoreRange == nullptr || dbg->PatchGet == nullptr)
    {
        responseText = "{\"error\":\"PatchRestoreRange API not available\"}\n";
        return;
    }

    char startStr[64] = { 0 };
    if (!json_get_string(readBuf, "start_address", startStr, sizeof(startStr)) || startStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing start_address parameter\"}\n";
        return;
    }

    char endStr[64] = { 0 };
    if (!json_get_string(readBuf, "end_address", endStr, sizeof(endStr)) || endStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing end_address parameter\"}\n";
        return;
    }

    duint startVa = 0;
    if (!resolve_address(startStr, &startVa))
    {
        responseText = "{\"error\":\"invalid start_address format\"}\n";
        return;
    }

    duint endVa = 0;
    if (!resolve_address(endStr, &endVa))
    {
        responseText = "{\"error\":\"invalid end_address format\"}\n";
        return;
    }

    if (startVa > endVa)
    {
        responseText = "{\"error\":\"start_address must be less than or equal to end_address\"}\n";
        return;
    }

    if (endVa - startVa > MAX_PATCH_RANGE_SPAN)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"range span exceeds maximum allowed (%llu bytes)\"}\n",
                  (unsigned long long)MAX_PATCH_RANGE_SPAN);
        responseText = responseBuf;
        return;
    }

    int count = 0;
    for (duint a = startVa; a <= endVa; a++)
    {
        if (dbg->PatchGet(a))
            count++;
    }

    dbg->PatchRestoreRange(startVa, endVa);
    GuiUpdatePatches();

    sprintf_s(responseBuf, responseBufSize,
              "{\"start_address\":\"0x%016llX\",\"end_address\":\"0x%016llX\",\"patches_restored\":%d}\n",
              (unsigned long long)startVa, (unsigned long long)endVa, count);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] restore_patches_range: restored %d patches in range 0x%llX..0x%llX\n",
                      count, (unsigned long long)startVa, (unsigned long long)endVa);
}
