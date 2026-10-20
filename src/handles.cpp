#include "handles.h"

void handle_list_handles(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_handles: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] list_handles: debuggee is running.\n");
        responseText = "{\"error\":\"debuggee is running; handles only available when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumHandles == nullptr || dbg->GetHandleName == nullptr)
    {
        responseText = "{\"error\":\"EnumHandles API not available\"}\n";
        return;
    }

    int offsetVal = 0;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":\"invalid offset: must be non-negative\"}\n";
        return;
    }
    if (offsetVal < 0) offsetVal = 0;

    int limitVal = 100;
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":\"invalid limit: must be positive\"}\n";
        return;
    }
    if (limitVal <= 0) limitVal = 100;
    if (limitVal > 200) limitVal = 200; // Keep transport bounded within 64 KB

    BridgeList<HANDLEINFO> hs;
    bool ok = dbg->EnumHandles(&hs);
    if (!ok)
    {
        responseText = "{\"error\":\"failed to enumerate handles\"}\n";
        return;
    }

    int totalCount = hs.Count();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"total_count\":%d,\"offset\":%d,\"limit\":%d,\"handles\":[",
        totalCount, offsetVal, limitVal);

    for (int i = startIdx; i < endIdx && bufOffset < (int)responseBufSize - 1024; i++)
    {
        char name[MAX_PATH] = { 0 };
        char typeName[MAX_PATH] = { 0 };
        dbg->GetHandleName(hs[i].Handle, name, sizeof(name), typeName, sizeof(typeName));

        char safeName[MAX_PATH * 2] = { 0 };
        escape_json_string(name, safeName, sizeof(safeName));

        char safeTypeName[MAX_PATH * 2] = { 0 };
        escape_json_string(typeName, safeTypeName, sizeof(safeTypeName));

        bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
            "%s{\"handle\":\"0x%016llX\",\"type_number\":%u,\"type_name\":\"%s\","
            "\"granted_access\":\"0x%08X\",\"name\":\"%s\"}",
            (i > startIdx ? "," : ""),
            (unsigned long long)hs[i].Handle,
            (unsigned int)hs[i].TypeNumber,
            safeTypeName,
            (unsigned int)hs[i].GrantedAccess,
            safeName);
    }

    bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;

    hs.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] list_handles: total=%d, slice %d..%d\n",
                      totalCount, startIdx, endIdx);
}

void handle_get_handle_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_handle_info: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        _plugin_logprintf("[x64dbg-MCP] get_handle_info: debuggee is running.\n");
        responseText = "{\"error\":\"debuggee is running; handle info only available when paused\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->GetHandleName == nullptr)
    {
        responseText = "{\"error\":\"GetHandleName API not available\"}\n";
        return;
    }

    char handleStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "handle", handleStr, sizeof(handleStr)) || handleStr[0] == '\0')
    {
        int handleInt = 0;
        if (json_get_int(readBuf, "handle", &handleInt))
        {
            sprintf_s(handleStr, sizeof(handleStr), "%d", handleInt);
        }
        else
        {
            responseText = "{\"error\":\"missing or invalid 'handle' parameter\"}\n";
            return;
        }
    }

    const char* pAddr = handleStr;
    while (*pAddr == ' ' || *pAddr == '\t') pAddr++;
    int base = 10;
    if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X'))
    {
        pAddr += 2;
        base = 16;
    }
    char* endPtr = nullptr;
    duint handleVal = (duint)_strtoui64(pAddr, &endPtr, base);
    if (endPtr == pAddr)
    {
        responseText = "{\"error\":\"invalid handle format\"}\n";
        return;
    }

    char name[MAX_PATH] = { 0 };
    char typeName[MAX_PATH] = { 0 };
    bool found = dbg->GetHandleName(handleVal, name, sizeof(name), typeName, sizeof(typeName));

    if (!found || strcmp(name, "ERROR_INVALID_HANDLE") == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"handle\":\"0x%016llX\",\"found\":false}\n",
            (unsigned long long)handleVal);
        responseText = responseBuf;
        return;
    }

    char safeName[MAX_PATH * 2] = { 0 };
    escape_json_string(name, safeName, sizeof(safeName));

    char safeTypeName[MAX_PATH * 2] = { 0 };
    escape_json_string(typeName, safeTypeName, sizeof(safeTypeName));

    sprintf_s(responseBuf, responseBufSize,
        "{\"handle\":\"0x%016llX\",\"found\":true,\"type_name\":\"%s\",\"name\":\"%s\"}\n",
        (unsigned long long)handleVal, safeTypeName, safeName);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] get_handle_info: 0x%llX -> %s (%s)\n",
                      (unsigned long long)handleVal, safeTypeName, safeName);
}

void handle_list_tcp_connections(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_tcp_connections: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumTcpConnections == nullptr)
    {
        responseText = "{\"error\":\"EnumTcpConnections API not available\"}\n";
        return;
    }

    BridgeList<TCPCONNECTIONINFO> conns;
    bool ok = dbg->EnumTcpConnections(&conns);
    int count = ok ? conns.Count() : 0;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"connections\":[", count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 512; i++)
    {
        char safeRemote[TCP_ADDR_SIZE * 2] = { 0 };
        escape_json_string(conns[i].RemoteAddress, safeRemote, sizeof(safeRemote));

        char safeLocal[TCP_ADDR_SIZE * 2] = { 0 };
        escape_json_string(conns[i].LocalAddress, safeLocal, sizeof(safeLocal));

        char safeState[TCP_ADDR_SIZE * 2] = { 0 };
        escape_json_string(conns[i].StateText, safeState, sizeof(safeState));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            "%s{\"local_address\":\"%s\",\"local_port\":%u,\"remote_address\":\"%s\","
            "\"remote_port\":%u,\"state_text\":\"%s\",\"state\":%u}",
            (i > 0 ? "," : ""),
            safeLocal,
            (unsigned int)conns[i].LocalPort,
            safeRemote,
            (unsigned int)conns[i].RemotePort,
            safeState,
            conns[i].State);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;

    conns.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] list_tcp_connections: %d connections returned.\n", count);
}

void handle_list_windows(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_windows: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumWindows == nullptr)
    {
        responseText = "{\"error\":\"EnumWindows API not available\"}\n";
        return;
    }

    BridgeList<WINDOW_INFO> wins;
    bool ok = dbg->EnumWindows(&wins);
    int count = ok ? wins.Count() : 0;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"windows\":[", count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 1024; i++)
    {
        char safeTitle[MAX_COMMENT_SIZE * 2] = { 0 };
        escape_json_string(wins[i].windowTitle, safeTitle, sizeof(safeTitle));

        char safeClass[MAX_COMMENT_SIZE * 2] = { 0 };
        escape_json_string(wins[i].windowClass, safeClass, sizeof(safeClass));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            "%s{\"handle\":\"0x%016llX\",\"parent\":\"0x%016llX\",\"thread_id\":%u,"
            "\"style\":\"0x%08X\",\"style_ex\":\"0x%08X\",\"wnd_proc\":\"0x%016llX\","
            "\"enabled\":%s,\"title\":\"%s\",\"class_name\":\"%s\"}",
            (i > 0 ? "," : ""),
            (unsigned long long)wins[i].handle,
            (unsigned long long)wins[i].parent,
            (unsigned int)wins[i].threadId,
            (unsigned int)wins[i].style,
            (unsigned int)wins[i].styleEx,
            (unsigned long long)wins[i].wndProc,
            wins[i].enabled ? "true" : "false",
            safeTitle,
            safeClass);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    responseText = responseBuf;

    wins.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] list_windows: %d windows returned.\n", count);
}
