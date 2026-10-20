#include "scripts.h"

void handle_run_script(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char path[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "path", path, sizeof(path)) || path[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or empty path parameter\"}}\n";
        return;
    }

    // Validate file existence
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY))
    {
        responseText = "{\"error\":{\"code\":\"not_found\",\"message\":\"Script file does not exist or is a directory\"}}\n";
        return;
    }

    char cmd[MAX_PATH + 32] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "scriptexec \"%s\"", path);

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"script_error\",\"message\":\"Script execution failed or was aborted\"}}\n";
        return;
    }

    char safePath[MAX_PATH * 2] = { 0 };
    escape_json_string(path, safePath, sizeof(safePath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"path\":\"%s\",\"success\":true,\"message\":\"Script executed successfully\"}\n",
              safePath);
    responseText = responseBuf;

    _plugin_logprintf("[x64dbg-MCP] run_script executed successfully: %s\n", path);
}
