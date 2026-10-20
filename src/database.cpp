#include "database.h"
#include "annotations.h"
#include "functions.h"
#include "environment.h"
#include <_scriptapi_comment.h>
#include <_scriptapi_label.h>
#include <_scriptapi_bookmark.h>
#include <_scriptapi_function.h>
#include <Windows.h>
#include <stdio.h>
#include <string>

static CRITICAL_SECTION g_dbMutationCs;
static bool g_dbCsInitialized = false;

void database_init()
{
    if (!g_dbCsInitialized)
    {
        InitializeCriticalSection(&g_dbMutationCs);
        g_dbCsInitialized = true;
    }
}

void database_cleanup()
{
    if (g_dbCsInitialized)
    {
        DeleteCriticalSection(&g_dbMutationCs);
        g_dbCsInitialized = false;
    }
}

void db_mutation_lock()
{
    if (g_dbCsInitialized)
    {
        EnterCriticalSection(&g_dbMutationCs);
    }
}

void db_mutation_unlock()
{
    if (g_dbCsInitialized)
    {
        LeaveCriticalSection(&g_dbMutationCs);
    }
}

void handle_save_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] save_database: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    DbMutationGuard guard;

    char path[MAX_PATH] = { 0 };
    bool hasPath = json_get_string(readBuf, "path", path, sizeof(path)) && path[0] != '\0';

    bool compression = true;
    bool compVal = true;
    if (json_get_bool(readBuf, "compression", &compVal))
    {
        compression = compVal;
    }

    char cmd[MAX_PATH * 2] = { 0 };
    if (hasPath)
    {
        sprintf_s(cmd, sizeof(cmd), "dbsave \"%s\"", path);
    }
    else
    {
        strcpy_s(cmd, sizeof(cmd), "dbsave");
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        if (hasPath)
        {
            sprintf_s(cmd, sizeof(cmd), "savedb \"%s\"", path);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "savedb");
        }
        ok = DbgCmdExecDirect(cmd);
    }

    if (!ok)
    {
        _plugin_logprintf("[x64dbg-MCP] save_database failed.\n");
        responseText = "{\"error\":\"dbsave command failed\"}\n";
        return;
    }

    char escapedPath[MAX_PATH * 2] = { 0 };
    if (hasPath)
    {
        escape_json_string(path, escapedPath, sizeof(escapedPath));
    }
    else
    {
        char modName[MAX_MODULE_SIZE] = { 0 };
        duint entry = DbgValFromString("cip");
        if (entry && DbgFunctions() && DbgFunctions()->ModNameFromAddr)
        {
            DbgFunctions()->ModNameFromAddr(entry, modName, true);
        }
        if (modName[0] != '\0')
        {
            escape_json_string(modName, escapedPath, sizeof(escapedPath));
        }
        else
        {
            strcpy_s(escapedPath, sizeof(escapedPath), "default");
        }
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"saved\":true,\"path\":\"%s\",\"compression\":%s}\n",
              escapedPath, compression ? "true" : "false");
    responseText = responseBuf;
}

void handle_load_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] load_database: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    DbMutationGuard guard;

    char path[MAX_PATH] = { 0 };
    bool hasPath = json_get_string(readBuf, "path", path, sizeof(path)) && path[0] != '\0';

    char cmd[MAX_PATH * 2] = { 0 };
    if (hasPath)
    {
        sprintf_s(cmd, sizeof(cmd), "dbload \"%s\"", path);
    }
    else
    {
        strcpy_s(cmd, sizeof(cmd), "dbload");
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        if (hasPath)
        {
            sprintf_s(cmd, sizeof(cmd), "loaddb \"%s\"", path);
        }
        else
        {
            strcpy_s(cmd, sizeof(cmd), "loaddb");
        }
        ok = DbgCmdExecDirect(cmd);
    }

    if (!ok)
    {
        _plugin_logprintf("[x64dbg-MCP] load_database failed.\n");
        responseText = "{\"error\":\"dbload command failed\"}\n";
        return;
    }

    char escapedPath[MAX_PATH * 2] = { 0 };
    if (hasPath)
    {
        escape_json_string(path, escapedPath, sizeof(escapedPath));
    }
    else
    {
        strcpy_s(escapedPath, sizeof(escapedPath), "default");
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"loaded\":true,\"path\":\"%s\"}\n",
              escapedPath);
    responseText = responseBuf;
}

void handle_clear_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)responseBuf;
    (void)responseBufSize;

    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] clear_database: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Confirmation required: set confirm to true to clear database\"}\n";
        return;
    }

    DbMutationGuard guard;

    Script::Comment::Clear();
    Script::Label::Clear();
    Script::Bookmark::Clear();
    Script::Function::Clear();
    DbgCmdExecDirect("loopclear");
    DbgCmdExecDirect("argumentclear");

    // Also queue dbclear asynchronously to ensure internal debugger structures and GUI stay synchronized
    DbgCmdExec("dbclear");

    responseText = "{\"status\":\"success\",\"cleared\":true}\n";
}

bool dispatch_commands_phase26(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "save_database") == 0)
    {
        handle_save_database(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "load_database") == 0)
    {
        handle_load_database(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_database") == 0)
    {
        handle_clear_database(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "list_comments") == 0)
    {
        handle_list_comments(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "delete_comment") == 0)
    {
        handle_delete_comment(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_comments") == 0)
    {
        handle_clear_comments(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "list_labels") == 0)
    {
        handle_list_labels(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "delete_label") == 0)
    {
        handle_delete_label(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_labels") == 0)
    {
        handle_clear_labels(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "list_bookmarks") == 0)
    {
        handle_list_bookmarks(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "delete_bookmark") == 0)
    {
        handle_delete_bookmark(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_bookmarks") == 0)
    {
        handle_clear_bookmarks(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_function") == 0)
    {
        handle_add_function(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "delete_function") == 0)
    {
        handle_delete_function(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_functions") == 0)
    {
        handle_clear_functions(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_command_line") == 0)
    {
        handle_set_command_line(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}
