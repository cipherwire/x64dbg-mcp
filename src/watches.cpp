#include "watches.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Helper to escape internal quotes for commands
static void escape_watch_cmd_quotes(const char* src, char* dst, size_t dstSize)
{
    if (!src || !dst || dstSize == 0) return;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d < dstSize - 2; s++)
    {
        if (src[s] == '\"')
        {
            if (d < dstSize - 3)
            {
                dst[d++] = '\\';
                dst[d++] = '\"';
            }
        }
        else
        {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
}

static const char* watch_type_to_string(WATCHVARTYPE type)
{
    switch (type)
    {
    case TYPE_UINT: return "uint";
    case TYPE_INT: return "int";
    case TYPE_FLOAT: return "float";
    case TYPE_ASCII: return "ascii";
    case TYPE_UNICODE: return "unicode";
    case TYPE_INVALID: return "invalid";
    default: return "unknown";
    }
}

static bool string_to_watch_type(const char* str, WATCHVARTYPE& type)
{
    if (!str) return false;
    if (_stricmp(str, "uint") == 0) { type = TYPE_UINT; return true; }
    if (_stricmp(str, "int") == 0) { type = TYPE_INT; return true; }
    if (_stricmp(str, "float") == 0) { type = TYPE_FLOAT; return true; }
    if (_stricmp(str, "ascii") == 0) { type = TYPE_ASCII; return true; }
    if (_stricmp(str, "unicode") == 0) { type = TYPE_UNICODE; return true; }
    return false;
}

static const char* watchdog_mode_to_string(WATCHDOGMODE mode)
{
    switch (mode)
    {
    case MODE_DISABLED: return "disabled";
    case MODE_ISTRUE: return "istrue";
    case MODE_ISFALSE: return "isfalse";
    case MODE_CHANGED: return "changed";
    case MODE_UNCHANGED: return "unchanged";
    default: return "disabled";
    }
}

static bool string_to_watchdog_mode(const char* str, WATCHDOGMODE& mode)
{
    if (!str) return false;
    if (_stricmp(str, "disabled") == 0) { mode = MODE_DISABLED; return true; }
    if (_stricmp(str, "changed") == 0) { mode = MODE_CHANGED; return true; }
    if (_stricmp(str, "unchanged") == 0) { mode = MODE_UNCHANGED; return true; }
    if (_stricmp(str, "istrue") == 0) { mode = MODE_ISTRUE; return true; }
    if (_stricmp(str, "isfalse") == 0) { mode = MODE_ISFALSE; return true; }
    return false;
}

static bool get_watch_list_internal(BridgeList<WATCHINFO>& list)
{
    // In x64dbg, _dbg_sendmessage(DBG_GET_WATCH_LIST) populates list via CopyData
    // but breaks out of the switch without returning 1, so DbgGetWatchList returns false.
    // However, CopyData successfully initializes the list structure, so list.Count() is valid.
    DbgGetWatchList(&list);
    return true;
}

static bool find_watch_by_id(unsigned int id, WATCHINFO& outInfo)
{
    BridgeList<WATCHINFO> list;
    get_watch_list_internal(list);
    for (int i = 0; i < list.Count(); i++)
    {
        if (list[i].id == id)
        {
            outInfo = list[i];
            return true;
        }
    }
    return false;
}

static bool parse_watch_id(const char* readBuf, unsigned int& outId)
{
    int idInt = 0;
    if (json_get_int(readBuf, "id", &idInt) && idInt > 0)
    {
        outId = (unsigned int)idInt;
        return true;
    }
    char idStr[64] = { 0 };
    if (json_get_string(readBuf, "id", idStr, sizeof(idStr)) && idStr[0] != '\0')
    {
        char* endPtr = nullptr;
        unsigned long val = strtoul(idStr, &endPtr, 0);
        if (val > 0 && endPtr != idStr)
        {
            outId = (unsigned int)val;
            return true;
        }
    }
    return false;
}

// 1. list_watches
void handle_list_watches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    BridgeList<WATCHINFO> list;
    get_watch_list_internal(list);

    size_t offset = 0;
    int written = sprintf_s(responseBuf, responseBufSize, "{\"status\":\"success\",\"count\":%d,\"watches\":[", list.Count());
    if (written > 0) offset += (size_t)written;

    for (int i = 0; i < list.Count(); i++)
    {
        const WATCHINFO& info = list[i];
        char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
        char escExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
        escape_json_string(info.WatchName, escName, sizeof(escName));
        escape_json_string(info.Expression, escExpr, sizeof(escExpr));

        const char* typeStr = watch_type_to_string(info.varType);
        const char* modeStr = watchdog_mode_to_string(info.watchdogMode);

        if (offset < responseBufSize - 512)
        {
            written = sprintf_s(responseBuf + offset, responseBufSize - offset,
                                "%s{\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"watchdog_mode\":\"%s\",\"watchdog_triggered\":%s,\"window\":%u}",
                                (i > 0) ? "," : "",
                                info.id,
                                escName,
                                escExpr,
                                typeStr,
                                (unsigned long long)info.value,
                                modeStr,
                                info.watchdogTriggered ? "true" : "false",
                                info.window);
            if (written > 0) offset += (size_t)written;
        }
    }

    if (offset < responseBufSize - 8)
    {
        strcpy_s(responseBuf + offset, responseBufSize - offset, "]}\n");
    }
    responseText = responseBuf;
}

// 2. get_watch
void handle_get_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    bool evalRequested = false;
    json_get_bool(readBuf, "evaluate", &evalRequested);

    WATCHINFO info = { 0 };
    if (!find_watch_by_id(id, info))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
    char escExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(info.WatchName, escName, sizeof(escName));
    escape_json_string(info.Expression, escExpr, sizeof(escExpr));

    const char* typeStr = watch_type_to_string(info.varType);
    const char* modeStr = watchdog_mode_to_string(info.watchdogMode);

    if (evalRequested)
    {
        duint evalVal = 0;
        bool evalOk = (DbgFunctions() && DbgFunctions()->ValFromString) ? DbgFunctions()->ValFromString(info.Expression, &evalVal) : false;

        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"success\",\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"evaluated_value\":\"0x%016llX\",\"evaluation_succeeded\":%s,\"watchdog_mode\":\"%s\",\"watchdog_triggered\":%s,\"window\":%u}\n",
                  info.id,
                  escName,
                  escExpr,
                  typeStr,
                  (unsigned long long)info.value,
                  (unsigned long long)evalVal,
                  evalOk ? "true" : "false",
                  modeStr,
                  info.watchdogTriggered ? "true" : "false",
                  info.window);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"status\":\"success\",\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"watchdog_mode\":\"%s\",\"watchdog_triggered\":%s,\"window\":%u}\n",
                  info.id,
                  escName,
                  escExpr,
                  typeStr,
                  (unsigned long long)info.value,
                  modeStr,
                  info.watchdogTriggered ? "true" : "false",
                  info.window);
    }
    responseText = responseBuf;
}

// 3. add_watch
void handle_add_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char expr[MAX_CONDITIONAL_EXPR_SIZE] = { 0 };
    if (!json_get_string(readBuf, "expression", expr, sizeof(expr)) || expr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"'expression' is required for add_watch\"}}\n";
        return;
    }

    char typeStr[32] = { 0 };
    WATCHVARTYPE varType = TYPE_UINT;
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (!string_to_watch_type(typeStr, varType))
        {
            responseText = "{\"error\":{\"code\":\"invalid_type\",\"message\":\"Invalid watch type: must be 'uint', 'int', 'float', 'ascii', or 'unicode'\"}}\n";
            return;
        }
    }

    char escExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_watch_cmd_quotes(expr, escExpr, sizeof(escExpr));

    char cmd[MAX_CONDITIONAL_EXPR_SIZE * 2 + 64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "AddWatch \"%s\", %s", escExpr, watch_type_to_string(varType));

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"AddWatch command failed in x64dbg\"}}\n";
        return;
    }

    duint resId = DbgValFromString("$result");
    if (resId == 0)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"AddWatch returned 0 id\"}}\n";
        return;
    }

    unsigned int newId = (unsigned int)resId;
    WATCHINFO info = { 0 };
    if (!find_watch_by_id(newId, info))
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"Watch was created but could not be located in watch list\"}}\n";
        return;
    }

    if (info.varType == TYPE_INVALID)
    {
        char delCmd[64] = { 0 };
        sprintf_s(delCmd, sizeof(delCmd), "DelWatch 0x%X", newId);
        DbgCmdExecDirect(delCmd);

        responseText = "{\"error\":{\"code\":\"invalid_expression\",\"message\":\"Watch expression evaluated to invalid syntax or type by x64dbg\"}}\n";
        return;
    }

    char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
    char escStoredExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(info.WatchName, escName, sizeof(escName));
    escape_json_string(info.Expression, escStoredExpr, sizeof(escStoredExpr));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"watchdog_mode\":\"%s\",\"watchdog_triggered\":%s,\"window\":%u}\n",
              info.id,
              escName,
              escStoredExpr,
              watch_type_to_string(info.varType),
              (unsigned long long)info.value,
              watchdog_mode_to_string(info.watchdogMode),
              info.watchdogTriggered ? "true" : "false",
              info.window);
    responseText = responseBuf;
}

// 4. modify_watch
void handle_modify_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    WATCHINFO prevInfo = { 0 };
    if (!find_watch_by_id(id, prevInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char expr[MAX_CONDITIONAL_EXPR_SIZE] = { 0 };
    if (!json_get_string(readBuf, "expression", expr, sizeof(expr)) || expr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"'expression' is required for modify_watch\"}}\n";
        return;
    }

    char typeStr[32] = { 0 };
    WATCHVARTYPE varType = prevInfo.varType;
    if (json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) && typeStr[0] != '\0')
    {
        if (!string_to_watch_type(typeStr, varType))
        {
            responseText = "{\"error\":{\"code\":\"invalid_type\",\"message\":\"Invalid watch type: must be 'uint', 'int', 'float', 'ascii', or 'unicode'\"}}\n";
            return;
        }
    }

    char escExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_watch_cmd_quotes(expr, escExpr, sizeof(escExpr));

    char cmd[MAX_CONDITIONAL_EXPR_SIZE * 2 + 64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetWatchExpression 0x%X, \"%s\", %s", id, escExpr, watch_type_to_string(varType));

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"SetWatchExpression command rejected by x64dbg\"}}\n";
        return;
    }

    WATCHINFO newInfo = { 0 };
    if (!find_watch_by_id(id, newInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found after modification\"}}\n";
        return;
    }

    // Verify whether modification succeeded: expression must match new expression and type must not be invalid
    if (newInfo.varType == TYPE_INVALID || strcmp(newInfo.Expression, expr) != 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_expression\",\"message\":\"Failed to modify watch expression: invalid expression syntax\"}}\n";
        return;
    }

    char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
    char escStoredExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(newInfo.WatchName, escName, sizeof(escName));
    escape_json_string(newInfo.Expression, escStoredExpr, sizeof(escStoredExpr));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"watchdog_mode\":\"%s\",\"watchdog_triggered\":%s,\"window\":%u}\n",
              newInfo.id,
              escName,
              escStoredExpr,
              watch_type_to_string(newInfo.varType),
              (unsigned long long)newInfo.value,
              watchdog_mode_to_string(newInfo.watchdogMode),
              newInfo.watchdogTriggered ? "true" : "false",
              newInfo.window);
    responseText = responseBuf;
}

// 5. rename_watch
void handle_rename_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    WATCHINFO prevInfo = { 0 };
    if (!find_watch_by_id(id, prevInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char name[MAX_WATCH_NAME_SIZE] = { 0 };
    if (!json_get_string(readBuf, "name", name, sizeof(name)) || name[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"'name' is required for rename_watch\"}}\n";
        return;
    }

    if (strlen(name) >= MAX_WATCH_NAME_SIZE)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Watch name exceeds maximum length (63 characters)\"}}\n";
        return;
    }

    char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
    escape_watch_cmd_quotes(name, escName, sizeof(escName));

    char cmd[MAX_WATCH_NAME_SIZE * 2 + 64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetWatchName 0x%X, \"%s\"", id, escName);

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"SetWatchName command failed in x64dbg\"}}\n";
        return;
    }

    WATCHINFO newInfo = { 0 };
    if (!find_watch_by_id(id, newInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found after rename\"}}\n";
        return;
    }

    char escStoredName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
    char escStoredExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
    escape_json_string(newInfo.WatchName, escStoredName, sizeof(escStoredName));
    escape_json_string(newInfo.Expression, escStoredExpr, sizeof(escStoredExpr));

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"id\":%u,\"name\":\"%s\",\"previous_name\":\"%s\",\"expression\":\"%s\"}\n",
              newInfo.id,
              escStoredName,
              prevInfo.WatchName,
              escStoredExpr);
    responseText = responseBuf;
}

// 6. set_watch_type
void handle_set_watch_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    WATCHINFO prevInfo = { 0 };
    if (!find_watch_by_id(id, prevInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char typeStr[32] = { 0 };
    if (!json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) || typeStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"missing_argument\",\"message\":\"'type' is required for set_watch_type\"}}\n";
        return;
    }

    WATCHVARTYPE newType;
    if (!string_to_watch_type(typeStr, newType))
    {
        responseText = "{\"error\":{\"code\":\"invalid_type\",\"message\":\"Invalid watch type: must be 'uint', 'int', 'float', 'ascii', or 'unicode'\"}}\n";
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "SetWatchType 0x%X, %s", id, watch_type_to_string(newType));

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"SetWatchType command failed in x64dbg\"}}\n";
        return;
    }

    WATCHINFO newInfo = { 0 };
    if (!find_watch_by_id(id, newInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found after type change\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"id\":%u,\"previous_type\":\"%s\",\"type\":\"%s\"}\n",
              newInfo.id,
              watch_type_to_string(prevInfo.varType),
              watch_type_to_string(newInfo.varType));
    responseText = responseBuf;
}

// 7. delete_watch
void handle_delete_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    WATCHINFO info = { 0 };
    if (!find_watch_by_id(id, info))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char cmd[64] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "DelWatch 0x%X", id);

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"DelWatch command failed in x64dbg\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"deleted\":true,\"id\":%u}\n",
              id);
    responseText = responseBuf;
}

// 8. clear_watches
void handle_clear_watches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":{\"code\":\"confirmation_required\",\"message\":\"Confirmation required: set confirm to true to clear all watch expressions\"}}\n";
        return;
    }

    BridgeList<WATCHINFO> list;
    int count = 0;
    if (get_watch_list_internal(list))
    {
        count = list.Count();
        for (int i = 0; i < count; i++)
        {
            char cmd[64] = { 0 };
            sprintf_s(cmd, sizeof(cmd), "DelWatch 0x%X", list[i].id);
            DbgCmdExecDirect(cmd);
        }
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"cleared\":true,\"deleted_count\":%d}\n",
              count);
    responseText = responseBuf;
}

// 9. set_watchdog
void handle_set_watchdog(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    unsigned int id = 0;
    if (!parse_watch_id(readBuf, id))
    {
        responseText = "{\"error\":{\"code\":\"invalid_watch_id\",\"message\":\"Invalid or missing watch 'id' parameter\"}}\n";
        return;
    }

    WATCHINFO prevInfo = { 0 };
    if (!find_watch_by_id(id, prevInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found with specified ID\"}}\n";
        return;
    }

    char modeStr[32] = { 0 };
    bool hasMode = json_get_string(readBuf, "mode", modeStr, sizeof(modeStr)) && modeStr[0] != '\0';

    char cmd[64] = { 0 };
    if (hasMode)
    {
        WATCHDOGMODE mode;
        if (!string_to_watchdog_mode(modeStr, mode))
        {
            responseText = "{\"error\":{\"code\":\"invalid_mode\",\"message\":\"Invalid watchdog mode: must be 'disabled', 'changed', 'unchanged', 'istrue', or 'isfalse'\"}}\n";
            return;
        }
        sprintf_s(cmd, sizeof(cmd), "SetWatchdog 0x%X, %s", id, watchdog_mode_to_string(mode));
    }
    else
    {
        // Omitted mode triggers native x64dbg toggle: disabled -> changed, enabled -> disabled
        sprintf_s(cmd, sizeof(cmd), "SetWatchdog 0x%X", id);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"SetWatchdog command failed in x64dbg\"}}\n";
        return;
    }

    WATCHINFO newInfo = { 0 };
    if (!find_watch_by_id(id, newInfo))
    {
        responseText = "{\"error\":{\"code\":\"watch_not_found\",\"message\":\"Watch not found after watchdog update\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"id\":%u,\"previous_mode\":\"%s\",\"mode\":\"%s\",\"watchdog_triggered\":%s}\n",
              newInfo.id,
              watchdog_mode_to_string(prevInfo.watchdogMode),
              watchdog_mode_to_string(newInfo.watchdogMode),
              newInfo.watchdogTriggered ? "true" : "false");
    responseText = responseBuf;
}

// 10. check_watchdogs
void handle_check_watchdogs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool ok = DbgCmdExecDirect("CheckWatchdog");
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"native_operation_failed\",\"message\":\"CheckWatchdog command failed in x64dbg\"}}\n";
        return;
    }

    duint res = DbgValFromString("$result");
    bool anyTriggered = (res != 0);

    BridgeList<WATCHINFO> list;
    int totalCount = 0;
    int triggeredCount = 0;

    size_t offset = 0;
    int written = sprintf_s(responseBuf, responseBufSize,
                            "{\"status\":\"success\",\"triggered\":%s,",
                            anyTriggered ? "true" : "false");
    if (written > 0) offset += (size_t)written;

    char watchArrBuf[32768] = { 0 };
    size_t arrOffset = 0;
    int arrWritten = sprintf_s(watchArrBuf, sizeof(watchArrBuf), "\"triggered_watches\":[");
    if (arrWritten > 0) arrOffset += (size_t)arrWritten;

    if (get_watch_list_internal(list))
    {
        totalCount = list.Count();
        for (int i = 0; i < totalCount; i++)
        {
            const WATCHINFO& info = list[i];
            if (info.watchdogTriggered)
            {
                char escName[MAX_WATCH_NAME_SIZE * 2] = { 0 };
                char escExpr[MAX_CONDITIONAL_EXPR_SIZE * 2] = { 0 };
                escape_json_string(info.WatchName, escName, sizeof(escName));
                escape_json_string(info.Expression, escExpr, sizeof(escExpr));

                if (arrOffset < sizeof(watchArrBuf) - 512)
                {
                    arrWritten = sprintf_s(watchArrBuf + arrOffset, sizeof(watchArrBuf) - arrOffset,
                                           "%s{\"id\":%u,\"name\":\"%s\",\"expression\":\"%s\",\"type\":\"%s\",\"value\":\"0x%016llX\",\"watchdog_mode\":\"%s\"}",
                                           (triggeredCount > 0) ? "," : "",
                                           info.id,
                                           escName,
                                           escExpr,
                                           watch_type_to_string(info.varType),
                                           (unsigned long long)info.value,
                                           watchdog_mode_to_string(info.watchdogMode));
                    if (arrWritten > 0) arrOffset += (size_t)arrWritten;
                }
                triggeredCount++;
            }
        }
    }

    if (arrOffset < sizeof(watchArrBuf) - 4)
    {
        strcpy_s(watchArrBuf + arrOffset, sizeof(watchArrBuf) - arrOffset, "]");
    }

    if (offset < responseBufSize - arrOffset - 64)
    {
        sprintf_s(responseBuf + offset, responseBufSize - offset,
                  "\"triggered_count\":%d,\"total_watches\":%d,%s}\n",
                  triggeredCount,
                  totalCount,
                  watchArrBuf);
    }

    responseText = responseBuf;
}

// Dispatch function for Phase 28
bool dispatch_commands_phase28(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "list_watches") == 0)
    {
        handle_list_watches(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_watch") == 0)
    {
        handle_get_watch(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_watch") == 0)
    {
        handle_add_watch(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "modify_watch") == 0)
    {
        handle_modify_watch(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "rename_watch") == 0)
    {
        handle_rename_watch(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_watch_type") == 0)
    {
        handle_set_watch_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "delete_watch") == 0)
    {
        handle_delete_watch(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_watches") == 0)
    {
        handle_clear_watches(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_watchdog") == 0)
    {
        handle_set_watchdog(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "check_watchdogs") == 0)
    {
        handle_check_watchdogs(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}
