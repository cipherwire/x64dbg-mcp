#include "functions.h"
#include "database.h"
#include <_scriptapi_function.h>
#include <_scriptapi_argument.h>

void handle_get_function_boundary(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_function_boundary: no debuggee active.\n");
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

    duint start = 0;
    duint end = 0;
    duint instrCount = 0;
    bool found = Script::Function::Get(va, &start, &end, &instrCount);
    if (!found)
    {
        found = DbgFunctionGet(va, &start, &end);
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":false}\n",
                  (unsigned long long)va);
    }
    else
    {
        duint size = (end >= start) ? (end - start + 1) : 0;
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"size\":%llu,\"instruction_count\":%llu}\n",
                  (unsigned long long)va,
                  (unsigned long long)start,
                  (unsigned long long)end,
                  (unsigned long long)size,
                  (unsigned long long)instrCount);
    }
    responseText = responseBuf;
}

// -------------------------------------------------------------
// Group C - Loops
// -------------------------------------------------------------

void handle_get_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int depth = 0;
    json_get_int(readBuf, "depth", &depth);
    if (depth < 0) depth = 0;

    duint start = 0;
    duint end = 0;
    bool found = DbgLoopGet(depth, va, &start, &end);
    LOOPTYPE ltype = DbgGetLoopTypeAt(va, depth);
    const char* typeStr = "none";
    switch (ltype)
    {
    case LOOP_BEGIN: typeStr = "begin"; break;
    case LOOP_MIDDLE: typeStr = "middle"; break;
    case LOOP_ENTRY: typeStr = "entry"; break;
    case LOOP_END: typeStr = "end"; break;
    case LOOP_SINGLE: typeStr = "single"; break;
    default: typeStr = "none"; break;
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"found\":false,\"address\":\"0x%016llX\",\"depth\":%d,\"success\":true}\n",
                  (unsigned long long)va, depth);
    }
    else
    {
        duint size = (end >= start) ? (end - start + 1) : 0;
        sprintf_s(responseBuf, responseBufSize,
                  "{\"found\":true,\"address\":\"0x%016llX\",\"depth\":%d,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"size\":%llu,\"type\":\"%s\",\"success\":true}\n",
                  (unsigned long long)va, depth,
                  (unsigned long long)start, (unsigned long long)end,
                  (unsigned long long)size, typeStr);
    }
    responseText = responseBuf;
}

void handle_list_loops(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    DbgCmdExecDirect("looplist");
    int count = GuiReferenceGetRowCount();
    if (count < 0) count = 0;

    int offset = sprintf_s(responseBuf, responseBufSize, "{\"count\":%d,\"loops\":[", count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 512; i++)
    {
        char* sStart = GuiReferenceGetCellContent(i, 0);
        char* sEnd = GuiReferenceGetCellContent(i, 1);
        char* sDepth = GuiReferenceGetCellContent(i, 2);
        char* sParent = GuiReferenceGetCellContent(i, 3);
        char* sDisasm = GuiReferenceGetCellContent(i, 4);
        char* sComment = GuiReferenceGetCellContent(i, 5);

        char safeDisasm[256] = { 0 };
        char safeComment[256] = { 0 };
        if (sDisasm) escape_json_string(sDisasm, safeDisasm, sizeof(safeDisasm));
        if (sComment) escape_json_string(sComment, safeComment, sizeof(safeComment));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            "%s{\"start\":\"%s\",\"end\":\"%s\",\"depth\":%s,\"parent\":\"%s\",\"disassembly\":\"%s\",\"comment\":\"%s\"}",
            (i > 0 ? "," : ""),
            sStart ? sStart : "",
            sEnd ? sEnd : "",
            sDepth ? sDepth : "0",
            sParent ? sParent : "",
            safeDisasm,
            safeComment);

        if (sStart) BridgeFree(sStart);
        if (sEnd) BridgeFree(sEnd);
        if (sDepth) BridgeFree(sDepth);
        if (sParent) BridgeFree(sParent);
        if (sDisasm) BridgeFree(sDisasm);
        if (sComment) BridgeFree(sComment);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_add_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char startStr[64] = { 0 };
    char endStr[64] = { 0 };
    if (!json_get_string(readBuf, "start", startStr, sizeof(startStr)) || startStr[0] == '\0' ||
        !json_get_string(readBuf, "end", endStr, sizeof(endStr)) || endStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing start or end parameter\"}}\n";
        return;
    }

    duint startVA = 0, endVA = 0;
    if (!resolve_address(startStr, &startVA) || !resolve_address(endStr, &endVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    if (startVA >= endVA)
    {
        responseText = "{\"error\":{\"code\":\"invalid_range\",\"message\":\"Start address must be strictly less than end address\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(startVA) || !DbgMemIsValidReadPtr(endVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Start and end addresses must be valid mapped readable memory\"}}\n";
        return;
    }

    if (DbgLoopOverlaps(0, startVA, endVA))
    {
        responseText = "{\"error\":{\"code\":\"overlap\",\"message\":\"Loop overlaps with an existing loop range\"}}\n";
        return;
    }

    bool ok = DbgLoopAdd(startVA, endVA);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"DbgLoopAdd failed\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"added\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"success\":true}\n",
              (unsigned long long)startVA, (unsigned long long)endVA);
    responseText = responseBuf;
}

void handle_delete_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    int depth = 0;
    json_get_int(readBuf, "depth", &depth);
    if (depth < 0) depth = 0;

    bool ok = DbgLoopDel(depth, va);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"not_found\",\"message\":\"Loop not found at specified address and depth\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"deleted\":true,\"address\":\"0x%016llX\",\"depth\":%d,\"success\":true}\n",
              (unsigned long long)va, depth);
    responseText = responseBuf;
}

void handle_clear_loops(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    DbgCmdExecDirect("loopclear");
    sprintf_s(responseBuf, responseBufSize, "{\"cleared\":true,\"success\":true,\"message\":\"All loops cleared\"}\n");
    responseText = responseBuf;
}

// -------------------------------------------------------------
// Group C - Arguments
// -------------------------------------------------------------

void handle_get_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    duint start = 0;
    duint end = 0;
    duint instrCount = 0;
    bool found = Script::Argument::Get(va, &start, &end, &instrCount);
    if (!found)
    {
        found = DbgArgumentGet(va, &start, &end);
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"found\":false,\"address\":\"0x%016llX\",\"success\":true}\n",
                  (unsigned long long)va);
    }
    else
    {
        duint size = (end >= start) ? (end - start + 1) : 0;
        sprintf_s(responseBuf, responseBufSize,
                  "{\"found\":true,\"address\":\"0x%016llX\",\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"size\":%llu,\"instruction_count\":%llu,\"success\":true}\n",
                  (unsigned long long)va,
                  (unsigned long long)start,
                  (unsigned long long)end,
                  (unsigned long long)size,
                  (unsigned long long)instrCount);
    }
    responseText = responseBuf;
}

void handle_list_arguments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    BridgeList<Script::Argument::ArgumentInfo> argList;
    bool ok = Script::Argument::GetList(&argList);
    int count = ok ? argList.Count() : 0;

    int offset = sprintf_s(responseBuf, responseBufSize, "{\"count\":%d,\"arguments\":[", count);

    for (int i = 0; i < count && offset < (int)responseBufSize - 512; i++)
    {
        duint modBase = DbgModBaseFromName(argList[i].mod);
        duint startVA = modBase + argList[i].rvaStart;
        duint endVA = modBase + argList[i].rvaEnd;

        char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(argList[i].mod, safeMod, sizeof(safeMod));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
            "%s{\"module\":\"%s\",\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"manual\":%s,\"instruction_count\":%llu}",
            (i > 0 ? "," : ""),
            safeMod,
            (unsigned long long)startVA,
            (unsigned long long)endVA,
            argList[i].manual ? "true" : "false",
            (unsigned long long)argList[i].instructioncount);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_add_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char startStr[64] = { 0 };
    char endStr[64] = { 0 };
    if (!json_get_string(readBuf, "start", startStr, sizeof(startStr)) || startStr[0] == '\0' ||
        !json_get_string(readBuf, "end", endStr, sizeof(endStr)) || endStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing start or end parameter\"}}\n";
        return;
    }

    duint startVA = 0, endVA = 0;
    if (!resolve_address(startStr, &startVA) || !resolve_address(endStr, &endVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    if (startVA >= endVA)
    {
        responseText = "{\"error\":{\"code\":\"invalid_range\",\"message\":\"Start address must be strictly less than end address\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(startVA) || !DbgMemIsValidReadPtr(endVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Start and end addresses must be valid mapped readable memory\"}}\n";
        return;
    }

    if (Script::Argument::Overlaps(startVA, endVA) || DbgArgumentOverlaps(startVA, endVA))
    {
        responseText = "{\"error\":{\"code\":\"overlap\",\"message\":\"Argument range overlaps with an existing argument\"}}\n";
        return;
    }

    bool ok = Script::Argument::Add(startVA, endVA, true);
    if (!ok)
    {
        ok = DbgArgumentAdd(startVA, endVA);
    }

    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Failed to add argument\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"added\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"success\":true}\n",
              (unsigned long long)startVA, (unsigned long long)endVA);
    responseText = responseBuf;
}

void handle_delete_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    bool ok = Script::Argument::Delete(va);
    if (!ok)
    {
        ok = DbgArgumentDel(va);
    }

    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"not_found\",\"message\":\"Argument not found at specified address\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"deleted\":true,\"address\":\"0x%016llX\",\"success\":true}\n",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_clear_arguments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    Script::Argument::Clear();
    DbgCmdExecDirect("argumentclear");
    sprintf_s(responseBuf, responseBufSize, "{\"cleared\":true,\"success\":true,\"message\":\"All arguments cleared\"}\n");
    responseText = responseBuf;
}

void handle_list_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char modFilter[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modFilter, sizeof(modFilter));

    int offset = 0;
    json_get_int(readBuf, "offset", &offset);
    if (offset < 0) offset = 0;

    int limit = 100;
    json_get_int(readBuf, "limit", &limit);
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    BridgeList<Script::Function::FunctionInfo> list;
    if (!Script::Function::GetList(&list))
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"Script::Function::GetList failed\"}}\n";
        return;
    }

    int totalInList = list.Count();
    struct MatchedFn {
        char mod[MAX_MODULE_SIZE];
        duint start;
        duint end;
        duint icount;
        bool manual;
    };
    std::vector<MatchedFn> matched;
    matched.reserve(min(totalInList, 1000));

    for (int i = 0; i < totalInList; i++)
    {
        const auto& item = list[i];
        if (modFilter[0] != '\0' && _stricmp(item.mod, modFilter) != 0)
        {
            continue;
        }

        duint modBase = DbgModBaseFromName(item.mod);
        duint startVA = modBase ? (modBase + item.rvaStart) : item.rvaStart;
        duint endVA = modBase ? (modBase + item.rvaEnd) : item.rvaEnd;

        MatchedFn fn;
        strcpy_s(fn.mod, item.mod);
        fn.start = startVA;
        fn.end = endVA;
        fn.icount = item.instructioncount;
        fn.manual = item.manual;
        matched.push_back(fn);
    }

    size_t totalMatched = matched.size();
    size_t startIdx = (size_t)min((size_t)offset, totalMatched);
    size_t endIdx = (size_t)min(startIdx + limit, totalMatched);
    size_t returnedCount = (endIdx >= startIdx) ? (endIdx - startIdx) : 0;

    sprintf_s(responseBuf, responseBufSize,
        "{\"total\":%zu,\"count\":%zu,\"offset\":%d,\"limit\":%d,\"functions\":[",
        totalMatched, returnedCount, offset, limit);

    for (size_t i = startIdx; i < endIdx; i++)
    {
        const auto& fn = matched[i];
        char itemJson[256];
        char escMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(fn.mod, escMod, sizeof(escMod));

        sprintf_s(itemJson, sizeof(itemJson),
            "%s{\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"size\":%llu,\"instruction_count\":%llu,\"manual\":%s,\"module\":\"%s\"}",
            (i > startIdx) ? "," : "",
            (unsigned long long)fn.start,
            (unsigned long long)fn.end,
            (unsigned long long)((fn.end >= fn.start) ? (fn.end - fn.start + 1) : 0),
            (unsigned long long)fn.icount,
            fn.manual ? "true" : "false",
            escMod);

        strcat_s(responseBuf, responseBufSize, itemJson);
    }

    strcat_s(responseBuf, responseBufSize, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_get_function_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    Script::Function::FunctionInfo info = { 0 };
    bool foundInfo = Script::Function::GetInfo(va, &info);
    duint start = 0, end = 0, instrCount = 0;
    bool foundBounds = Script::Function::Get(va, &start, &end, &instrCount);
    if (!foundBounds)
    {
        foundBounds = DbgFunctionGet(va, &start, &end);
    }

    if (!foundInfo && !foundBounds)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"address\":\"0x%016llX\",\"found\":false,\"success\":true}\n",
            (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    duint modBase = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (foundInfo && info.mod[0] != '\0')
    {
        strcpy_s(modName, info.mod);
        modBase = DbgModBaseFromName(info.mod);
    }
    else
    {
        if (DbgFunctions() && DbgFunctions()->ModNameFromAddr)
        {
            DbgFunctions()->ModNameFromAddr(va, modName, true);
        }
        modBase = DbgModBaseFromName(modName);
    }

    duint startVA = start;
    duint endVA = end;
    if (foundInfo)
    {
        if (modBase != 0)
        {
            startVA = modBase + info.rvaStart;
            endVA = modBase + info.rvaEnd;
        }
        if (instrCount == 0)
        {
            instrCount = info.instructioncount;
        }
    }

    duint size = (endVA >= startVA) ? (endVA - startVA + 1) : 0;
    duint rvaStart = (modBase && startVA >= modBase) ? (startVA - modBase) : 0;
    duint rvaEnd = (modBase && endVA >= modBase) ? (endVA - modBase) : 0;

    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modName, escMod, sizeof(escMod));

    sprintf_s(responseBuf, responseBufSize,
        "{\"address\":\"0x%016llX\",\"found\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"size\":%llu,\"instruction_count\":%llu,\"manual\":%s,\"module\":\"%s\",\"module_base\":\"0x%016llX\",\"rva_start\":\"0x%llX\",\"rva_end\":\"0x%llX\",\"success\":true}\n",
        (unsigned long long)va,
        (unsigned long long)startVA,
        (unsigned long long)endVA,
        (unsigned long long)size,
        (unsigned long long)instrCount,
        info.manual ? "true" : "false",
        escMod,
        (unsigned long long)modBase,
        (unsigned long long)rvaStart,
        (unsigned long long)rvaEnd);
    responseText = responseBuf;
}

void handle_add_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    char startStr[64] = { 0 };
    if (!json_get_string(readBuf, "start", startStr, sizeof(startStr)) || startStr[0] == '\0')
    {
        if (!json_get_string(readBuf, "entry", startStr, sizeof(startStr)) || startStr[0] == '\0')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing start/entry address parameter\"}}\n";
            return;
        }
    }

    char endStr[64] = { 0 };
    if (!json_get_string(readBuf, "end", endStr, sizeof(endStr)) || endStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing end address parameter\"}}\n";
        return;
    }

    duint start = 0;
    if (!resolve_address(startStr, &start))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid start address format\"}}\n";
        return;
    }

    duint end = 0;
    if (!resolve_address(endStr, &end))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid end address format\"}}\n";
        return;
    }

    if (start > end)
    {
        responseText = "{\"error\":{\"code\":\"invalid_range\",\"message\":\"Start address must be less than or equal to end address\"}}\n";
        return;
    }

    if (Script::Function::Overlaps(start, end))
    {
        responseText = "{\"error\":{\"code\":\"overlap_error\",\"message\":\"Function range overlaps with an existing function\"}}\n";
        return;
    }

    bool manual = true;
    bool parsedManual = true;
    if (json_get_bool(readBuf, "manual", &parsedManual))
    {
        manual = parsedManual;
    }

    int instrCount = 0;
    json_get_int(readBuf, "instruction_count", &instrCount);
    if (instrCount < 0) instrCount = 0;

    DbMutationGuard guard;
    bool ok = Script::Function::Add(start, end, manual, (duint)instrCount);
    if (!ok)
    {
        ok = DbgFunctionAdd(start, end);
    }

    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":{\"code\":\"api_failure\",\"message\":\"Script::Function::Add failed for range [0x%016llX, 0x%016llX]\"}}\n",
                  (unsigned long long)start, (unsigned long long)end);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"added\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"manual\":%s,\"instruction_count\":%u}\n",
              (unsigned long long)start,
              (unsigned long long)end,
              manual ? "true" : "false",
              (unsigned int)instrCount);
    responseText = responseBuf;
}

void handle_delete_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint va = 0;
    if (!resolve_address(addrStr, &va))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
        return;
    }

    DbMutationGuard guard;
    bool ok = Script::Function::Delete(va);
    if (!ok)
    {
        ok = DbgFunctionDel(va);
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"deleted\":%s,\"address\":\"0x%016llX\"}\n",
              ok ? "true" : "false",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_clear_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)responseBuf;
    (void)responseBufSize;

    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":{\"code\":\"confirmation_required\",\"message\":\"Confirmation required: set confirm to true to clear all functions\"}}\n";
        return;
    }

    DbMutationGuard guard;
    Script::Function::Clear();
    responseText = "{\"status\":\"success\",\"cleared\":true}\n";
}
