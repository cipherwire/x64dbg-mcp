#include "analysis.h"
#include <_scriptapi_function.h>
#include <bridgegraph.h>
#include <vector>
#include <set>
#include <queue>
#include <string>
#include <sstream>
#include <iomanip>

static volatile LONG g_analysisActive = 0;

static std::string to_hex(duint val)
{
    std::ostringstream ss;
    ss << std::uppercase << std::setfill('0') << std::setw(sizeof(duint) * 2) << std::hex << val;
    return ss.str();
}

// RAII helper for GUI Disassembly selection preservation
class GuiSelectionGuard
{
public:
    explicit GuiSelectionGuard(duint targetAddr)
        : m_restored(false)
    {
        memset(&m_oldSel, 0, sizeof(m_oldSel));
        m_hadOldSel = GuiSelectionGet(GUI_DISASSEMBLY, &m_oldSel);

        SELECTIONDATA newSel = { targetAddr, targetAddr };
        GuiSelectionSet(GUI_DISASSEMBLY, &newSel);
    }

    ~GuiSelectionGuard()
    {
        Restore();
    }

    void Restore()
    {
        if (!m_restored)
        {
            if (m_hadOldSel)
            {
                GuiSelectionSet(GUI_DISASSEMBLY, &m_oldSel);
            }
            m_restored = true;
        }
    }

private:
    SELECTIONDATA m_oldSel;
    bool m_hadOldSel;
    bool m_restored;
};

static void execute_analysis_tool(const char* toolName, const char* cmdString, const char* readBuf,
                                  char* responseBuf, size_t responseBufSize, const char*& responseText,
                                  bool hasOption = false, bool optionVal = false)
{
    (void)toolName;
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        // Try 'entry' parameter as well
        if (!json_get_string(readBuf, "entry", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing address/entry parameter\"}}\n";
            return;
        }
    }

    duint targetVA = 0;
    if (!resolve_address(addrStr, &targetVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address expression\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(targetVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_address\",\"message\":\"Target address does not reside in readable mapped memory\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_analysisActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"concurrency_conflict\",\"message\":\"Another analysis operation is already in progress\"}}\n";
        return;
    }

    duint memSize = 0;
    duint memBase = DbgMemFindBaseAddr(targetVA, &memSize);

    bool cmdOk = false;
    {
        GuiSelectionGuard selGuard(targetVA);
        cmdOk = DbgCmdExecDirect(cmdString);
    }

    InterlockedExchange(&g_analysisActive, 0);

    if (!cmdOk)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":{\"code\":\"analysis_failed\",\"message\":\"x64dbg command '%s' execution failed\"}}\n",
                  cmdString);
        responseText = responseBuf;
        return;
    }

    if (hasOption)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"tool\":\"%s\",\"address\":\"0x%016llX\",\"base\":\"0x%016llX\",\"size\":%llu,\"use_exception_directory\":%s,\"command\":\"%s\",\"status\":\"completed\",\"success\":true}\n",
                  toolName,
                  (unsigned long long)targetVA,
                  (unsigned long long)memBase,
                  (unsigned long long)memSize,
                  optionVal ? "true" : "false",
                  cmdString);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"tool\":\"%s\",\"address\":\"0x%016llX\",\"base\":\"0x%016llX\",\"size\":%llu,\"command\":\"%s\",\"status\":\"completed\",\"success\":true}\n",
                  toolName,
                  (unsigned long long)targetVA,
                  (unsigned long long)memBase,
                  (unsigned long long)memSize,
                  cmdString);
    }
    responseText = responseBuf;
}

// 1. analyze_code
void handle_analyze_code(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_analysis_tool("analyze_code", "analyse", readBuf, responseBuf, responseBufSize, responseText);
}

// 2. analyze_control_flow
void handle_analyze_control_flow(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool useExDir = false;
    json_get_bool(readBuf, "use_exception_directory", &useExDir);

    const char* cmd = useExDir ? "cfanal 1" : "cfanal";
    execute_analysis_tool("analyze_control_flow", cmd, readBuf, responseBuf, responseBufSize, responseText, true, useExDir);
}

// 3. analyze_exception_directory
void handle_analyze_exception_directory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_analysis_tool("analyze_exception_directory", "exanal", readBuf, responseBuf, responseBufSize, responseText);
}

// 4. analyze_recursive
void handle_analyze_recursive(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"No active debuggee session\"}}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":{\"code\":\"invalid_state\",\"message\":\"Debuggee is currently running\"}}\n";
        return;
    }

    char entryStr[64] = { 0 };
    if (!json_get_string(readBuf, "entry", entryStr, sizeof(entryStr)) || entryStr[0] == '\0')
    {
        if (!json_get_string(readBuf, "address", entryStr, sizeof(entryStr)) || entryStr[0] == '\0')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing entry address parameter\"}}\n";
            return;
        }
    }

    duint entryVA = 0;
    if (!resolve_address(entryStr, &entryVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid entry address expression\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(entryVA))
    {
        responseText = "{\"error\":{\"code\":\"invalid_address\",\"message\":\"Entry address does not reside in readable mapped memory\"}}\n";
        return;
    }

    if (InterlockedCompareExchange(&g_analysisActive, 1, 0) != 0)
    {
        responseText = "{\"error\":{\"code\":\"concurrency_conflict\",\"message\":\"Another analysis operation is already in progress\"}}\n";
        return;
    }

    char cmd[128] = { 0 };
    sprintf_s(cmd, sizeof(cmd), "analrecur 0x%llX", (unsigned long long)entryVA);

    bool ok = DbgCmdExecDirect(cmd);
    InterlockedExchange(&g_analysisActive, 0);

    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":{\"code\":\"analysis_failed\",\"message\":\"x64dbg command '%s' execution failed\"}}\n",
                  cmd);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"tool\":\"analyze_recursive\",\"entry\":\"0x%016llX\",\"command\":\"%s\",\"status\":\"completed\",\"success\":true}\n",
              (unsigned long long)entryVA,
              cmd);
    responseText = responseBuf;
}

// 5. analyze_advanced
void handle_analyze_advanced(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_analysis_tool("analyze_advanced", "analadv", readBuf, responseBuf, responseBufSize, responseText);
}

// 6. analyze_xrefs
void handle_analyze_xrefs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_analysis_tool("analyze_xrefs", "analxrefs", readBuf, responseBuf, responseBufSize, responseText);
}

// 7. analyze_nukem
void handle_analyze_nukem(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    execute_analysis_tool("analyze_nukem", "analyse_nukem", readBuf, responseBuf, responseBufSize, responseText);
}

// ---------------------------------------------------------------------------
static bool safe_dbg_analyze_function(duint entry, BridgeCFGraphList* graph)
{
    __try {
        return DbgAnalyzeFunction(entry, graph);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Group C - Structured Control-Flow Graph
// ---------------------------------------------------------------------------
void handle_get_control_flow_graph(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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

    duint entry = 0;
    if (!resolve_address(addrStr, &entry))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address expression\"}}\n";
        return;
    }

    if (!DbgMemIsValidReadPtr(entry))
    {
        responseText = "{\"error\":{\"code\":\"invalid_address\",\"message\":\"Target address does not reside in readable mapped memory\"}}\n";
        return;
    }

    // If inside a known function, use function start
    duint fnStart = 0, fnEnd = 0, fnIcount = 0;
    if (Script::Function::Get(entry, &fnStart, &fnEnd, &fnIcount) && fnStart != 0)
    {
        entry = fnStart;
    }

    int maxBlocks = 256;
    json_get_int(readBuf, "max_blocks", &maxBlocks);
    if (maxBlocks < 1) maxBlocks = 1;
    if (maxBlocks > 1024) maxBlocks = 1024;

    // First attempt: native BridgeCFGraph via DbgAnalyzeFunction
    BridgeCFGraphList graphList = { 0 };
    bool nativeSuccess = safe_dbg_analyze_function(entry, &graphList);

    if (nativeSuccess && graphList.nodes.count > 0 && graphList.nodes.data != nullptr)
    {
        auto nodeList = (BridgeCFNodeList*)graphList.nodes.data;
        int count = min(graphList.nodes.count, maxBlocks);

        std::string json = "{\"entry\":\"0x" + to_hex(entry) + "\",\"method\":\"native_bridge\",\"block_count\":" + std::to_string(count) + ",\"blocks\":[";
        for (int i = 0; i < count; i++)
        {
            if (i > 0) json += ",";
            const auto& node = nodeList[i];
            json += "{\"start\":\"0x" + to_hex(node.start) + "\",\"end\":\"0x" + to_hex(node.end) +
                    "\",\"instructions\":" + std::to_string(node.icount) +
                    ",\"terminal\":" + (node.terminal ? "true" : "false") +
                    ",\"indirect_call\":" + (node.indirectcall ? "true" : "false") + "}";
        }
        json += "],\"edges\":[";

        bool firstEdge = true;
        for (int i = 0; i < count; i++)
        {
            const auto& node = nodeList[i];
            if (node.brtrue != 0)
            {
                if (!firstEdge) json += ",";
                firstEdge = false;
                std::string edgeType = (node.brfalse != 0) ? "conditional_true" : "unconditional_jump";
                json += "{\"from\":\"0x" + to_hex(node.start) + "\",\"to\":\"0x" + to_hex(node.brtrue) + "\",\"type\":\"" + edgeType + "\"}";
            }
            if (node.brfalse != 0)
            {
                if (!firstEdge) json += ",";
                firstEdge = false;
                json += "{\"from\":\"0x" + to_hex(node.start) + "\",\"to\":\"0x" + to_hex(node.brfalse) + "\",\"type\":\"conditional_false\"}";
            }
        }
        json += "],\"success\":true}\n";

        BridgeCFGraph::Free(&graphList);

        if (json.length() < responseBufSize)
        {
            strcpy_s(responseBuf, responseBufSize, json.c_str());
            responseText = responseBuf;
            return;
        }
    }

    // Fallback: bounded recursive disassembly traversal
    struct FallbackBlock {
        duint start;
        duint end;
        duint instructions;
        bool terminal;
    };
    struct FallbackEdge {
        duint from;
        duint to;
        std::string type;
    };

    std::vector<FallbackBlock> blocks;
    std::vector<FallbackEdge> edges;
    std::set<duint> visitedStarts;
    std::queue<duint> queue;

    queue.push(entry);
    visitedStarts.insert(entry);

    while (!queue.empty() && blocks.size() < (size_t)maxBlocks)
    {
        duint bStart = queue.front();
        queue.pop();

        duint curr = bStart;
        duint instrCount = 0;
        bool blockEnded = false;
        duint bEnd = bStart;
        bool terminal = false;

        while (!blockEnded && instrCount < 256)
        {
            if (!DbgMemIsValidReadPtr(curr))
            {
                blockEnded = true;
                break;
            }

            DISASM_INSTR instr = { 0 };
            DbgDisasmAt(curr, &instr);
            if (instr.instr_size == 0)
            {
                blockEnded = true;
                break;
            }

            instrCount++;
            bEnd = curr;
            duint nextAddr = curr + instr.instr_size;

            unsigned char op = (unsigned char)instr.instruction[0];
            // Check ret
            if (strstr(instr.instruction, "ret") != nullptr || op == 0xC3 || op == 0xC2)
            {
                terminal = true;
                blockEnded = true;
                edges.push_back({ bStart, 0, "return" });
            }
            // Check unconditional jmp
            else if (instr.type == instr_branch && strstr(instr.instruction, "jmp") != nullptr)
            {
                blockEnded = true;
                // Read jump target
                unsigned char code[16] = { 0 };
                DbgMemRead(curr, code, instr.instr_size);
                duint targetVA = 0;
                if (code[0] == 0xE9 && instr.instr_size >= 5) // jmp rel32
                {
                    int rel = *(int*)(code + 1);
                    targetVA = curr + 5 + rel;
                }
                else if (code[0] == 0xEB && instr.instr_size >= 2) // jmp rel8
                {
                    signed char rel8 = (signed char)code[1];
                    targetVA = curr + 2 + rel8;
                }

                if (targetVA != 0)
                {
                    edges.push_back({ bStart, targetVA, "unconditional_jump" });
                    if (visitedStarts.find(targetVA) == visitedStarts.end())
                    {
                        visitedStarts.insert(targetVA);
                        queue.push(targetVA);
                    }
                }
                else
                {
                    edges.push_back({ bStart, 0, "unresolved_indirect" });
                }
            }
            // Check conditional jcc
            else if (instr.type == instr_branch && strstr(instr.instruction, "j") != nullptr && strstr(instr.instruction, "jmp") == nullptr)
            {
                blockEnded = true;
                unsigned char code[16] = { 0 };
                DbgMemRead(curr, code, instr.instr_size);
                duint targetVA = 0;
                if (code[0] == 0x0F && (code[1] & 0xF0) == 0x80 && instr.instr_size >= 6) // jcc rel32
                {
                    int rel = *(int*)(code + 2);
                    targetVA = curr + 6 + rel;
                }
                else if ((code[0] & 0xF0) == 0x70 && instr.instr_size >= 2) // jcc rel8
                {
                    signed char rel8 = (signed char)code[1];
                    targetVA = curr + 2 + rel8;
                }

                if (targetVA != 0)
                {
                    edges.push_back({ bStart, targetVA, "conditional_true" });
                    if (visitedStarts.find(targetVA) == visitedStarts.end())
                    {
                        visitedStarts.insert(targetVA);
                        queue.push(targetVA);
                    }
                }
                // Fallthrough edge
                edges.push_back({ bStart, nextAddr, "conditional_false" });
                if (visitedStarts.find(nextAddr) == visitedStarts.end())
                {
                    visitedStarts.insert(nextAddr);
                    queue.push(nextAddr);
                }
            }

            curr = nextAddr;
        }

        blocks.push_back({ bStart, bEnd, instrCount, terminal });
    }

    std::string json = "{\"entry\":\"0x" + to_hex(entry) + "\",\"method\":\"recursive_disasm\",\"block_count\":" + std::to_string(blocks.size()) + ",\"blocks\":[";
    for (size_t i = 0; i < blocks.size(); i++)
    {
        if (i > 0) json += ",";
        json += "{\"start\":\"0x" + to_hex(blocks[i].start) + "\",\"end\":\"0x" + to_hex(blocks[i].end) +
                "\",\"instructions\":" + std::to_string(blocks[i].instructions) +
                ",\"terminal\":" + (blocks[i].terminal ? "true" : "false") + "}";
    }
    json += "],\"edges\":[";
    for (size_t i = 0; i < edges.size(); i++)
    {
        if (i > 0) json += ",";
        json += "{\"from\":\"0x" + to_hex(edges[i].from) + "\",\"to\":\"0x" + to_hex(edges[i].to) + "\",\"type\":\"" + edges[i].type + "\"}";
    }
    json += "],\"success\":true}\n";

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}

// ---------------------------------------------------------------------------
// Group D - Function Relationships
// ---------------------------------------------------------------------------
void handle_get_function_callers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address expression\"}}\n";
        return;
    }

    // Determine function start
    duint fnStart = 0, fnEnd = 0, fnIcount = 0;
    if (Script::Function::Get(targetVA, &fnStart, &fnEnd, &fnIcount) && fnStart != 0)
    {
        targetVA = fnStart;
    }

    size_t count = DbgGetXrefCountAt(targetVA);

    struct CallerInfo {
        duint callSite;
        duint callerFn;
        char instruction[64];
        std::string callType;
    };
    std::vector<CallerInfo> callers;
    std::set<duint> seenCallSites;

    if (count > 0)
    {
        std::vector<XREF_RECORD> records(count);
        XREF_INFO info = { (duint)count, records.data() };
        if (DbgXrefGet(targetVA, &info))
        {
            for (duint i = 0; i < info.refcount; i++)
            {
                duint callAddr = records[i].addr;
                if (seenCallSites.count(callAddr) > 0)
                    continue;

                DISASM_INSTR instr = { 0 };
                DbgDisasmAt(callAddr, &instr);
                if (strstr(instr.instruction, "call") != nullptr)
                {
                    seenCallSites.insert(callAddr);
                    duint callerFn = 0;
                    Script::Function::Get(callAddr, &callerFn);

                    unsigned char code[16] = { 0 };
                    DbgMemRead(callAddr, code, sizeof(code));
                    std::string callType = (code[0] == 0xE8) ? "direct_call" : "indirect_call";

                    CallerInfo cinfo;
                    cinfo.callSite = callAddr;
                    cinfo.callerFn = callerFn;
                    strcpy_s(cinfo.instruction, instr.instruction);
                    cinfo.callType = callType;
                    callers.push_back(cinfo);
                }
            }
        }
    }

    std::string json = "{\"target_address\":\"0x" + to_hex(targetVA) + "\",\"caller_count\":" + std::to_string(callers.size()) + ",\"callers\":[";
    for (size_t i = 0; i < callers.size(); i++)
    {
        if (i > 0) json += ",";
        char safeInstr[128] = { 0 };
        escape_json_string(callers[i].instruction, safeInstr, sizeof(safeInstr));

        json += "{\"call_site\":\"0x" + to_hex(callers[i].callSite) +
                "\",\"caller_function\":\"0x" + to_hex(callers[i].callerFn) +
                "\",\"instruction\":\"" + safeInstr +
                "\",\"call_type\":\"" + callers[i].callType + "\"}";
    }
    json += "],\"success\":true}\n";

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}

void handle_get_function_callees(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address expression\"}}\n";
        return;
    }

    duint fnStart = 0, fnEnd = 0, fnIcount = 0;
    if (!Script::Function::Get(va, &fnStart, &fnEnd, &fnIcount) || fnStart == 0)
    {
        fnStart = va;
        fnEnd = va + 512;
    }

    int maxCallees = 100;
    json_get_int(readBuf, "max_callees", &maxCallees);
    if (maxCallees < 1) maxCallees = 1;
    if (maxCallees > 500) maxCallees = 500;

    struct CalleeInfo {
        duint callSite;
        duint calleeAddr;
        char instruction[64];
        char module[MAX_MODULE_SIZE];
        char symbol[MAX_LABEL_SIZE];
        std::string callType;
    };

    std::vector<CalleeInfo> callees;
    std::set<duint> seenCallees;

    duint curr = fnStart;
    duint scanLimit = min(fnEnd, fnStart + 0x4000);

    while (curr <= scanLimit && callees.size() < (size_t)maxCallees)
    {
        if (!DbgMemIsValidReadPtr(curr))
            break;

        DISASM_INSTR instr = { 0 };
        DbgDisasmAt(curr, &instr);
        if (instr.instr_size == 0)
            break;

        if (strstr(instr.instruction, "call") != nullptr)
        {
            unsigned char code[16] = { 0 };
            DbgMemRead(curr, code, min(instr.instr_size, 16));

            duint calleeVA = 0;
            std::string callType = "direct";
            if (code[0] == 0xE8 && instr.instr_size >= 5) // direct call rel32
            {
                int rel = *(int*)(code + 1);
                calleeVA = curr + 5 + rel;
                callType = "direct";
            }
            else if (code[0] == 0xFF && code[1] == 0x15 && instr.instr_size >= 6) // call qword ptr [rip+rel]
            {
                int rel = *(int*)(code + 2);
                duint ptr = curr + 6 + rel;
                DbgMemRead(ptr, &calleeVA, sizeof(calleeVA));
                callType = "indirect_import";
            }
            else
            {
                callType = "indirect_reg";
            }

            char symName[MAX_LABEL_SIZE] = { 0 };
            char modName[MAX_MODULE_SIZE] = { 0 };
            if (calleeVA != 0)
            {
                DbgGetLabelAt(calleeVA, SEG_DEFAULT, symName);
                if (DbgFunctions() && DbgFunctions()->ModNameFromAddr)
                {
                    DbgFunctions()->ModNameFromAddr(calleeVA, modName, true);
                }
            }

            CalleeInfo info;
            info.callSite = curr;
            info.calleeAddr = calleeVA;
            strcpy_s(info.instruction, instr.instruction);
            strcpy_s(info.module, modName);
            strcpy_s(info.symbol, symName);
            info.callType = callType;
            callees.push_back(info);
        }

        curr += instr.instr_size;
    }

    std::string json = "{\"function_start\":\"0x" + to_hex(fnStart) + "\",\"function_end\":\"0x" + to_hex(fnEnd) + "\",\"callee_count\":" + std::to_string(callees.size()) + ",\"callees\":[";
    for (size_t i = 0; i < callees.size(); i++)
    {
        if (i > 0) json += ",";
        char safeInstr[128] = { 0 };
        char safeSym[MAX_LABEL_SIZE * 2] = { 0 };
        char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(callees[i].instruction, safeInstr, sizeof(safeInstr));
        escape_json_string(callees[i].symbol, safeSym, sizeof(safeSym));
        escape_json_string(callees[i].module, safeMod, sizeof(safeMod));

        json += "{\"call_site\":\"0x" + to_hex(callees[i].callSite) +
                "\",\"callee_address\":\"0x" + to_hex(callees[i].calleeAddr) +
                "\",\"instruction\":\"" + safeInstr +
                "\",\"module\":\"" + safeMod +
                "\",\"symbol\":\"" + safeSym +
                "\",\"call_type\":\"" + callees[i].callType + "\"}";
    }
    json += "],\"success\":true}\n";

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}
