#include "address_info.h"
#include "memory.h"

// Decodes a SYMBOLTYPE enum value to a stable string
const char* decode_symbol_type(SYMBOLTYPE type)
{
    switch (type)
    {
    case sym_import: return "IMPORT";
    case sym_export: return "EXPORT";
    case sym_symbol: return "SYMBOL";
    default:         return "UNKNOWN";
    }
}

void handle_get_address_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_address_info: no debuggee active.\n");
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
                Script::Module::ModuleInfo modInfo = { 0 };
                bool modFound = Script::Module::InfoFromAddr(va, &modInfo);

                SYMBOLINFOCPP symInfo;
                bool symFound = DbgGetSymbolInfoAt(va, &symInfo);

                duint funcStart = 0;
                duint funcEnd = 0;
                bool funcFound = DbgFunctionGet(va, &funcStart, &funcEnd);

                int offset = sprintf_s(responseBuf, responseBufSize,
                    "{\"address\":\"0x%016llX\",", (unsigned long long)va);

                // Module section
                if (modFound && offset < (int)responseBufSize - 1024)
                {
                    char escapedModName[MAX_MODULE_SIZE * 2] = { 0 };
                    char escapedModPath[MAX_PATH * 2] = { 0 };
                    escape_json_string(modInfo.name, escapedModName, sizeof(escapedModName));
                    escape_json_string(modInfo.path, escapedModPath, sizeof(escapedModPath));
                    duint modOffset = (va >= modInfo.base) ? (va - modInfo.base) : 0;

                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"module\":{\"found\":true,\"name\":\"%s\",\"base\":\"0x%016llX\",\"size\":%llu,\"entry\":\"0x%016llX\",\"section_count\":%d,\"path\":\"%s\",\"offset\":%llu},",
                        escapedModName,
                        (unsigned long long)modInfo.base,
                        (unsigned long long)modInfo.size,
                        (unsigned long long)modInfo.entry,
                        modInfo.sectionCount,
                        escapedModPath,
                        (unsigned long long)modOffset);
                }
                else
                {
                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"module\":{\"found\":false},");
                }

                // Symbol section
                if (symFound && offset < (int)responseBufSize - 2048)
                {
                    const char* rawSymName = (symInfo.undecoratedSymbol && symInfo.undecoratedSymbol[0] != '\0')
                        ? symInfo.undecoratedSymbol
                        : ((symInfo.decoratedSymbol && symInfo.decoratedSymbol[0] != '\0') ? symInfo.decoratedSymbol : "");

                    char escapedSymName[2048] = { 0 };
                    escape_json_string(rawSymName, escapedSymName, sizeof(escapedSymName));

                    char decNameBuf[2048] = { 0 };
                    if (symInfo.decoratedSymbol && symInfo.decoratedSymbol[0] != '\0')
                    {
                        char escapedDec[1900] = { 0 };
                        escape_json_string(symInfo.decoratedSymbol, escapedDec, sizeof(escapedDec));
                        sprintf_s(decNameBuf, sizeof(decNameBuf), "\"%s\"", escapedDec);
                    }
                    else
                    {
                        strcpy_s(decNameBuf, sizeof(decNameBuf), "null");
                    }

                    duint symDisp = (va >= symInfo.addr) ? (va - symInfo.addr) : 0;

                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"symbol\":{\"found\":true,\"address\":\"0x%016llX\",\"name\":\"%s\",\"decorated_name\":%s,\"type\":\"%s\",\"type_raw\":%d,\"ordinal\":%u,\"displacement\":%llu},",
                        (unsigned long long)symInfo.addr,
                        escapedSymName,
                        decNameBuf,
                        decode_symbol_type(symInfo.type),
                        (int)symInfo.type,
                        (unsigned int)symInfo.ordinal,
                        (unsigned long long)symDisp);
                }
                else
                {
                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"symbol\":{\"found\":false},");
                }

                // Function section
                if (funcFound && offset < (int)responseBufSize - 512)
                {
                    duint funcDisp = (va >= funcStart) ? (va - funcStart) : 0;
                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"function\":{\"found\":true,\"start\":\"0x%016llX\",\"end\":\"0x%016llX\",\"displacement\":%llu}}\n",
                        (unsigned long long)funcStart,
                        (unsigned long long)funcEnd,
                        (unsigned long long)funcDisp);
                }
                else
                {
                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "\"function\":{\"found\":false}}\n");
                }

                responseText = responseBuf;

                _plugin_logprintf("[x64dbg-MCP] get_address_info for 0x%016llX: mod=%d, sym=%d, func=%d\n",
                                  (unsigned long long)va, modFound ? 1 : 0, symFound ? 1 : 0, funcFound ? 1 : 0);
            }
        }
    }
}
