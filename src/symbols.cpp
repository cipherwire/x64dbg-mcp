#include "symbols.h"
#include <string>
#include <vector>
#include <algorithm>

static bool resolve_module_info(const char* mod_str, duint* out_base, char* out_name, size_t name_size, duint* out_size)
{
    if (!mod_str || mod_str[0] == '\0') return false;
    duint base = Script::Module::BaseFromName(mod_str);
    if (base == 0) {
        duint eval_val = 0;
        if (resolve_address(mod_str, &eval_val)) {
            base = Script::Module::BaseFromAddr(eval_val);
        }
    }
    if (base == 0) return false;
    if (out_base) *out_base = base;
    if (out_name && name_size > 0) {
        if (!Script::Module::NameFromAddr(base, out_name)) {
            strncpy_s(out_name, name_size, mod_str, _TRUNCATE);
        }
    }
    if (out_size) {
        *out_size = Script::Module::SizeFromAddr(base);
    }
    return true;
}

void handle_resolve_symbol(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] resolve_symbol: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char symInput[256] = { 0 };
    if (!json_get_string(readBuf, "symbol", symInput, sizeof(symInput)) || symInput[0] == '\0')
    {
        responseText = "{\"error\":\"missing symbol parameter\"}\n";
        return;
    }

    duint addr = 0;
    bool ok = DbgFunctions()->ValFromString(symInput, &addr);
    char escInput[512] = { 0 };
    escape_json_string(symInput, escInput, sizeof(escInput));

    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"input\":\"%s\",\"resolved\":false}\n", escInput);
        responseText = responseBuf;
        return;
    }

    char modname[MAX_MODULE_SIZE] = { 0 };
    duint modbase = Script::Module::BaseFromAddr(addr);
    bool has_mod = (modbase != 0) && Script::Module::NameFromAddr(addr, modname);
    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    if (has_mod)
    {
        escape_json_string(modname, escMod, sizeof(escMod));
    }

    SYMBOLINFOCPP symInfo;
    bool has_sym = DbgGetSymbolInfoAt(addr, &symInfo);

    char label[MAX_LABEL_SIZE] = { 0 };
    bool has_label = DbgGetLabelAt(addr, SEG_DEFAULT, label);
    char escLabel[MAX_LABEL_SIZE * 2] = { 0 };
    if (has_label && label[0] != '\0')
    {
        escape_json_string(label, escLabel, sizeof(escLabel));
    }

    if (has_sym)
    {
        char escName[1024] = { 0 };
        char escDemangled[1024] = { 0 };
        if (symInfo.decoratedSymbol)
            escape_json_string(symInfo.decoratedSymbol, escName, sizeof(escName));
        if (symInfo.undecoratedSymbol)
            escape_json_string(symInfo.undecoratedSymbol, escDemangled, sizeof(escDemangled));

        duint sym_rva = (modbase != 0 && addr >= modbase) ? (addr - modbase) : 0;

        const char* type_str = "symbol";
        switch (symInfo.type)
        {
        case sym_import: type_str = "import"; break;
        case sym_export: type_str = "export"; break;
        case sym_symbol: type_str = "symbol"; break;
        default: type_str = "unknown"; break;
        }

        if (escDemangled[0] != '\0')
        {
            sprintf_s(responseBuf, responseBufSize,
                "{\"input\":\"%s\",\"resolved\":true,\"address\":\"0x%016llX\",\"module\":\"%s\","
                "\"symbol_found\":true,\"is_exact_symbol\":true,"
                "\"symbol\":{\"name\":\"%s\",\"demangled_name\":\"%s\",\"type\":\"%s\",\"rva\":\"0x%llX\"}}\n",
                escInput, (unsigned long long)addr, escMod,
                escName, escDemangled, type_str, (unsigned long long)sym_rva);
        }
        else
        {
            sprintf_s(responseBuf, responseBufSize,
                "{\"input\":\"%s\",\"resolved\":true,\"address\":\"0x%016llX\",\"module\":\"%s\","
                "\"symbol_found\":true,\"is_exact_symbol\":true,"
                "\"symbol\":{\"name\":\"%s\",\"type\":\"%s\",\"rva\":\"0x%llX\"}}\n",
                escInput, (unsigned long long)addr, escMod,
                escName, type_str, (unsigned long long)sym_rva);
        }
    }
    else
    {
        if (has_label && escLabel[0] != '\0')
        {
            sprintf_s(responseBuf, responseBufSize,
                "{\"input\":\"%s\",\"resolved\":true,\"address\":\"0x%016llX\",\"module\":%s%s%s,"
                "\"symbol_found\":false,\"is_exact_symbol\":false,\"label\":\"%s\"}\n",
                escInput, (unsigned long long)addr,
                has_mod ? "\"" : "", has_mod ? escMod : "null", has_mod ? "\"" : "",
                escLabel);
        }
        else
        {
            sprintf_s(responseBuf, responseBufSize,
                "{\"input\":\"%s\",\"resolved\":true,\"address\":\"0x%016llX\",\"module\":%s%s%s,"
                "\"symbol_found\":false,\"is_exact_symbol\":false}\n",
                escInput, (unsigned long long)addr,
                has_mod ? "\"" : "", has_mod ? escMod : "null", has_mod ? "\"" : "");
        }
    }

    responseText = responseBuf;
}

struct SymbolListEntry {
    duint addr;
    duint rva;
    std::string name;
    std::string demangled;
    std::string type;
};

struct SymbolEnumContext {
    duint modbase;
    int offset;
    int limit;
    int current_index;
    bool has_more;
    std::vector<SymbolListEntry> entries;
};

static bool cb_symbol_enum(const struct SYMBOLPTR_* symbol, void* user)
{
    auto ctx = (SymbolEnumContext*)user;
    if (ctx->current_index < ctx->offset) {
        ctx->current_index++;
        return true;
    }

    if ((int)ctx->entries.size() >= ctx->limit) {
        ctx->has_more = true;
        return false;
    }

    SYMBOLINFOCPP info;
    DbgGetSymbolInfo(symbol, &info);

    SymbolListEntry entry;
    entry.addr = info.addr;
    entry.rva = (info.addr >= ctx->modbase) ? (info.addr - ctx->modbase) : 0;
    if (info.decoratedSymbol) entry.name = info.decoratedSymbol;
    if (info.undecoratedSymbol) entry.demangled = info.undecoratedSymbol;

    switch (info.type) {
    case sym_import: entry.type = "import"; break;
    case sym_export: entry.type = "export"; break;
    case sym_symbol: entry.type = "symbol"; break;
    default: entry.type = "unknown"; break;
    }

    ctx->entries.push_back(std::move(entry));
    ctx->current_index++;
    return true;
}

void handle_list_symbols(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_symbols: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    duint modbase = 0;
    char modname[MAX_MODULE_SIZE] = { 0 };
    duint modsize = 0;
    if (!resolve_module_info(modStr, &modbase, modname, sizeof(modname), &modsize))
    {
        responseText = "{\"error\":\"module not found\"}\n";
        return;
    }

    duint beginRva = 0;
    duint endRva = (modsize > 0) ? (modsize - 1) : 0;

    char startStr[64] = { 0 };
    if (json_get_string(readBuf, "start_address", startStr, sizeof(startStr)) ||
        json_get_string(readBuf, "start_rva", startStr, sizeof(startStr)))
    {
        duint val = 0;
        if (resolve_address(startStr, &val))
        {
            if (val >= modbase && val < modbase + modsize)
                beginRva = val - modbase;
            else
                beginRva = val;
        }
    }

    char endStr[64] = { 0 };
    if (json_get_string(readBuf, "end_address", endStr, sizeof(endStr)) ||
        json_get_string(readBuf, "end_rva", endStr, sizeof(endStr)))
    {
        duint val = 0;
        if (resolve_address(endStr, &val))
        {
            if (val >= modbase && val < modbase + modsize)
                endRva = val - modbase;
            else
                endRva = val;
        }
    }

    if (beginRva > endRva)
    {
        responseText = "{\"error\":\"start must be less than or equal to end\"}\n";
        return;
    }

    unsigned int symbolMask = SYMBOL_MASK_ALL;
    char maskStr[32] = { 0 };
    if (json_get_string(readBuf, "symbol_mask", maskStr, sizeof(maskStr)) && maskStr[0] != '\0')
    {
        if (_stricmp(maskStr, "all") == 0) symbolMask = SYMBOL_MASK_ALL;
        else if (_stricmp(maskStr, "symbol") == 0) symbolMask = SYMBOL_MASK_SYMBOL;
        else if (_stricmp(maskStr, "export") == 0) symbolMask = SYMBOL_MASK_EXPORT;
        else if (_stricmp(maskStr, "import") == 0) symbolMask = SYMBOL_MASK_IMPORT;
        else
        {
            responseText = "{\"error\":\"invalid symbol_mask: must be 'all', 'symbol', 'export', or 'import'\"}\n";
            return;
        }
    }

    int offsetVal = 0;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":\"offset must be non-negative\"}\n";
        return;
    }
    if (offsetVal < 0) offsetVal = 0;

    int limitVal = 100;
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":\"limit must be positive\"}\n";
        return;
    }
    if (limitVal <= 0) limitVal = 100;
    if (limitVal > 500) limitVal = 500;

    duint max_rva = (modsize > 0) ? (modsize - 1) : 0;
    if (endRva > max_rva) endRva = max_rva;
    duint start_va = modbase + beginRva;
    duint end_va = modbase + endRva;

    SymbolEnumContext ctx;
    ctx.modbase = modbase;
    ctx.offset = offsetVal;
    ctx.limit = limitVal;
    ctx.current_index = 0;
    ctx.has_more = false;

    if (symbolMask == SYMBOL_MASK_ALL && beginRva == 0 && endRva == max_rva)
    {
        DbgSymbolEnum(modbase, cb_symbol_enum, &ctx);
    }
    else
    {
        DbgSymbolEnumRange(start_va, end_va, symbolMask, cb_symbol_enum, &ctx);
    }

    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modname, escMod, sizeof(escMod));

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"offset\":%d,\"limit\":%d,\"count\":%d,\"has_more\":%s,\"symbols\":[",
        escMod, (unsigned long long)modbase, offsetVal, limitVal,
        (int)ctx.entries.size(), ctx.has_more ? "true" : "false");

    for (size_t i = 0; i < ctx.entries.size() && bufOffset < (int)responseBufSize - 1024; i++)
    {
        const auto& item = ctx.entries[i];
        char escName[512] = { 0 };
        char escDemangled[512] = { 0 };
        escape_json_string(item.name.c_str(), escName, sizeof(escName));
        escape_json_string(item.demangled.c_str(), escDemangled, sizeof(escDemangled));

        if (i > 0)
        {
            bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, ",");
        }

        if (escDemangled[0] != '\0')
        {
            bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
                "{\"name\":\"%s\",\"demangled_name\":\"%s\",\"address\":\"0x%016llX\",\"rva\":\"0x%llX\",\"type\":\"%s\"}",
                escName, escDemangled, (unsigned long long)item.addr, (unsigned long long)item.rva, item.type.c_str());
        }
        else
        {
            bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
                "{\"name\":\"%s\",\"address\":\"0x%016llX\",\"rva\":\"0x%llX\",\"type\":\"%s\"}",
                escName, (unsigned long long)item.addr, (unsigned long long)item.rva, item.type.c_str());
        }
    }

    sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;
}

void handle_get_symbol_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_symbol_status: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    duint modbase = 0;
    char modname[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_module_info(modStr, &modbase, modname, sizeof(modname), nullptr))
    {
        responseText = "{\"error\":\"module not found\"}\n";
        return;
    }

    MODULESYMBOLSTATUS status = DbgFunctions()->ModSymbolStatus(modbase);
    const char* status_str = "unknown";
    switch (status)
    {
    case MODSYMUNLOADED: status_str = "unloaded"; break;
    case MODSYMLOADING:  status_str = "loading";  break;
    case MODSYMLOADED:   status_str = "loaded";   break;
    default:             status_str = "unknown";  break;
    }

    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modname, escMod, sizeof(escMod));

    sprintf_s(responseBuf, responseBufSize,
        "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"status\":%d,\"status_string\":\"%s\"}\n",
        escMod, (unsigned long long)modbase, (int)status, status_str);
    responseText = responseBuf;
}

void handle_get_source_location(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_source_location: no debuggee active.\n");
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

    char sourceFile[MAX_STRING_SIZE] = { 0 };
    int line = 0;
    bool found = DbgFunctions()->GetSourceFromAddr(va, sourceFile, &line);

    if (found && sourceFile[0] != '\0')
    {
        char escFile[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(sourceFile, escFile, sizeof(escFile));
        sprintf_s(responseBuf, responseBufSize,
            "{\"found\":true,\"address\":\"0x%016llX\",\"source_file\":\"%s\",\"line\":%d,\"file_exists\":true}\n",
            (unsigned long long)va, escFile, line);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"found\":false,\"address\":\"0x%016llX\"}\n",
            (unsigned long long)va);
    }

    responseText = responseBuf;
}

void handle_find_source_address(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] find_source_address: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", modStr, sizeof(modStr)) || modStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    char srcFile[MAX_STRING_SIZE] = { 0 };
    if (!json_get_string(readBuf, "source_file", srcFile, sizeof(srcFile)) || srcFile[0] == '\0')
    {
        responseText = "{\"error\":\"missing source_file parameter\"}\n";
        return;
    }

    int line = 0;
    if (!json_get_int(readBuf, "line", &line) || line <= 0)
    {
        responseText = "{\"error\":\"invalid or missing line parameter: must be positive\"}\n";
        return;
    }

    duint modbase = 0;
    char modname[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_module_info(modStr, &modbase, modname, sizeof(modname), nullptr))
    {
        responseText = "{\"error\":\"module not found\"}\n";
        return;
    }

    duint addr = DbgFunctions()->GetAddrFromLineEx(modbase, srcFile, line);
    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    char escFile[MAX_STRING_SIZE * 2] = { 0 };
    escape_json_string(modname, escMod, sizeof(escMod));
    escape_json_string(srcFile, escFile, sizeof(escFile));

    if (addr != 0)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"found\":true,\"module\":\"%s\",\"source_file\":\"%s\",\"line\":%d,\"address\":\"0x%016llX\"}\n",
            escMod, escFile, line, (unsigned long long)addr);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"found\":false,\"module\":\"%s\",\"source_file\":\"%s\",\"line\":%d}\n",
            escMod, escFile, line);
    }

    responseText = responseBuf;
}

void handle_symbol_autocomplete(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] symbol_autocomplete: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char prefixStr[256] = { 0 };
    json_get_string(readBuf, "prefix", prefixStr, sizeof(prefixStr));

    int maxResults = 20;
    json_get_int(readBuf, "max_results", &maxResults);
    if (maxResults < 1) maxResults = 1;
    if (maxResults > 100) maxResults = 100;

    std::vector<char*> buffer(maxResults, nullptr);
    int count = DbgFunctions()->SymAutoComplete(prefixStr, buffer.data(), maxResults);
    if (count < 0) count = 0;
    if (count > maxResults) count = maxResults;

    char escPrefix[512] = { 0 };
    escape_json_string(prefixStr, escPrefix, sizeof(escPrefix));

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"prefix\":\"%s\",\"count\":%d,\"symbols\":[",
        escPrefix, count);

    for (int i = 0; i < count; i++)
    {
        if (buffer[i])
        {
            char escSym[512] = { 0 };
            escape_json_string(buffer[i], escSym, sizeof(escSym));
            BridgeFree(buffer[i]);

            if (i > 0)
            {
                bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, ",");
            }
            bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "\"%s\"", escSym);
        }
    }

    sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;
}
