#include "modules.h"

void handle_list_modules(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_modules: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        BridgeList<Script::Module::ModuleInfo> modList;
        bool ok = Script::Module::GetList(&modList);
        duint mainBase = Script::Module::GetMainModuleBase();
        int count = ok ? modList.Count() : 0;

        int offset = sprintf_s(responseBuf, responseBufSize,
                               "{\"count\":%d,\"main_module_base\":\"0x%016llX\",\"modules\":[",
                               count, (unsigned long long)mainBase);

        for (int i = 0; i < count && offset < (int)responseBufSize - 1024; i++)
        {
            bool isMain = (modList[i].base == mainBase);

            char safeName[MAX_MODULE_SIZE * 2] = { 0 };
            escape_json_string(modList[i].name, safeName, sizeof(safeName));

            char safePath[MAX_PATH * 2] = { 0 };
            escape_json_string(modList[i].path, safePath, sizeof(safePath));

            offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                "%s{\"name\":\"%s\",\"path\":\"%s\",\"base\":\"0x%016llX\",\"size\":%llu,"
                "\"entry\":\"0x%016llX\",\"section_count\":%d,\"is_main\":%s}",
                (i > 0 ? "," : ""),
                safeName,
                safePath,
                (unsigned long long)modList[i].base,
                (unsigned long long)modList[i].size,
                (unsigned long long)modList[i].entry,
                modList[i].sectionCount,
                isMain ? "true" : "false");
        }

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
        responseText = responseBuf;

        modList.Cleanup();

        _plugin_logprintf("[x64dbg-MCP] Listed %d modules (main base: 0x%llX).\n",
                          count, (unsigned long long)mainBase);
    }
}

void handle_list_module_sections(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_module_sections: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        char moduleStr[MAX_PATH] = { 0 };
        if (!json_get_string(readBuf, "module", moduleStr, sizeof(moduleStr)) || moduleStr[0] == '\0')
        {
            responseText = "{\"error\":\"missing module parameter\"}\n";
        }
        else
        {
            duint modBase = 0;

            // 1. Try resolving as module name first
            modBase = Script::Module::BaseFromName(moduleStr);

            // 2. If not found, try parsing as hex or decimal address pointing into a module
            if (modBase == 0)
            {
                const char* pAddr = moduleStr;
                while (*pAddr == ' ' || *pAddr == '\t') pAddr++;
                if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X'))
                {
                    pAddr += 2;
                }
                char* endPtr = nullptr;
                duint addrVal = (duint)_strtoui64(pAddr, &endPtr, 16);
                if (endPtr != pAddr && *endPtr == '\0' && addrVal != 0)
                {
                    modBase = Script::Module::BaseFromAddr(addrVal);
                }
            }

            if (modBase == 0)
            {
                char safeMod[MAX_PATH * 2] = { 0 };
                escape_json_string(moduleStr, safeMod, sizeof(safeMod));
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                          safeMod);
                responseText = responseBuf;
            }
            else
            {
                char modName[MAX_MODULE_SIZE] = { 0 };
                if (!Script::Module::NameFromAddr(modBase, modName) || modName[0] == '\0')
                {
                    strcpy_s(modName, moduleStr);
                }

                char safeModName[MAX_MODULE_SIZE * 2] = { 0 };
                escape_json_string(modName, safeModName, sizeof(safeModName));

                BridgeList<Script::Module::ModuleSectionInfo> sectionList;
                bool ok = Script::Module::SectionListFromAddr(modBase, &sectionList);

                if (!ok)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"error\":\"failed to retrieve section list\",\"module\":\"%s\"}\n",
                              safeModName);
                    responseText = responseBuf;
                }
                else
                {
                    int count = sectionList.Count();
                    int offset = sprintf_s(responseBuf, responseBufSize,
                        "{\"module\":{\"name\":\"%s\",\"base\":\"0x%016llX\"},\"count\":%d,\"sections\":[",
                        safeModName, (unsigned long long)modBase, count);

                    for (int i = 0; i < count && offset < (int)responseBufSize - 512; i++)
                    {
                        char safeSecName[MAX_SECTION_SIZE * 5 * 2] = { 0 };
                        escape_json_string(sectionList[i].name, safeSecName, sizeof(safeSecName));

                        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s{\"name\":\"%s\",\"addr\":\"0x%016llX\",\"size\":%llu}",
                            (i > 0 ? "," : ""),
                            safeSecName,
                            (unsigned long long)sectionList[i].addr,
                            (unsigned long long)sectionList[i].size);
                    }

                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
                    responseText = responseBuf;

                    sectionList.Cleanup();

                    _plugin_logprintf("[x64dbg-MCP] Listed %d sections for module %s (base 0x%llX).\n",
                                      count, safeModName, (unsigned long long)modBase);
                }
            }
        }
    }
}

void handle_list_imports(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_imports: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char moduleStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "module", moduleStr, sizeof(moduleStr)) || moduleStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
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
    if (limitVal > 500) limitVal = 500;

    duint modBase = Script::Module::BaseFromName(moduleStr);
    if (modBase == 0)
    {
        const char* pAddr = moduleStr;
        while (*pAddr == ' ' || *pAddr == '\t') pAddr++;
        if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X'))
        {
            pAddr += 2;
        }
        char* endPtr = nullptr;
        duint addrVal = (duint)_strtoui64(pAddr, &endPtr, 16);
        if (endPtr != pAddr && *endPtr == '\0' && addrVal != 0)
        {
            modBase = Script::Module::BaseFromAddr(addrVal);
        }
    }

    if (modBase == 0)
    {
        char safeMod[MAX_PATH * 2] = { 0 };
        escape_json_string(moduleStr, safeMod, sizeof(safeMod));
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                  safeMod);
        responseText = responseBuf;
        return;
    }

    Script::Module::ModuleInfo modInfo = { 0 };
    if (!Script::Module::InfoFromAddr(modBase, &modInfo))
    {
        if (!Script::Module::InfoFromName(moduleStr, &modInfo))
        {
            char safeMod[MAX_PATH * 2] = { 0 };
            escape_json_string(moduleStr, safeMod, sizeof(safeMod));
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                      safeMod);
            responseText = responseBuf;
            return;
        }
    }

    char safeModName[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modInfo.name, safeModName, sizeof(safeModName));

    BridgeList<Script::Module::ModuleImport> importList;
    bool ok = Script::Module::GetImports(&modInfo, &importList);
    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to retrieve imports\",\"module\":\"%s\"}\n",
                  safeModName);
        responseText = responseBuf;
        return;
    }

    int totalCount = importList.Count();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"module\":{\"name\":\"%s\",\"base\":\"0x%016llX\"},\"total_count\":%d,\"offset\":%d,\"limit\":%d,\"imports\":[",
        safeModName, (unsigned long long)modBase, totalCount, offsetVal, limitVal);

    for (int i = startIdx; i < endIdx && bufOffset < (int)responseBufSize - 1024; i++)
    {
        char safeName[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(importList[i].name, safeName, sizeof(safeName));

        char safeUndec[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(importList[i].undecoratedName, safeUndec, sizeof(safeUndec));

        long long ordVal = (importList[i].ordinal == (duint)-1) ? -1LL : (long long)importList[i].ordinal;

        bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
            "%s{\"name\":\"%s\",\"undecorated_name\":\"%s\",\"ordinal\":%lld,"
            "\"iat_rva\":\"0x%016llX\",\"iat_va\":\"0x%016llX\"}",
            (i > startIdx ? "," : ""),
            safeName,
            safeUndec,
            ordVal,
            (unsigned long long)importList[i].iatRva,
            (unsigned long long)importList[i].iatVa);
    }

    bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;

    importList.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] Listed imports for %s (total: %d, slice: %d..%d).\n",
                      safeModName, totalCount, startIdx, endIdx);
}

void handle_list_exports(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_exports: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char moduleStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "module", moduleStr, sizeof(moduleStr)) || moduleStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
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
    if (limitVal > 500) limitVal = 500;

    duint modBase = Script::Module::BaseFromName(moduleStr);
    if (modBase == 0)
    {
        const char* pAddr = moduleStr;
        while (*pAddr == ' ' || *pAddr == '\t') pAddr++;
        if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X'))
        {
            pAddr += 2;
        }
        char* endPtr = nullptr;
        duint addrVal = (duint)_strtoui64(pAddr, &endPtr, 16);
        if (endPtr != pAddr && *endPtr == '\0' && addrVal != 0)
        {
            modBase = Script::Module::BaseFromAddr(addrVal);
        }
    }

    if (modBase == 0)
    {
        char safeMod[MAX_PATH * 2] = { 0 };
        escape_json_string(moduleStr, safeMod, sizeof(safeMod));
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                  safeMod);
        responseText = responseBuf;
        return;
    }

    Script::Module::ModuleInfo modInfo = { 0 };
    if (!Script::Module::InfoFromAddr(modBase, &modInfo))
    {
        if (!Script::Module::InfoFromName(moduleStr, &modInfo))
        {
            char safeMod[MAX_PATH * 2] = { 0 };
            escape_json_string(moduleStr, safeMod, sizeof(safeMod));
            sprintf_s(responseBuf, responseBufSize,
                      "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                      safeMod);
            responseText = responseBuf;
            return;
        }
    }

    char safeModName[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modInfo.name, safeModName, sizeof(safeModName));

    BridgeList<Script::Module::ModuleExport> exportList;
    bool ok = Script::Module::GetExports(&modInfo, &exportList);
    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to retrieve exports\",\"module\":\"%s\"}\n",
                  safeModName);
        responseText = responseBuf;
        return;
    }

    int totalCount = exportList.Count();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"module\":{\"name\":\"%s\",\"base\":\"0x%016llX\"},\"total_count\":%d,\"offset\":%d,\"limit\":%d,\"exports\":[",
        safeModName, (unsigned long long)modBase, totalCount, offsetVal, limitVal);

    for (int i = startIdx; i < endIdx && bufOffset < (int)responseBufSize - 1024; i++)
    {
        char safeName[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(exportList[i].name, safeName, sizeof(safeName));

        char safeUndec[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(exportList[i].undecoratedName, safeUndec, sizeof(safeUndec));

        char safeForward[MAX_STRING_SIZE * 2] = { 0 };
        escape_json_string(exportList[i].forwardName, safeForward, sizeof(safeForward));

        bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
            "%s{\"name\":\"%s\",\"undecorated_name\":\"%s\",\"ordinal\":%llu,"
            "\"rva\":\"0x%016llX\",\"va\":\"0x%016llX\",\"forwarded\":%s,\"forward_name\":\"%s\"}",
            (i > startIdx ? "," : ""),
            safeName,
            safeUndec,
            (unsigned long long)exportList[i].ordinal,
            (unsigned long long)exportList[i].rva,
            (unsigned long long)exportList[i].va,
            exportList[i].forwarded ? "true" : "false",
            safeForward);
    }

    bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;

    exportList.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] Listed exports for %s (total: %d, slice: %d..%d).\n",
                      safeModName, totalCount, startIdx, endIdx);
}

void handle_va_to_file_offset(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] va_to_file_offset: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->VaToFileOffset == nullptr || dbg->FileOffsetToVa == nullptr)
    {
        responseText = "{\"error\":\"VaToFileOffset API not available\"}\n";
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

    duint modBase = Script::Module::BaseFromAddr(va);
    if (modBase == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":false,\"message\":\"address not within any loaded module\"}\n",
                  (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char modName[MAX_MODULE_SIZE] = { 0 };
    Script::Module::NameFromAddr(va, modName);

    duint fileOffset = dbg->VaToFileOffset(va);

    bool found = true;
    if (fileOffset == 0 && va != modBase)
    {
        duint roundtripVa = dbg->FileOffsetToVa(modName, fileOffset);
        if (roundtripVa != va)
        {
            found = false;
        }
    }

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modName, safeMod, sizeof(safeMod));

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"address\":\"0x%016llX\",\"module\":\"%s\",\"module_base\":\"0x%016llX\",\"rva\":\"0x%016llX\",\"found\":false}\n",
            (unsigned long long)va, safeMod, (unsigned long long)modBase, (unsigned long long)(va - modBase));
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"address\":\"0x%016llX\",\"module\":\"%s\",\"module_base\":\"0x%016llX\",\"rva\":\"0x%016llX\","
            "\"file_offset\":\"0x%llX\",\"file_offset_dec\":%llu,\"found\":true}\n",
            (unsigned long long)va, safeMod, (unsigned long long)modBase, (unsigned long long)(va - modBase),
            (unsigned long long)fileOffset, (unsigned long long)fileOffset);
    }
    responseText = responseBuf;
}

void handle_file_offset_to_va(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] file_offset_to_va: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->FileOffsetToVa == nullptr)
    {
        responseText = "{\"error\":\"FileOffsetToVa API not available\"}\n";
        return;
    }

    char moduleStr[MAX_MODULE_SIZE] = { 0 };
    if (!json_get_string(readBuf, "module", moduleStr, sizeof(moduleStr)) || moduleStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing module parameter\"}\n";
        return;
    }

    duint modBase = Script::Module::BaseFromName(moduleStr);
    if (modBase == 0)
    {
        const char* pAddr = moduleStr;
        while (*pAddr == ' ' || *pAddr == '\t') pAddr++;
        if (pAddr[0] == '0' && (pAddr[1] == 'x' || pAddr[1] == 'X')) pAddr += 2;
        char* endPtr = nullptr;
        duint addrVal = (duint)_strtoui64(pAddr, &endPtr, 16);
        if (endPtr != pAddr && *endPtr == '\0' && addrVal != 0)
        {
            modBase = Script::Module::BaseFromAddr(addrVal);
        }
    }

    if (modBase == 0)
    {
        char safeMod[MAX_PATH * 2] = { 0 };
        escape_json_string(moduleStr, safeMod, sizeof(safeMod));
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"module not found\",\"module\":\"%s\"}\n",
                  safeMod);
        responseText = responseBuf;
        return;
    }

    char modName[MAX_MODULE_SIZE] = { 0 };
    Script::Module::NameFromAddr(modBase, modName);

    int offsetInt = 0;
    if (!json_get_int(readBuf, "offset", &offsetInt) || offsetInt < 0)
    {
        responseText = "{\"error\":\"missing or invalid 'offset' parameter (must be non-negative integer)\"}\n";
        return;
    }

    duint offsetVal = (duint)offsetInt;
    duint va = dbg->FileOffsetToVa(modName, offsetVal);

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modName, safeMod, sizeof(safeMod));

    if (va == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"module\":\"%s\",\"module_base\":\"0x%016llX\",\"file_offset\":%llu,\"file_offset_hex\":\"0x%llX\",\"found\":false}\n",
            safeMod, (unsigned long long)modBase, (unsigned long long)offsetVal, (unsigned long long)offsetVal);
    }
    else
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"module\":\"%s\",\"module_base\":\"0x%016llX\",\"file_offset\":%llu,\"file_offset_hex\":\"0x%llX\","
            "\"address\":\"0x%016llX\",\"rva\":\"0x%016llX\",\"found\":true}\n",
            safeMod, (unsigned long long)modBase, (unsigned long long)offsetVal, (unsigned long long)offsetVal,
            (unsigned long long)va, (unsigned long long)(va - modBase));
    }
    responseText = responseBuf;
}

void handle_get_relocation(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_relocation: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->ModRelocationAtAddr == nullptr)
    {
        responseText = "{\"error\":\"ModRelocationAtAddr API not available\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address parameter\"}\n";
        return;
    }

    duint addr = 0;
    if (!resolve_address(addrStr, &addr))
    {
        responseText = "{\"error\":\"invalid address format\"}\n";
        return;
    }

    DBGRELOCATIONINFO reloc = { 0 };
    bool found = dbg->ModRelocationAtAddr(addr, &reloc);

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"found\":false}\n",
                  (unsigned long long)addr);
        responseText = responseBuf;
        return;
    }

    duint modBase = Script::Module::BaseFromAddr(addr);
    char modName[MAX_MODULE_SIZE] = { 0 };
    Script::Module::NameFromAddr(addr, modName);

    const char* typeName = "UNKNOWN";
    switch (reloc.type)
    {
    case 0: typeName = "ABSOLUTE"; break;
    case 1: typeName = "HIGH"; break;
    case 2: typeName = "LOW"; break;
    case 3: typeName = "HIGHLOW"; break;
    case 4: typeName = "HIGHADJ"; break;
    case 10: typeName = "DIR64"; break;
    }

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modName, safeMod, sizeof(safeMod));

    duint relocVa = modBase + reloc.rva;

    sprintf_s(responseBuf, responseBufSize,
        "{\"address\":\"0x%016llX\",\"found\":true,\"module\":\"%s\",\"module_base\":\"0x%016llX\","
        "\"relocation_address\":\"0x%016llX\",\"rva\":\"0x%016llX\",\"type\":\"%s\",\"type_raw\":%u,\"size\":%u}\n",
        (unsigned long long)addr, safeMod, (unsigned long long)modBase,
        (unsigned long long)relocVa, (unsigned long long)reloc.rva,
        typeName, (unsigned int)reloc.type, (unsigned int)reloc.size);
    responseText = responseBuf;
}

void handle_list_relocations(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_relocations: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->ModRelocationsInRange == nullptr)
    {
        responseText = "{\"error\":\"ModRelocationsInRange API not available\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing address parameter\"}\n";
        return;
    }

    duint addr = 0;
    if (!resolve_address(addrStr, &addr))
    {
        responseText = "{\"error\":\"invalid address format\"}\n";
        return;
    }

    int sizeInt = 0;
    if (!json_get_int(readBuf, "size", &sizeInt) || sizeInt <= 0)
    {
        responseText = "{\"error\":\"missing or invalid 'size' parameter (must be positive integer)\"}\n";
        return;
    }
    duint sizeVal = (duint)sizeInt;

    int offsetVal = 0;
    json_get_int(readBuf, "offset", &offsetVal);
    if (offsetVal < 0) offsetVal = 0;

    int limitVal = 100;
    json_get_int(readBuf, "limit", &limitVal);
    if (limitVal <= 0) limitVal = 100;
    if (limitVal > 500) limitVal = 500;

    BridgeList<DBGRELOCATIONINFO> relocList;
    bool ok = dbg->ModRelocationsInRange(addr, sizeVal, &relocList);

    int totalCount = relocList.Count();
    if (!ok || totalCount == 0)
    {
        relocList.Cleanup();
        sprintf_s(responseBuf, responseBufSize,
            "{\"address\":\"0x%016llX\",\"size\":%llu,\"total_count\":0,\"offset\":%d,\"limit\":%d,\"relocations\":[]}\n",
            (unsigned long long)addr, (unsigned long long)sizeVal, offsetVal, limitVal);
        responseText = responseBuf;
        return;
    }

    duint modBase = Script::Module::BaseFromAddr(addr);
    char modName[MAX_MODULE_SIZE] = { 0 };
    Script::Module::NameFromAddr(addr, modName);

    char safeMod[MAX_MODULE_SIZE * 2] = { 0 };
    escape_json_string(modName, safeMod, sizeof(safeMod));

    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;

    int bufOffset = sprintf_s(responseBuf, responseBufSize,
        "{\"address\":\"0x%016llX\",\"size\":%llu,\"module\":\"%s\",\"total_count\":%d,\"offset\":%d,\"limit\":%d,\"relocations\":[",
        (unsigned long long)addr, (unsigned long long)sizeVal, safeMod, totalCount, offsetVal, limitVal);

    for (int i = startIdx; i < endIdx && bufOffset < (int)responseBufSize - 1024; i++)
    {
        const char* typeName = "UNKNOWN";
        switch (relocList[i].type)
        {
        case 0: typeName = "ABSOLUTE"; break;
        case 1: typeName = "HIGH"; break;
        case 2: typeName = "LOW"; break;
        case 3: typeName = "HIGHLOW"; break;
        case 4: typeName = "HIGHADJ"; break;
        case 10: typeName = "DIR64"; break;
        }

        duint relocVa = modBase + relocList[i].rva;

        bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset,
            "%s{\"address\":\"0x%016llX\",\"rva\":\"0x%016llX\",\"type\":\"%s\",\"type_raw\":%u,\"size\":%u}",
            (i > startIdx ? "," : ""),
            (unsigned long long)relocVa,
            (unsigned long long)relocList[i].rva,
            typeName,
            (unsigned int)relocList[i].type,
            (unsigned int)relocList[i].size);
    }

    bufOffset += sprintf_s(responseBuf + bufOffset, responseBufSize - bufOffset, "]}\n");
    responseText = responseBuf;

    relocList.Cleanup();

    _plugin_logprintf("[x64dbg-MCP] list_relocations: addr=0x%llX, size=%llu, total=%d, slice %d..%d\n",
                      (unsigned long long)addr, (unsigned long long)sizeVal, totalCount, startIdx, endIdx);
}

