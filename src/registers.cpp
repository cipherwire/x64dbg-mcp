#include "registers.h"

void handle_get_registers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] get_registers: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] get_registers: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        REGDUMP_AVX512 regDump = { 0 };
        bool ok = DbgGetRegDumpEx(&regDump, sizeof(regDump));
        if (!ok)
        {
            _plugin_logprintf("[x64dbg-MCP] ERROR: DbgGetRegDumpEx returned false.\n");
            responseText = "{\"error\":\"DbgGetRegDumpEx failed\"}\n";
        }
        else
        {
#ifdef _WIN64
            _plugin_logprintf("[x64dbg-MCP] Registers read: RIP=0x%llX, RAX=0x%llX, RSP=0x%llX\n",
                              (unsigned long long)regDump.regcontext.cip,
                              (unsigned long long)regDump.regcontext.cax,
                              (unsigned long long)regDump.regcontext.csp);

            sprintf_s(responseBuf, responseBufSize,
                "{\"rax\":\"0x%016llX\",\"rbx\":\"0x%016llX\",\"rcx\":\"0x%016llX\","
                "\"rdx\":\"0x%016llX\",\"rsp\":\"0x%016llX\",\"rbp\":\"0x%016llX\","
                "\"rsi\":\"0x%016llX\",\"rdi\":\"0x%016llX\",\"rip\":\"0x%016llX\","
                "\"r8\":\"0x%016llX\",\"r9\":\"0x%016llX\",\"r10\":\"0x%016llX\","
                "\"r11\":\"0x%016llX\",\"r12\":\"0x%016llX\",\"r13\":\"0x%016llX\","
                "\"r14\":\"0x%016llX\",\"r15\":\"0x%016llX\",\"eflags\":\"0x%08X\"}\n",
                (unsigned long long)regDump.regcontext.cax,
                (unsigned long long)regDump.regcontext.cbx,
                (unsigned long long)regDump.regcontext.ccx,
                (unsigned long long)regDump.regcontext.cdx,
                (unsigned long long)regDump.regcontext.csp,
                (unsigned long long)regDump.regcontext.cbp,
                (unsigned long long)regDump.regcontext.csi,
                (unsigned long long)regDump.regcontext.cdi,
                (unsigned long long)regDump.regcontext.cip,
                (unsigned long long)regDump.regcontext.r8,
                (unsigned long long)regDump.regcontext.r9,
                (unsigned long long)regDump.regcontext.r10,
                (unsigned long long)regDump.regcontext.r11,
                (unsigned long long)regDump.regcontext.r12,
                (unsigned long long)regDump.regcontext.r13,
                (unsigned long long)regDump.regcontext.r14,
                (unsigned long long)regDump.regcontext.r15,
                (unsigned int)regDump.regcontext.eflags);
#else
            _plugin_logprintf("[x64dbg-MCP] Registers read: EIP=0x%08X, EAX=0x%08X, ESP=0x%08X\n",
                              (unsigned int)regDump.regcontext.cip,
                              (unsigned int)regDump.regcontext.cax,
                              (unsigned int)regDump.regcontext.csp);

            sprintf_s(responseBuf, responseBufSize,
                "{\"eax\":\"0x%08X\",\"ebx\":\"0x%08X\",\"ecx\":\"0x%08X\","
                "\"edx\":\"0x%08X\",\"esp\":\"0x%08X\",\"ebp\":\"0x%08X\","
                "\"esi\":\"0x%08X\",\"edi\":\"0x%08X\",\"eip\":\"0x%08X\","
                "\"eflags\":\"0x%08X\"}\n",
                (unsigned int)regDump.regcontext.cax,
                (unsigned int)regDump.regcontext.cbx,
                (unsigned int)regDump.regcontext.ccx,
                (unsigned int)regDump.regcontext.cdx,
                (unsigned int)regDump.regcontext.csp,
                (unsigned int)regDump.regcontext.cbp,
                (unsigned int)regDump.regcontext.csi,
                (unsigned int)regDump.regcontext.cdi,
                (unsigned int)regDump.regcontext.cip,
                (unsigned int)regDump.regcontext.eflags);
#endif
            responseText = responseBuf;
        }
    }
}

void handle_set_register(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] set_register: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] set_register: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        char regStr[64] = { 0 };
        if (!json_get_string(readBuf, "register", regStr, sizeof(regStr)) || regStr[0] == '\0')
        {
            responseText = "{\"error\":\"missing register parameter\"}\n";
        }
        else
        {
            // Normalize register name to lowercase
            std::string regLower = regStr;
            std::transform(regLower.begin(), regLower.end(), regLower.begin(), [](unsigned char c) { return (char)tolower(c); });

            // Validate register name against supported registers
#ifdef _WIN64
            static const char* const validRegs[] = {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
                "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
                "eflags"
            };
#else
            static const char* const validRegs[] = {
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
                "eflags"
            };
#endif

            bool isValid = false;
            for (const auto& vr : validRegs)
            {
                if (regLower == vr)
                {
                    isValid = true;
                    break;
                }
            }

            if (!isValid)
            {
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"unknown or unsupported register\",\"register\":\"%s\"}\n",
                          regStr);
                responseText = responseBuf;
            }
            else
            {
                // Parse value parameter (can be string or int)
                char valStr[128] = { 0 };
                bool hasVal = json_get_string(readBuf, "value", valStr, sizeof(valStr)) && valStr[0] != '\0';
                duint targetVal = 0;
                bool parseOk = false;

                if (hasVal)
                {
                    parseOk = Script::Misc::ParseExpression(valStr, &targetVal);
                }
                else
                {
                    int intVal = 0;
                    if (json_get_int(readBuf, "value", &intVal))
                    {
                        targetVal = (duint)intVal;
                        parseOk = true;
                    }
                }

                if (!parseOk)
                {
                    responseText = "{\"error\":\"invalid or missing value parameter\"}\n";
                }
                else
                {
                    // Read previous value
                    duint prevVal = DbgValFromString(regLower.c_str());

                    // Execute register assignment
                    char setCmd[128] = { 0 };
                    sprintf_s(setCmd, sizeof(setCmd), "mov %s, 0x%llX", regLower.c_str(), (unsigned long long)targetVal);
                    bool ok = DbgCmdExecDirect(setCmd);
                    if (!ok)
                    {
                        ok = DbgValSetScalar(regLower.c_str(), targetVal);
                    }

                    duint newVal = DbgValFromString(regLower.c_str());

                    sprintf_s(responseBuf, responseBufSize,
                        "{\"register\":\"%s\",\"previous_value\":\"0x%016llX\",\"value\":\"0x%016llX\"}\n",
                        regLower.c_str(),
                        (unsigned long long)prevVal,
                        (unsigned long long)newVal);
                    responseText = responseBuf;

                    _plugin_logprintf("[x64dbg-MCP] set_register %s: 0x%llX -> 0x%llX (ok=%d)\n",
                                      regLower.c_str(), (unsigned long long)prevVal, (unsigned long long)newVal, ok ? 1 : 0);
                }
            }
        }
    }
}

void handle_test_raw_regdump(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    // Experimental check of raw DbgGetRegDumpEx return behavior without state guard
    REGDUMP_AVX512 rawDump = { 0 };
    bool rawOk = DbgGetRegDumpEx(&rawDump, sizeof(rawDump));
#ifdef _WIN64
    sprintf_s(responseBuf, responseBufSize,
              "{\"raw_return\":%s,\"rip\":\"0x%016llX\"}\n",
              rawOk ? "true" : "false",
              (unsigned long long)rawDump.regcontext.cip);
#else
    sprintf_s(responseBuf, responseBufSize,
              "{\"raw_return\":%s,\"eip\":\"0x%08X\"}\n",
              rawOk ? "true" : "false",
              (unsigned int)rawDump.regcontext.cip);
#endif
    responseText = responseBuf;
}

