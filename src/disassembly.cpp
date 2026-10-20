#include "disassembly.h"

void handle_disassemble(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    if (!isDebugging)
    {
        _plugin_logprintf("[x64dbg-MCP] disassemble: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else if (isRunning)
    {
        _plugin_logprintf("[x64dbg-MCP] disassemble: debuggee is currently running.\n");
        responseText = "{\"error\":\"debuggee is running\"}\n";
    }
    else
    {
        char addrStr[64] = { 0 };
        json_get_string(readBuf, "address", addrStr, sizeof(addrStr));

        duint va = 0;
        if (!resolve_address(addrStr, &va))
        {
            responseText = "{\"error\":\"invalid address format\"}\n";
        }
        else
        {
            int count = 10;
            json_get_int(readBuf, "count", &count);

            if (count <= 0 || count > 64)
            {
                responseText = "{\"error\":\"invalid count: must be between 1 and 64\"}\n";
            }
            else
            {
                duint curAddr = va;
                int offset = sprintf_s(responseBuf, responseBufSize,
                    "{\"address\":\"0x%016llX\",\"instructions\":[", (unsigned long long)va);

                int decodedCount = 0;
                static const char hexChars[] = "0123456789abcdef";

                for (int i = 0; i < count; i++)
                {
                    DISASM_INSTR instr = { 0 };
                    DbgDisasmAt(curAddr, &instr);

                    if (instr.instr_size <= 0 || instr.instr_size > 15)
                    {
                        break;
                    }

                    unsigned char bytes[16] = { 0 };
                    bool memOk = DbgMemRead(curAddr, bytes, (duint)instr.instr_size);
                    if (!memOk)
                    {
                        break;
                    }

                    char hexStr[33] = { 0 };
                    for (int b = 0; b < instr.instr_size; b++)
                    {
                        hexStr[b * 2] = hexChars[(bytes[b] >> 4) & 0x0F];
                        hexStr[b * 2 + 1] = hexChars[bytes[b] & 0x0F];
                    }

                    const char* typeStr = "normal";
                    if (instr.type == instr_branch) typeStr = "branch";
                    else if (instr.type == instr_stack) typeStr = "stack";

                    char safeInstr[128] = { 0 };
                    int dstIdx = 0;
                    for (int s = 0; instr.instruction[s] != '\0' && dstIdx < sizeof(safeInstr) - 2; s++)
                    {
                        if (instr.instruction[s] == '\"' || instr.instruction[s] == '\\')
                        {
                            safeInstr[dstIdx++] = '\\';
                        }
                        safeInstr[dstIdx++] = instr.instruction[s];
                    }

                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                        "%s{\"address\":\"0x%016llX\",\"size\":%d,\"bytes\":\"%s\",\"instruction\":\"%s\",\"type\":\"%s\"}",
                        (decodedCount > 0 ? "," : ""),
                        (unsigned long long)curAddr,
                        instr.instr_size,
                        hexStr,
                        safeInstr,
                        typeStr);

                    curAddr += instr.instr_size;
                    decodedCount++;
                }

                if (decodedCount == 0)
                {
                    sprintf_s(responseBuf, responseBufSize,
                              "{\"error\":\"disassembly failed at address 0x%016llX\"}\n",
                              (unsigned long long)va);
                    responseText = responseBuf;
                }
                else
                {
                    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
                    responseText = responseBuf;

                    _plugin_logprintf("[x64dbg-MCP] Disassembly success: 0x%016llX (%d instructions)\n",
                                      (unsigned long long)va, decodedCount);
                }
            }
        }
    }
}

void handle_test_raw_disasm(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    // Experimental check of raw DbgDisasmAt on unmapped address
    DISASM_INSTR rawInstr = { 0 };
    DbgDisasmAt(0x0, &rawInstr);
    sprintf_s(responseBuf, responseBufSize,
              "{\"raw_size\":%d,\"instruction\":\"%s\"}\n",
              rawInstr.instr_size, rawInstr.instruction);
    responseText = responseBuf;
}
