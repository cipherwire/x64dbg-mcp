#include "assembler.h"
#include <_scriptapi_assembler.h>

void handle_assemble(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char instrStr[512] = { 0 };
    if (!json_get_string(readBuf, "instruction", instrStr, sizeof(instrStr)) || instrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing instruction parameter\"}\n";
        return;
    }

    char addrStr[64] = { 0 };
    duint va = 0;
    if (json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0')
    {
        if (!resolve_address(addrStr, &va))
        {
            responseText = "{\"error\":\"invalid address format\"}\n";
            return;
        }
    }
    else
    {
        // Default to RIP if debugging, or 0
        if (DbgIsDebugging())
        {
            resolve_address("rip", &va);
        }
    }

    bool writeToMem = false;
    bool parsedWrite = false;
    if (json_get_bool(readBuf, "write_to_memory", &parsedWrite))
    {
        writeToMem = parsedWrite;
    }

    if (writeToMem)
    {
        bool isDebugging = DbgIsDebugging();
        bool isRunning = isDebugging ? DbgIsRunning() : false;
        if (!isDebugging)
        {
            responseText = "{\"error\":\"no debuggee active for memory write\"}\n";
            return;
        }
        if (isRunning)
        {
            responseText = "{\"error\":\"debuggee is running, pause before writing memory\"}\n";
            return;
        }

        int size = 0;
        char err[512] = { 0 };
        bool ok = Script::Assembler::AssembleMemEx(va, instrStr, &size, err, false);
        if (!ok || size <= 0)
        {
            char escapedErr[1024] = { 0 };
            escape_json_string(err[0] != '\0' ? err : "assembly failed", escapedErr, sizeof(escapedErr));
            sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", escapedErr);
            responseText = responseBuf;
            return;
        }

        // Read back bytes from memory
        unsigned char readback[32] = { 0 };
        duint readLen = (size > 32) ? 32 : (duint)size;
        DbgMemRead(va, readback, readLen);

        char hexStr[128] = { 0 };
        static const char hexChars[] = "0123456789abcdef";
        for (int i = 0; i < size && i < 32; i++)
        {
            hexStr[i * 2] = hexChars[(readback[i] >> 4) & 0x0F];
            hexStr[i * 2 + 1] = hexChars[readback[i] & 0x0F];
        }

        char escapedInstr[1024] = { 0 };
        escape_json_string(instrStr, escapedInstr, sizeof(escapedInstr));

        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"instruction\":\"%s\",\"hex\":\"%s\",\"size\":%d,\"written\":true}\n",
                  (unsigned long long)va, escapedInstr, hexStr, size);
        responseText = responseBuf;
    }
    else
    {
        unsigned char dest[32] = { 0 };
        int size = 0;
        char err[512] = { 0 };
        bool ok = Script::Assembler::AssembleEx(va, dest, &size, instrStr, err);
        if (!ok || size <= 0)
        {
            char escapedErr[1024] = { 0 };
            escape_json_string(err[0] != '\0' ? err : "assembly failed", escapedErr, sizeof(escapedErr));
            sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", escapedErr);
            responseText = responseBuf;
            return;
        }

        char hexStr[128] = { 0 };
        static const char hexChars[] = "0123456789abcdef";
        for (int i = 0; i < size && i < 32; i++)
        {
            hexStr[i * 2] = hexChars[(dest[i] >> 4) & 0x0F];
            hexStr[i * 2 + 1] = hexChars[dest[i] & 0x0F];
        }

        char escapedInstr[1024] = { 0 };
        escape_json_string(instrStr, escapedInstr, sizeof(escapedInstr));

        sprintf_s(responseBuf, responseBufSize,
                  "{\"address\":\"0x%016llX\",\"instruction\":\"%s\",\"hex\":\"%s\",\"size\":%d,\"written\":false}\n",
                  (unsigned long long)va, escapedInstr, hexStr, size);
        responseText = responseBuf;
    }
}
