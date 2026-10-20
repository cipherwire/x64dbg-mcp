#include "xrefs.h"
#include "memory.h"

// Decodes an XREFTYPE enum value to a stable string
const char* decode_xref_type(XREFTYPE type)
{
    switch (type)
    {
    case XREF_NONE: return "XREF_NONE";
    case XREF_DATA: return "XREF_DATA";
    case XREF_JMP:  return "XREF_JMP";
    case XREF_CALL: return "XREF_CALL";
    default:        return "UNKNOWN";
    }
}

void handle_get_xrefs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_xrefs: no debuggee active.\n");
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
                size_t count = DbgGetXrefCountAt(va);
                XREFTYPE mainType = DbgGetXrefTypeAt(va);

                if (count == 0)
                {
                    // "No recorded XREFs for this address" - successful zero-reference state
                    sprintf_s(responseBuf, responseBufSize,
                        "{\"address\":\"0x%016llX\",\"count\":0,\"type\":\"%s\",\"type_raw\":%u,\"references\":[]}\n",
                        (unsigned long long)va,
                        decode_xref_type(mainType),
                        (unsigned int)mainType);
                    responseText = responseBuf;
                }
                else
                {
                    // Defensive upper bound to ensure formatted JSON fits inside responseBuf (65536)
                    const size_t maxAllowedXrefs = 800;
                    if (count > maxAllowedXrefs || (count * 75 + 256 >= responseBufSize))
                    {
                        sprintf_s(responseBuf, responseBufSize,
                            "{\"error\":\"xref list exceeds response buffer capacity\",\"count\":%zu,\"address\":\"0x%016llX\"}\n",
                            count, (unsigned long long)va);
                        responseText = responseBuf;
                    }
                    else
                    {
                        std::vector<XREF_RECORD> records;
                        bool queryOk = false;

                        // Bounded race-retry loop (up to 3 attempts)
                        for (int attempt = 0; attempt < 3; ++attempt)
                        {
                            if (count == 0)
                            {
                                queryOk = true;
                                break;
                            }

                            records.resize(count);
                            XREF_INFO info = { (duint)count, records.data() };

                            if (DbgXrefGet(va, &info))
                            {
                                queryOk = true;
                                break;
                            }

                            // Refresh count for next attempt
                            count = DbgGetXrefCountAt(va);
                            mainType = DbgGetXrefTypeAt(va);
                            if (count > maxAllowedXrefs)
                                break;
                        }

                        if (!queryOk)
                        {
                            sprintf_s(responseBuf, responseBufSize,
                                "{\"error\":\"xref query failed\",\"address\":\"0x%016llX\"}\n",
                                (unsigned long long)va);
                            responseText = responseBuf;
                        }
                        else if (count == 0)
                        {
                            sprintf_s(responseBuf, responseBufSize,
                                "{\"address\":\"0x%016llX\",\"count\":0,\"type\":\"%s\",\"type_raw\":%u,\"references\":[]}\n",
                                (unsigned long long)va,
                                decode_xref_type(mainType),
                                (unsigned int)mainType);
                            responseText = responseBuf;
                        }
                        else
                        {
                            // Serialize JSON safely into responseBuf
                            int written = sprintf_s(responseBuf, responseBufSize,
                                "{\"address\":\"0x%016llX\",\"count\":%zu,\"type\":\"%s\",\"type_raw\":%u,\"references\":[",
                                (unsigned long long)va,
                                count,
                                decode_xref_type(mainType),
                                (unsigned int)mainType);
                            (void)written;

                            for (size_t i = 0; i < count; ++i)
                            {
                                char entryBuf[128] = { 0 };
                                sprintf_s(entryBuf, sizeof(entryBuf),
                                    "%s{\"addr\":\"0x%016llX\",\"type\":\"%s\",\"type_raw\":%u}",
                                    (i > 0 ? "," : ""),
                                    (unsigned long long)records[i].addr,
                                    decode_xref_type(records[i].type),
                                    (unsigned int)records[i].type);
                                strcat_s(responseBuf, responseBufSize, entryBuf);
                            }

                            strcat_s(responseBuf, responseBufSize, "]}\n");
                            responseText = responseBuf;

                            _plugin_logprintf("[x64dbg-MCP] get_xrefs for 0x%016llX: returned %zu references (type=%s)\n",
                                              (unsigned long long)va, count, decode_xref_type(mainType));
                        }
                    }
                }
            }
        }
    }
}
