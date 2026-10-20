#include "patterns.h"

static inline bool isHexChar(char ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}

static inline std::string formathexpattern(const std::string & patterntext)
{
    std::string result;
    int len = (int)patterntext.length();
    for (int i = 0; i < len; i++)
    {
        if (patterntext[i] == '?' || isHexChar(patterntext[i]))
            result += patterntext[i];
    }
    return result;
}

static inline int hexchtoint(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

bool patterntransform(const std::string & patterntext, std::vector<PatternByte> & pattern)
{
    pattern.clear();

    // reject patterns with unsupported characters (whitespace allowed)
    for (char ch : patterntext)
    {
        if (ch != '?' && ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n' && !isHexChar(ch))
            return false;
    }

    std::string formattext = formathexpattern(patterntext);
    int len = (int)formattext.length();
    if (len == 0)
        return false;

    if (len % 2 != 0) // odd nibble normalization per patternfind.cpp
    {
        formattext += '?';
        len++;
    }

    PatternByte newByte = { 0, 0 };
    for (int i = 0, j = 0; i < len; i++)
    {
        int shift = j ? 0 : 4;

        if (formattext[i] != '?')
        {
            newByte.data |= (unsigned char)((hexchtoint(formattext[i]) & 0xF) << shift);
            newByte.mask |= (unsigned char)(0xF << shift);
        }

        j++;
        if (j == 2) // two nibbles = one byte
        {
            j = 0;
            pattern.push_back(newByte);
            newByte = { 0, 0 };
        }
    }

    // reject wildcard-only patterns
    bool allWildcard = std::all_of(pattern.begin(), pattern.end(), [](const PatternByte & b)
    {
        return b.mask == 0x00;
    });
    if (allWildcard)
        return false;

    return true;
}

struct PatternNeedle
{
    unsigned char data;
    unsigned char mask;
    size_t offset;
};

size_t patternfind_vec(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern)
{
    size_t searchpatternsize = pattern.size();

    if (datasize < searchpatternsize)
        return (size_t)-1;

    std::unique_ptr<PatternNeedle[]> needles(new PatternNeedle[searchpatternsize]);
    size_t n_needles = 0;

    // Collect all of the literal bytes back-to-front
    for (size_t i = searchpatternsize; i--;)
    {
        if (pattern[i].mask == 0xFF)
            needles[n_needles++] = { pattern[i].data, pattern[i].mask, i };
    }

    size_t literals = n_needles;

    // Collect partially masked bytes
    for (size_t i = searchpatternsize; i--;)
    {
        if (pattern[i].mask != 0x00 && pattern[i].mask != 0xFF)
            needles[n_needles++] = { pattern[i].data, pattern[i].mask, i };
    }

    if (n_needles == 0)
        return (size_t)-1;

    const unsigned char* here = data;
    const unsigned char* end = &data[datasize - (searchpatternsize - 1)];

    do
    {
        if (literals)
        {
            PatternNeedle needle = needles[0];

            here = std::find(here + needle.offset, end + needle.offset, needle.data) - needle.offset;
            if (here == end)
                break;

            for (size_t i = 1; i < literals; ++i)
            {
                needle = needles[i];

                if (here[needle.offset] != needle.data)
                {
                    needles[i] = needles[i - 1];
                    needles[i - 1] = needle;
                    goto skip;
                }
            }
        }

        for (size_t i = literals; i < n_needles; ++i)
        {
            PatternNeedle needle = needles[i];

            if ((here[needle.offset] & needle.mask) != needle.data)
                goto skip;
        }

        return here - data;

skip:
        ++here;
    }
    while (here != end);

    return (size_t)-1;
}

void handle_find_pattern(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] find_pattern: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
    }
    else
    {
        char patternStr[512] = { 0 };
        if (!json_get_string(readBuf, "pattern", patternStr, sizeof(patternStr)) || patternStr[0] == '\0')
        {
            responseText = "{\"error\":\"missing or empty pattern parameter\"}\n";
        }
        else
        {
            std::vector<PatternByte> patternBytes;
            if (!patterntransform(patternStr, patternBytes) || patternBytes.empty())
            {
                responseText = "{\"error\":\"malformed pattern: must contain valid hex bytes or wildcards (?/??) and at least one non-wildcard byte\"}\n";
            }
            else
            {
                size_t patternLen = patternBytes.size();

                // Parse optional start_address
                char addrStr[64] = { 0 };
                duint startAddr = 0;
                bool hasStartAddr = json_get_string(readBuf, "start_address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0';
                if (hasStartAddr)
                {
                    if (!resolve_address(addrStr, &startAddr))
                    {
                        responseText = "{\"error\":\"invalid start_address format\"}\n";
                    }
                }
                else
                {
                    // Default start_address to main module base
                    startAddr = Script::Module::GetMainModuleBase();
                    if (startAddr == 0)
                    {
                        startAddr = Script::Module::GetMainModuleEntry();
                    }
                }

                if (responseText == nullptr)
                {
                    // Parse optional size
                    int requestedSize = 0;
                    bool hasSize = json_get_int(readBuf, "size", &requestedSize);
                    duint searchSpan = 0;

                    if (hasSize)
                    {
                        if (requestedSize <= 0 || requestedSize > 67108864) // 64 MB max span
                        {
                            responseText = "{\"error\":\"invalid size: must be between 1 and 67108864 bytes (64 MB)\"}\n";
                        }
                        else
                        {
                            searchSpan = (duint)requestedSize;
                        }
                    }
                    else
                    {
                        // Default size to containing module or region
                        duint modBase = Script::Module::BaseFromAddr(startAddr);
                        if (modBase != 0)
                        {
                            duint modSize = Script::Module::SizeFromAddr(startAddr);
                            if (startAddr >= modBase && startAddr < modBase + modSize)
                            {
                                searchSpan = (modBase + modSize) - startAddr;
                            }
                            else
                            {
                                searchSpan = modSize;
                            }
                        }
                        else
                        {
                            HANDLE hProc = DbgGetProcessHandle();
                            MEMORY_BASIC_INFORMATION mbi = { 0 };
                            if (hProc != nullptr && VirtualQueryEx(hProc, (LPCVOID)startAddr, &mbi, sizeof(mbi)) > 0)
                            {
                                duint regEnd = (duint)mbi.BaseAddress + mbi.RegionSize;
                                searchSpan = (startAddr < regEnd) ? (regEnd - startAddr) : mbi.RegionSize;
                            }
                            else
                            {
                                searchSpan = 65536;
                            }
                        }
                        if (searchSpan > 67108864) searchSpan = 67108864;
                    }

                    if (responseText == nullptr)
                    {
                        int maxMatches = 20;
                        if (json_get_int(readBuf, "max_matches", &maxMatches))
                        {
                            if (maxMatches < 1 || maxMatches > 100)
                            {
                                responseText = "{\"error\":\"invalid max_matches: must be between 1 and 100\"}\n";
                            }
                        }

                        HANDLE hProcess = DbgGetProcessHandle();
                        if (hProcess == nullptr || hProcess == INVALID_HANDLE_VALUE)
                        {
                            responseText = "{\"error\":\"invalid process handle\"}\n";
                        }
                        else
                        {
                            duint searchStart = startAddr;
                            duint searchEnd = searchStart + searchSpan;
                            if (searchEnd < searchStart) searchEnd = (duint)-1;

                            std::vector<duint> matches;
                            matches.reserve((size_t)maxMatches);
                            unsigned long long scannedBytes = 0;

                            const size_t SCAN_CHUNK_SIZE = 256 * 1024;
                            static unsigned char chunkBuf[SCAN_CHUNK_SIZE];

                            duint currentAddr = searchStart;
                            while (currentAddr < searchEnd && (int)matches.size() < maxMatches)
                            {
                                MEMORY_BASIC_INFORMATION mbi = { 0 };
                                SIZE_T q = VirtualQueryEx(hProcess, (LPCVOID)currentAddr, &mbi, sizeof(mbi));
                                if (q == 0)
                                {
                                    break;
                                }

                                duint regionBase = (duint)mbi.BaseAddress;
                                duint regionEnd = regionBase + mbi.RegionSize;
                                if (regionEnd <= currentAddr)
                                {
                                    currentAddr += 4096;
                                    continue;
                                }

                                duint subStart = (currentAddr > regionBase) ? currentAddr : regionBase;
                                duint subEnd = (searchEnd < regionEnd) ? searchEnd : regionEnd;

                                bool isCommitted = (mbi.State == MEM_COMMIT);
                                bool isGuard = (mbi.Protect & PAGE_GUARD) != 0;
                                bool isNoAccess = (mbi.Protect & PAGE_NOACCESS) != 0;
                                bool hasRead = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                               PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                                if (isCommitted && !isGuard && !isNoAccess && hasRead && subStart < subEnd)
                                {
                                    duint chunkStart = subStart;
                                    while (chunkStart < subEnd && (int)matches.size() < maxMatches)
                                    {
                                        duint chunkEnd = chunkStart + SCAN_CHUNK_SIZE;
                                        if (chunkEnd > subEnd) chunkEnd = subEnd;
                                        duint chunkSize = chunkEnd - chunkStart;

                                        if (chunkSize < patternLen)
                                        {
                                            scannedBytes += chunkSize;
                                            break;
                                        }

                                        bool chunkReadOk = DbgMemRead(chunkStart, chunkBuf, chunkSize);
                                        if (!chunkReadOk)
                                        {
                                            break;
                                        }

                                        scannedBytes += chunkSize;

                                        size_t curPos = 0;
                                        while (curPos + patternLen <= chunkSize && (int)matches.size() < maxMatches)
                                        {
                                            size_t found = patternfind_vec(chunkBuf + curPos, chunkSize - curPos, patternBytes);
                                            if (found == (size_t)-1)
                                            {
                                                break;
                                            }

                                            duint matchVa = chunkStart + curPos + found;
                                            if (matches.empty() || matchVa > matches.back())
                                            {
                                                matches.push_back(matchVa);
                                            }
                                            curPos += found + 1;
                                        }

                                        if (chunkEnd == subEnd)
                                        {
                                            break;
                                        }

                                        chunkStart = chunkEnd - (patternLen - 1);
                                    }
                                }

                                currentAddr = regionEnd;
                            }

                            bool truncated = ((int)matches.size() >= maxMatches);
                            bool isRunning = DbgIsRunning();

                            char safePattern[1024] = { 0 };
                            escape_json_string(patternStr, safePattern, sizeof(safePattern));

                            int offset = sprintf_s(responseBuf, responseBufSize,
                                "{\"pattern\":\"%s\","
                                "\"start_address\":\"0x%016llX\","
                                "\"size\":%llu,"
                                "\"scanned_bytes\":%llu,"
                                "\"match_count\":%d,"
                                "\"truncated\":%s,"
                                "\"is_running\":%s,"
                                "\"matches\":[",
                                safePattern,
                                (unsigned long long)startAddr,
                                (unsigned long long)searchSpan,
                                scannedBytes,
                                (int)matches.size(),
                                truncated ? "true" : "false",
                                isRunning ? "true" : "false");

                            for (size_t i = 0; i < matches.size() && offset < (int)responseBufSize - 512; i++)
                            {
                                offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                                                    "%s\"0x%016llX\"",
                                                    (i > 0 ? "," : ""),
                                                    (unsigned long long)matches[i]);
                            }

                            offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "]}\n");
                            responseText = responseBuf;

                            _plugin_logprintf("[x64dbg-MCP] find_pattern '%s' in [0x%llX, +0x%llX): %d matches, %llu scanned bytes (isRunning=%s).\n",
                                              safePattern, (unsigned long long)startAddr, (unsigned long long)searchSpan,
                                              (int)matches.size(), scannedBytes, isRunning ? "true" : "false");
                        }
                    }
                }
            }
        }
    }
}
