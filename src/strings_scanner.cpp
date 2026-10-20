#include "strings_scanner.h"
#include <vector>
#include <string>
#include <algorithm>

struct FoundString
{
    duint address;
    size_t length;
    const char* encoding;
    std::string text;
};

static inline bool is_printable_ascii(unsigned char c)
{
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\r' || c == '\n';
}

void handle_find_strings(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    char startStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "start_address", startStr, sizeof(startStr)) || startStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'start_address' parameter\"}\n";
        return;
    }

    duint startAddr = DbgValFromString(startStr);
    if (startAddr == 0)
    {
        responseText = "{\"error\":\"invalid start_address expression\"}\n";
        return;
    }

    duint scanSize = 0;
    char endStr[MAX_PATH] = { 0 };
    int sizeInt = 0;

    if (json_get_string(readBuf, "end_address", endStr, sizeof(endStr)) && endStr[0] != '\0')
    {
        duint endAddr = DbgValFromString(endStr);
        if (endAddr <= startAddr)
        {
            responseText = "{\"error\":\"end_address must be greater than start_address\"}\n";
            return;
        }
        scanSize = endAddr - startAddr;
    }
    else if (json_get_int(readBuf, "size", &sizeInt) && sizeInt > 0)
    {
        scanSize = (duint)sizeInt;
    }
    else
    {
        char sizeStr[64] = { 0 };
        if (json_get_string(readBuf, "size", sizeStr, sizeof(sizeStr)) && sizeStr[0] != '\0')
        {
            scanSize = DbgValFromString(sizeStr);
        }
    }

    if (scanSize == 0)
    {
        responseText = "{\"error\":\"must provide positive 'size' or valid 'end_address'\"}\n";
        return;
    }

    if (startAddr + scanSize < startAddr)
    {
        responseText = "{\"error\":\"address range integer overflow\"}\n";
        return;
    }

    constexpr duint kMaxScanSpan = 32 * 1024 * 1024; // 32MB max scan span
    if (scanSize > kMaxScanSpan)
    {
        responseText = "{\"error\":\"requested scan span exceeds maximum limit of 32MB\"}\n";
        return;
    }

    char encStr[32] = "all";
    json_get_string(readBuf, "encoding", encStr, sizeof(encStr));
    bool doAscii = (_stricmp(encStr, "ascii") == 0 || _stricmp(encStr, "all") == 0);
    bool doUtf16 = (_stricmp(encStr, "utf16") == 0 || _stricmp(encStr, "all") == 0);

    if (!doAscii && !doUtf16)
    {
        responseText = "{\"error\":\"invalid encoding: must be 'ascii', 'utf16', or 'all'\"}\n";
        return;
    }

    int minLen = 4;
    json_get_int(readBuf, "min_length", &minLen);
    if (minLen < 2) minLen = 2;
    if (minLen > 256) minLen = 256;

    int maxLimit = 100;
    json_get_int(readBuf, "limit", &maxLimit);
    if (maxLimit <= 0) maxLimit = 100;
    if (maxLimit > 1000) maxLimit = 1000;

    constexpr size_t kChunkSize = 65536; // 64 KB
    constexpr size_t kMaxStrLen = 256;

    std::vector<FoundString> results;
    results.reserve((size_t)maxLimit);

    std::vector<unsigned char> chunk(kChunkSize + kMaxStrLen * 2);

    duint offset = 0;
    while (offset < scanSize && results.size() < (size_t)maxLimit)
    {
        duint remaining = scanSize - offset;
        size_t toRead = (remaining < kChunkSize) ? (size_t)remaining : kChunkSize;

        // If not at the very end, read an overlap so strings crossing chunk boundary are captured
        size_t overlap = 0;
        if (remaining > toRead)
        {
            overlap = (remaining - toRead < kMaxStrLen * 2) ? (size_t)(remaining - toRead) : (kMaxStrLen * 2);
        }

        duint chunkVa = startAddr + offset;
        size_t readWithOverlap = toRead + overlap;

        if (!DbgMemRead(chunkVa, chunk.data(), readWithOverlap))
        {
            // If reading with overlap failed, try reading just toRead
            if (!DbgMemRead(chunkVa, chunk.data(), toRead))
            {
                // Advance by page (4096) to skip unmapped hole
                offset += 4096;
                continue;
            }
            readWithOverlap = toRead;
        }

        // 1. Scan ASCII
        if (doAscii)
        {
            size_t runStart = 0;
            size_t runLen = 0;
            for (size_t i = 0; i <= readWithOverlap; i++)
            {
                unsigned char c = (i < readWithOverlap) ? chunk[i] : 0;
                if (is_printable_ascii(c))
                {
                    if (runLen == 0)
                    {
                        runStart = i;
                    }
                    runLen++;
                    if (runLen > kMaxStrLen)
                    {
                        duint strVa = chunkVa + runStart;
                        if (strVa >= startAddr + offset && strVa < startAddr + offset + toRead)
                        {
                            std::string s((const char*)&chunk[runStart], runLen);
                            results.push_back({ strVa, runLen, "ascii", s });
                            if (results.size() >= (size_t)maxLimit) break;
                        }
                        runLen = 0;
                    }
                }
                else
                {
                    if (runLen >= (size_t)minLen)
                    {
                        duint strVa = chunkVa + runStart;
                        if (strVa >= startAddr + offset && strVa < startAddr + offset + toRead)
                        {
                            std::string s((const char*)&chunk[runStart], runLen);
                            results.push_back({ strVa, runLen, "ascii", s });
                            if (results.size() >= (size_t)maxLimit) break;
                        }
                    }
                    runLen = 0;
                }
            }
        }

        // 2. Scan UTF-16LE
        if (doUtf16 && results.size() < (size_t)maxLimit)
        {
            // Check even alignment
            for (size_t align = 0; align < 2; align++)
            {
                if (align >= readWithOverlap) break;
                size_t runStart = 0;
                size_t runLen = 0;

                for (size_t i = align; i + 1 < readWithOverlap; i += 2)
                {
                    unsigned char lo = chunk[i];
                    unsigned char hi = chunk[i + 1];

                    if (hi == 0 && is_printable_ascii(lo))
                    {
                        if (runLen == 0)
                        {
                            runStart = i;
                        }
                        runLen++;
                        if (runLen > kMaxStrLen)
                        {
                            duint strVa = chunkVa + runStart;
                            if (strVa >= startAddr + offset && strVa < startAddr + offset + toRead)
                            {
                                std::string s;
                                s.reserve(runLen);
                                for (size_t k = 0; k < runLen; k++)
                                {
                                    s.push_back((char)chunk[runStart + k * 2]);
                                }
                                results.push_back({ strVa, runLen, "utf16", s });
                                if (results.size() >= (size_t)maxLimit) break;
                            }
                            runLen = 0;
                        }
                    }
                    else
                    {
                        if (runLen >= (size_t)minLen)
                        {
                            duint strVa = chunkVa + runStart;
                            if (strVa >= startAddr + offset && strVa < startAddr + offset + toRead)
                            {
                                std::string s;
                                s.reserve(runLen);
                                for (size_t k = 0; k < runLen; k++)
                                {
                                    s.push_back((char)chunk[runStart + k * 2]);
                                }
                                results.push_back({ strVa, runLen, "utf16", s });
                                if (results.size() >= (size_t)maxLimit) break;
                            }
                        }
                        runLen = 0;
                    }
                }

                if (runLen >= (size_t)minLen && results.size() < (size_t)maxLimit)
                {
                    duint strVa = chunkVa + runStart;
                    if (strVa >= startAddr + offset && strVa < startAddr + offset + toRead)
                    {
                        std::string s;
                        s.reserve(runLen);
                        for (size_t k = 0; k < runLen; k++)
                        {
                            s.push_back((char)chunk[runStart + k * 2]);
                        }
                        results.push_back({ strVa, runLen, "utf16", s });
                    }
                }
                if (results.size() >= (size_t)maxLimit) break;
            }
        }

        offset += toRead;
    }

    // Sort results by address
    std::sort(results.begin(), results.end(), [](const FoundString& a, const FoundString& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.length > b.length;
    });

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"start_address\":\"0x%016llX\",\"size\":%llu,\"encoding\":\"%s\","
                        "\"min_length\":%d,\"total_found\":%d,\"strings\":[",
                        (unsigned long long)startAddr,
                        (unsigned long long)scanSize,
                        encStr,
                        minLen,
                        (int)results.size());

    for (size_t i = 0; i < results.size(); i++)
    {
        char escaped[1024] = { 0 };
        escape_json_string(results[i].text.c_str(), escaped, sizeof(escaped));

        char itemBuf[1280] = { 0 };
        int itemLen = sprintf_s(itemBuf, sizeof(itemBuf),
                                "%s{\"address\":\"0x%016llX\",\"length\":%llu,\"encoding\":\"%s\",\"string\":\"%s\"}",
                                (i > 0) ? "," : "",
                                (unsigned long long)results[i].address,
                                (unsigned long long)results[i].length,
                                results[i].encoding,
                                escaped);

        if ((size_t)pos + itemLen + 32 >= responseBufSize)
        {
            break;
        }
        memcpy(responseBuf + pos, itemBuf, itemLen);
        pos += itemLen;
    }

    responseBuf[pos++] = ']';
    responseBuf[pos++] = '}';
    responseBuf[pos++] = '\n';
    responseBuf[pos] = '\0';
    responseText = responseBuf;
}
