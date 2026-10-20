#include "type_system.h"
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>

static bool stristr_local(const char* haystack, const char* needle)
{
    if (!haystack || !needle) return false;
    if (!*needle) return true;

    for (; *haystack; ++haystack)
    {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n)))
        {
            ++h;
            ++n;
        }
        if (!*n) return true;
    }
    return false;
}

static void StructEnumCb(const char* str, void* userdata)
{
    if (str != nullptr && str[0] != '\0')
    {
        auto* vec = static_cast<std::vector<std::string>*>(userdata);
        vec->push_back(std::string(str));
    }
}

void handle_list_structs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumStructs == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"EnumStructs API not available\"}}\n";
        return;
    }

    int offsetVal = 0;
    int limitVal = 100;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Offset must be non-negative\"}}\n";
        return;
    }
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Limit must be positive\"}}\n";
        return;
    }
    if (limitVal > 500) limitVal = 500;

    char filterStr[128] = { 0 };
    bool hasFilter = json_get_string(readBuf, "filter", filterStr, sizeof(filterStr)) && filterStr[0] != '\0';

    std::vector<std::string> allStructs;
    dbg->EnumStructs(StructEnumCb, &allStructs);

    std::sort(allStructs.begin(), allStructs.end());

    std::vector<std::string> matched;
    matched.reserve(allStructs.size());
    for (const auto& s : allStructs)
    {
        if (hasFilter && !stristr_local(s.c_str(), filterStr))
            continue;
        matched.push_back(s);
    }

    int totalCount = (int)matched.size();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;
    int returnCount = endIdx - startIdx;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"total\":%d,\"structs\":[",
                           returnCount, totalCount);

    for (int i = startIdx; i < endIdx && offset < (int)responseBufSize - 512; i++)
    {
        char safeName[512] = { 0 };
        escape_json_string(matched[i].c_str(), safeName, sizeof(safeName));
        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s\"%s\"",
                            (i > startIdx ? "," : ""),
                            safeName);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_list_constants(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumConstants == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"EnumConstants API not available\"}}\n";
        return;
    }

    int offsetVal = 0;
    int limitVal = 100;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Offset must be non-negative\"}}\n";
        return;
    }
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Limit must be positive\"}}\n";
        return;
    }
    if (limitVal > 500) limitVal = 500;

    char filterStr[128] = { 0 };
    bool hasFilter = json_get_string(readBuf, "filter", filterStr, sizeof(filterStr)) && filterStr[0] != '\0';

    BridgeList<CONSTANTINFO> constList;
    dbg->EnumConstants(&constList);

    int totalInList = constList.Count();
    std::vector<int> matchedIndices;
    matchedIndices.reserve(totalInList);

    for (int i = 0; i < totalInList; i++)
    {
        const char* name = constList[i].name ? constList[i].name : "";
        if (hasFilter)
        {
            char valHex[32];
            sprintf_s(valHex, sizeof(valHex), "0x%08X", (unsigned int)constList[i].value);
            if (!stristr_local(name, filterStr) && !stristr_local(valHex, filterStr))
                continue;
        }
        matchedIndices.push_back(i);
    }

    int totalCount = (int)matchedIndices.size();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;
    int returnCount = endIdx - startIdx;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"total\":%d,\"constants\":[",
                           returnCount, totalCount);

    for (int i = startIdx; i < endIdx && offset < (int)responseBufSize - 512; i++)
    {
        int idx = matchedIndices[i];
        const char* name = constList[idx].name ? constList[idx].name : "";
        char safeName[256] = { 0 };
        escape_json_string(name, safeName, sizeof(safeName));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s{\"name\":\"%s\",\"value\":\"0x%08llX\",\"value_dec\":%llu}",
                            (i > startIdx ? "," : ""),
                            safeName,
                            (unsigned long long)constList[idx].value,
                            (unsigned long long)constList[idx].value);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_list_error_codes(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->EnumErrorCodes == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"EnumErrorCodes API not available\"}}\n";
        return;
    }

    int offsetVal = 0;
    int limitVal = 100;
    if (json_get_int(readBuf, "offset", &offsetVal) && offsetVal < 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Offset must be non-negative\"}}\n";
        return;
    }
    if (json_get_int(readBuf, "limit", &limitVal) && limitVal <= 0)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Limit must be positive\"}}\n";
        return;
    }
    if (limitVal > 500) limitVal = 500;

    char filterStr[128] = { 0 };
    bool hasFilter = json_get_string(readBuf, "filter", filterStr, sizeof(filterStr)) && filterStr[0] != '\0';

    BridgeList<CONSTANTINFO> errList;
    dbg->EnumErrorCodes(&errList);

    int totalInList = errList.Count();
    std::vector<int> matchedIndices;
    matchedIndices.reserve(totalInList);

    for (int i = 0; i < totalInList; i++)
    {
        const char* name = errList[i].name ? errList[i].name : "";
        if (hasFilter)
        {
            char valHex[32];
            sprintf_s(valHex, sizeof(valHex), "0x%08X", (unsigned int)errList[i].value);
            if (!stristr_local(name, filterStr) && !stristr_local(valHex, filterStr))
                continue;
        }
        matchedIndices.push_back(i);
    }

    int totalCount = (int)matchedIndices.size();
    int startIdx = offsetVal;
    if (startIdx > totalCount) startIdx = totalCount;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;
    int returnCount = endIdx - startIdx;

    int offset = sprintf_s(responseBuf, responseBufSize,
                           "{\"count\":%d,\"total\":%d,\"error_codes\":[",
                           returnCount, totalCount);

    for (int i = startIdx; i < endIdx && offset < (int)responseBufSize - 512; i++)
    {
        int idx = matchedIndices[i];
        const char* name = errList[idx].name ? errList[idx].name : "";
        char safeName[256] = { 0 };
        escape_json_string(name, safeName, sizeof(safeName));

        offset += sprintf_s(responseBuf + offset, responseBufSize - offset,
                            "%s{\"name\":\"%s\",\"value\":\"0x%08llX\",\"value_dec\":%llu}",
                            (i > startIdx ? "," : ""),
                            safeName,
                            (unsigned long long)errList[idx].value,
                            (unsigned long long)errList[idx].value);
    }

    offset += sprintf_s(responseBuf + offset, responseBufSize - offset, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_format_inline_string(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    const DBGFUNCTIONS* dbg = DbgFunctions();
    if (dbg == nullptr || dbg->StringFormatInline == nullptr)
    {
        responseText = "{\"error\":{\"code\":\"api_failure\",\"message\":\"StringFormatInline API not available\"}}\n";
        return;
    }

    char formatStr[2048] = { 0 };
    if (!json_get_string(readBuf, "format", formatStr, sizeof(formatStr)) || formatStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing or empty format parameter\"}}\n";
        return;
    }

    char formattedResult[4096] = { 0 };
    bool ok = dbg->StringFormatInline(formatStr, sizeof(formattedResult), formattedResult);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"format_error\",\"message\":\"StringFormatInline failed to evaluate or format expression\"}}\n";
        return;
    }

    char safeFormatted[sizeof(formattedResult) * 2] = { 0 };
    char safeOriginal[sizeof(formatStr) * 2] = { 0 };
    escape_json_string(formattedResult, safeFormatted, sizeof(safeFormatted));
    escape_json_string(formatStr, safeOriginal, sizeof(safeOriginal));

    sprintf_s(responseBuf, responseBufSize,
              "{\"formatted\":\"%s\",\"original\":\"%s\",\"success\":true}\n",
              safeFormatted, safeOriginal);
    responseText = responseBuf;
}
