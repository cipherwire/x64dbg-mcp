#include "annotations.h"
#include "database.h"
#include <_scriptapi_comment.h>
#include <_scriptapi_label.h>
#include <_scriptapi_bookmark.h>
#include <bridgelist.h>
#include <vector>
#include <string>
#include <algorithm>

// ---------------------------------------------------------------------------
// Group B - Comments
// ---------------------------------------------------------------------------

void handle_set_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] set_comment: no debuggee active.\n");
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

    char commentStr[1024] = { 0 };
    // Comment can be empty string to clear the comment
    json_get_string(readBuf, "comment", commentStr, sizeof(commentStr));

    DbMutationGuard guard;
    bool ok = DbgSetCommentAt(va, commentStr);
    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to set comment at address 0x%016llX\"}\n", (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char escapedComment[2048] = { 0 };
    escape_json_string(commentStr, escapedComment, sizeof(escapedComment));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"comment\":\"%s\"}\n",
              (unsigned long long)va, escapedComment);
    responseText = responseBuf;
}

void handle_get_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_comment: no debuggee active.\n");
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

    char comment[MAX_COMMENT_SIZE] = { 0 };
    bool found = DbgGetCommentAt(va, comment) && comment[0] != '\0';

    char escapedComment[2048] = { 0 };
    escape_json_string(comment, escapedComment, sizeof(escapedComment));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"found\":%s,\"comment\":\"%s\"}\n",
              (unsigned long long)va, found ? "true" : "false", escapedComment);
    responseText = responseBuf;
}

void handle_list_comments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] list_comments: no debuggee active.\n");
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modFilter[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modFilter, sizeof(modFilter));

    int page = 1;
    json_get_int(readBuf, "page", &page);
    int pageSize = 100;
    json_get_int(readBuf, "page_size", &pageSize);
    int limit = 100;
    if (json_get_int(readBuf, "limit", &limit)) pageSize = limit;
    int offset = 0;
    if (json_get_int(readBuf, "offset", &offset)) page = (offset / pageSize) + 1;

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 1000) pageSize = 1000;

    BridgeList<Script::Comment::CommentInfo> list;
    if (!Script::Comment::GetList(&list))
    {
        responseText = "{\"error\":\"Script::Comment::GetList failed\"}\n";
        return;
    }

    struct ItemRecord {
        duint va;
        duint rva;
        char mod[MAX_MODULE_SIZE];
        char text[MAX_LABEL_SIZE];
        bool manual;
    };
    std::vector<ItemRecord> matched;
    int totalCount = list.Count();
    matched.reserve(min(totalCount, 500));

    for (int i = 0; i < totalCount; i++)
    {
        const auto& item = list[i];
        if (modFilter[0] != '\0' && _stricmp(item.mod, modFilter) != 0)
        {
            continue;
        }

        duint modBase = DbgModBaseFromName(item.mod);
        duint va = modBase ? (modBase + item.rva) : item.rva;

        ItemRecord rec;
        rec.va = va;
        rec.rva = item.rva;
        strcpy_s(rec.mod, item.mod);
        strcpy_s(rec.text, item.text);
        rec.manual = item.manual;
        matched.push_back(rec);
    }

    size_t totalMatched = matched.size();
    size_t startIdx = (size_t)(page - 1) * pageSize;
    if (startIdx > totalMatched) startIdx = totalMatched;
    size_t endIdx = min(startIdx + pageSize, totalMatched);
    size_t returnedCount = (endIdx >= startIdx) ? (endIdx - startIdx) : 0;

    int curOffset = sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"total_count\":%zu,\"count\":%zu,\"page\":%d,\"page_size\":%d,\"comments\":[",
              totalMatched, returnedCount, page, pageSize);

    for (size_t i = startIdx; i < endIdx && curOffset < (int)responseBufSize - 512; i++)
    {
        const auto& item = matched[i];
        char escText[MAX_LABEL_SIZE * 2] = { 0 };
        char escMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(item.text, escText, sizeof(escText));
        escape_json_string(item.mod, escMod, sizeof(escMod));

        curOffset += sprintf_s(responseBuf + curOffset, responseBufSize - curOffset,
            "%s{\"address\":\"0x%016llX\",\"module\":\"%s\",\"rva\":\"0x%llX\",\"comment\":\"%s\",\"manual\":%s}",
            (i > startIdx ? "," : ""),
            (unsigned long long)item.va,
            escMod,
            (unsigned long long)item.rva,
            escText,
            item.manual ? "true" : "false");
    }

    strcat_s(responseBuf, responseBufSize, "]}\n");
    responseText = responseBuf;
}

void handle_delete_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
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

    DbMutationGuard guard;
    bool ok = Script::Comment::Delete(va);

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"deleted\":%s,\"address\":\"0x%016llX\"}\n",
              ok ? "true" : "false",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_clear_comments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)responseBuf;
    (void)responseBufSize;

    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Confirmation required: set confirm to true to clear comments\"}\n";
        return;
    }

    DbMutationGuard guard;
    Script::Comment::Clear();
    responseText = "{\"status\":\"success\",\"cleared\":true}\n";
}

// ---------------------------------------------------------------------------
// Group C - Labels
// ---------------------------------------------------------------------------

void handle_set_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] set_label: no debuggee active.\n");
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

    char labelStr[512] = { 0 };
    // Label can be empty string to clear the label
    json_get_string(readBuf, "label", labelStr, sizeof(labelStr));

    DbMutationGuard guard;
    bool ok = DbgSetLabelAt(va, labelStr);
    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to set label at address 0x%016llX\"}\n", (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    char escapedLabel[1024] = { 0 };
    escape_json_string(labelStr, escapedLabel, sizeof(escapedLabel));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"label\":\"%s\"}\n",
              (unsigned long long)va, escapedLabel);
    responseText = responseBuf;
}

void handle_get_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_label: no debuggee active.\n");
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

    char label[MAX_LABEL_SIZE] = { 0 };
    bool found = DbgGetLabelAt(va, SEG_DEFAULT, label) && label[0] != '\0';

    char escapedLabel[1024] = { 0 };
    escape_json_string(label, escapedLabel, sizeof(escapedLabel));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"found\":%s,\"label\":\"%s\"}\n",
              (unsigned long long)va, found ? "true" : "false", escapedLabel);
    responseText = responseBuf;
}

void handle_list_labels(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modFilter[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modFilter, sizeof(modFilter));

    bool hasTempFilter = false;
    bool tempFilterVal = false;
    if (json_get_bool(readBuf, "temporary", &tempFilterVal))
    {
        hasTempFilter = true;
    }

    int page = 1;
    json_get_int(readBuf, "page", &page);
    int pageSize = 100;
    json_get_int(readBuf, "page_size", &pageSize);
    int limit = 100;
    if (json_get_int(readBuf, "limit", &limit)) pageSize = limit;
    int offset = 0;
    if (json_get_int(readBuf, "offset", &offset)) page = (offset / pageSize) + 1;

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 1000) pageSize = 1000;

    BridgeList<Script::Label::LabelInfo> list;
    if (!Script::Label::GetList(&list))
    {
        responseText = "{\"error\":\"Script::Label::GetList failed\"}\n";
        return;
    }

    struct LabelRecord {
        duint va;
        duint rva;
        char mod[MAX_MODULE_SIZE];
        char text[MAX_LABEL_SIZE];
        bool manual;
        bool temporary;
    };
    std::vector<LabelRecord> matched;
    int totalCount = list.Count();
    matched.reserve(min(totalCount, 500));

    for (int i = 0; i < totalCount; i++)
    {
        const auto& item = list[i];
        if (modFilter[0] != '\0' && _stricmp(item.mod, modFilter) != 0)
        {
            continue;
        }

        duint modBase = DbgModBaseFromName(item.mod);
        duint va = modBase ? (modBase + item.rva) : item.rva;

        bool isTemp = Script::Label::IsTemporary(va);
        if (hasTempFilter && isTemp != tempFilterVal)
        {
            continue;
        }

        LabelRecord rec;
        rec.va = va;
        rec.rva = item.rva;
        strcpy_s(rec.mod, item.mod);
        strcpy_s(rec.text, item.text);
        rec.manual = item.manual;
        rec.temporary = isTemp;
        matched.push_back(rec);
    }

    size_t totalMatched = matched.size();
    size_t startIdx = (size_t)(page - 1) * pageSize;
    if (startIdx > totalMatched) startIdx = totalMatched;
    size_t endIdx = min(startIdx + pageSize, totalMatched);
    size_t returnedCount = (endIdx >= startIdx) ? (endIdx - startIdx) : 0;

    int curOffset = sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"total_count\":%zu,\"count\":%zu,\"page\":%d,\"page_size\":%d,\"labels\":[",
              totalMatched, returnedCount, page, pageSize);

    for (size_t i = startIdx; i < endIdx && curOffset < (int)responseBufSize - 512; i++)
    {
        const auto& item = matched[i];
        char escText[MAX_LABEL_SIZE * 2] = { 0 };
        char escMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(item.text, escText, sizeof(escText));
        escape_json_string(item.mod, escMod, sizeof(escMod));

        curOffset += sprintf_s(responseBuf + curOffset, responseBufSize - curOffset,
            "%s{\"address\":\"0x%016llX\",\"module\":\"%s\",\"rva\":\"0x%llX\",\"name\":\"%s\",\"manual\":%s,\"temporary\":%s}",
            (i > startIdx ? "," : ""),
            (unsigned long long)item.va,
            escMod,
            (unsigned long long)item.rva,
            escText,
            item.manual ? "true" : "false",
            item.temporary ? "true" : "false");
    }

    strcat_s(responseBuf, responseBufSize, "]}\n");
    responseText = responseBuf;
}

void handle_delete_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
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

    DbMutationGuard guard;
    bool ok = Script::Label::Delete(va);

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"deleted\":%s,\"address\":\"0x%016llX\"}\n",
              ok ? "true" : "false",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_clear_labels(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)responseBuf;
    (void)responseBufSize;

    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Confirmation required: set confirm to true to clear labels\"}\n";
        return;
    }

    DbMutationGuard guard;
    Script::Label::Clear();
    responseText = "{\"status\":\"success\",\"cleared\":true}\n";
}

// ---------------------------------------------------------------------------
// Group D - Bookmarks
// ---------------------------------------------------------------------------

void handle_set_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] set_bookmark: no debuggee active.\n");
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

    bool bookmarked = true;
    bool parsedVal = false;
    if (json_get_bool(readBuf, "bookmarked", &parsedVal))
    {
        bookmarked = parsedVal;
    }

    DbMutationGuard guard;
    bool ok = DbgSetBookmarkAt(va, bookmarked);
    if (!ok)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to set bookmark at address 0x%016llX\"}\n", (unsigned long long)va);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"bookmarked\":%s}\n",
              (unsigned long long)va, bookmarked ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        _plugin_logprintf("[x64dbg-MCP] get_bookmark: no debuggee active.\n");
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

    bool bookmarked = DbgGetBookmarkAt(va);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"bookmarked\":%s}\n",
              (unsigned long long)va, bookmarked ? "true" : "false");
    responseText = responseBuf;
}

void handle_list_bookmarks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    char modFilter[MAX_MODULE_SIZE] = { 0 };
    json_get_string(readBuf, "module", modFilter, sizeof(modFilter));

    int page = 1;
    json_get_int(readBuf, "page", &page);
    int pageSize = 100;
    json_get_int(readBuf, "page_size", &pageSize);
    int limit = 100;
    if (json_get_int(readBuf, "limit", &limit)) pageSize = limit;
    int offset = 0;
    if (json_get_int(readBuf, "offset", &offset)) page = (offset / pageSize) + 1;

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 1000) pageSize = 1000;

    BridgeList<Script::Bookmark::BookmarkInfo> list;
    if (!Script::Bookmark::GetList(&list))
    {
        responseText = "{\"error\":\"Script::Bookmark::GetList failed\"}\n";
        return;
    }

    struct BookmarkRecord {
        duint va;
        duint rva;
        char mod[MAX_MODULE_SIZE];
        bool manual;
    };
    std::vector<BookmarkRecord> matched;
    int totalCount = list.Count();
    matched.reserve(min(totalCount, 500));

    for (int i = 0; i < totalCount; i++)
    {
        const auto& item = list[i];
        if (modFilter[0] != '\0' && _stricmp(item.mod, modFilter) != 0)
        {
            continue;
        }

        duint modBase = DbgModBaseFromName(item.mod);
        duint va = modBase ? (modBase + item.rva) : item.rva;

        BookmarkRecord rec;
        rec.va = va;
        rec.rva = item.rva;
        strcpy_s(rec.mod, item.mod);
        rec.manual = item.manual;
        matched.push_back(rec);
    }

    size_t totalMatched = matched.size();
    size_t startIdx = (size_t)(page - 1) * pageSize;
    if (startIdx > totalMatched) startIdx = totalMatched;
    size_t endIdx = min(startIdx + pageSize, totalMatched);
    size_t returnedCount = (endIdx >= startIdx) ? (endIdx - startIdx) : 0;

    int curOffset = sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"total_count\":%zu,\"count\":%zu,\"page\":%d,\"page_size\":%d,\"bookmarks\":[",
              totalMatched, returnedCount, page, pageSize);

    for (size_t i = startIdx; i < endIdx && curOffset < (int)responseBufSize - 512; i++)
    {
        const auto& item = matched[i];
        char escMod[MAX_MODULE_SIZE * 2] = { 0 };
        escape_json_string(item.mod, escMod, sizeof(escMod));

        curOffset += sprintf_s(responseBuf + curOffset, responseBufSize - curOffset,
            "%s{\"address\":\"0x%016llX\",\"module\":\"%s\",\"rva\":\"0x%llX\",\"manual\":%s}",
            (i > startIdx ? "," : ""),
            (unsigned long long)item.va,
            escMod,
            (unsigned long long)item.rva,
            item.manual ? "true" : "false");
    }

    strcat_s(responseBuf, responseBufSize, "]}\n");
    responseText = responseBuf;
}

void handle_delete_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
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

    DbMutationGuard guard;
    bool ok = Script::Bookmark::Delete(va);

    sprintf_s(responseBuf, responseBufSize,
              "{\"status\":\"success\",\"deleted\":%s,\"address\":\"0x%016llX\"}\n",
              ok ? "true" : "false",
              (unsigned long long)va);
    responseText = responseBuf;
}

void handle_clear_bookmarks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)responseBuf;
    (void)responseBufSize;

    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Confirmation required: set confirm to true to clear bookmarks\"}\n";
        return;
    }

    DbMutationGuard guard;
    Script::Bookmark::Clear();
    responseText = "{\"status\":\"success\",\"cleared\":true}\n";
}
