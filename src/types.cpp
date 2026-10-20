#include "types.h"
#include "memory.h"
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>
#include <stdlib.h>

struct TypeNode {
    std::string name;
    std::string typeName;
    std::string valueStr;
    duint addr = 0;
    duint offset = 0;
    duint bitOffset = 0;
    int sizeBits = 0;
    int id = 0;
    bool expanded = false;
    std::vector<TypeNode*> children;

    ~TypeNode()
    {
        for (auto* child : children)
        {
            delete child;
        }
    }
};

struct VisitContext {
    int maxNodes = 500;
    int nodeCount = 0;
    bool truncated = false;
    std::vector<TypeNode*> rootNodes;
};

static void* TypeVisitCallback(void* parent, const TYPEDESCRIPTOR* type, void* userdata)
{
    if (!type || !userdata) return nullptr;
    auto* ctx = static_cast<VisitContext*>(userdata);
    if (ctx->nodeCount >= ctx->maxNodes)
    {
        ctx->truncated = true;
        return nullptr;
    }
    ctx->nodeCount++;

    auto* node = new TypeNode();
    if (type->name) node->name = type->name;
    if (type->typeName) node->typeName = type->typeName;
    node->addr = type->addr;
    node->offset = type->offset;
    node->bitOffset = type->bitOffset;
    node->sizeBits = type->sizeBits;
    node->id = type->id;
    node->expanded = type->expanded;

    if (type->callback && type->addr != 0)
    {
        char valBuf[256] = { 0 };
        size_t valSize = sizeof(valBuf);
        if (type->callback(type, valBuf, &valSize))
        {
            node->valueStr = valBuf;
        }
    }

    if (parent == nullptr)
    {
        ctx->rootNodes.push_back(node);
    }
    else
    {
        auto* parentNode = static_cast<TypeNode*>(parent);
        parentNode->children.push_back(node);
    }
    return node;
}

static void SerializeTypeNode(const TypeNode* node, std::string& outJson, int depth, int maxDepth)
{
    if (!node || depth > maxDepth) return;
    char safeName[512] = { 0 };
    char safeTypeName[512] = { 0 };
    char safeVal[512] = { 0 };
    escape_json_string(node->name.c_str(), safeName, sizeof(safeName));
    escape_json_string(node->typeName.c_str(), safeTypeName, sizeof(safeTypeName));
    escape_json_string(node->valueStr.c_str(), safeVal, sizeof(safeVal));

    char header[1024];
    sprintf_s(header, sizeof(header),
              "{\"name\":\"%s\",\"type_name\":\"%s\",\"address\":\"0x%llX\",\"offset\":%llu,\"bit_offset\":%llu,\"size_bits\":%d,\"size_bytes\":%d,\"type_id\":%d,\"expanded\":%s,\"value\":\"%s\",\"children\":[",
              safeName, safeTypeName, (unsigned long long)node->addr, (unsigned long long)node->offset, (unsigned long long)node->bitOffset,
              node->sizeBits, node->sizeBits / 8, node->id, node->expanded ? "true" : "false", safeVal);
    outJson += header;

    for (size_t i = 0; i < node->children.size(); i++)
    {
        if (i > 0) outJson += ",";
        SerializeTypeNode(node->children[i], outJson, depth + 1, maxDepth);
    }
    outJson += "]}";
}

void handle_inspect_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char typeNameStr[128] = { 0 };
    if (!json_get_string(readBuf, "type_name", typeNameStr, sizeof(typeNameStr)) || typeNameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'type_name' parameter\"}}\n";
        return;
    }

    char addrStr[64] = { 0 };
    duint va = 0;
    if (json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0')
    {
        if (!resolve_address(addrStr, &va))
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid address format\"}}\n";
            return;
        }
    }

    char declNameStr[128] = { 0 };
    json_get_string(readBuf, "decl_name", declNameStr, sizeof(declNameStr));

    int maxPtrDepth = 2;
    json_get_int(readBuf, "max_ptr_depth", &maxPtrDepth);
    if (maxPtrDepth < 0) maxPtrDepth = 0;
    if (maxPtrDepth > 5) maxPtrDepth = 5;

    int maxExpandDepth = 10;
    json_get_int(readBuf, "max_expand_depth", &maxExpandDepth);
    if (maxExpandDepth < 0) maxExpandDepth = 0;
    if (maxExpandDepth > 20) maxExpandDepth = 20;

    int maxExpandArray = 5;
    json_get_int(readBuf, "max_expand_array", &maxExpandArray);
    if (maxExpandArray < 0) maxExpandArray = 0;
    if (maxExpandArray > 50) maxExpandArray = 50;

    VisitContext ctx;
    ctx.maxNodes = 500;
    ctx.nodeCount = 0;
    ctx.truncated = false;

    TYPEVISITDATA data;
    memset(&data, 0, sizeof(data));
    data.typeName = typeNameStr;
    data.declName = declNameStr[0] != '\0' ? declNameStr : nullptr;
    data.root = nullptr;
    data.addr = va;
    data.maxPtrDepth = maxPtrDepth;
    data.maxExpandDepth = maxExpandDepth;
    data.maxExpandArray = maxExpandArray;
    data.createLabels = false;
    data.callback = TypeVisitCallback;
    data.userdata = &ctx;

    bool ok = DbgTypeVisit(&data);
    if (!ok)
    {
        for (auto* r : ctx.rootNodes) delete r;
        responseText = "{\"error\":{\"code\":\"type_not_found\",\"message\":\"Failed to visit type; type may not exist in database\"}}\n";
        return;
    }

    std::string nodesJson = "[";
    for (size_t i = 0; i < ctx.rootNodes.size(); i++)
    {
        if (i > 0) nodesJson += ",";
        SerializeTypeNode(ctx.rootNodes[i], nodesJson, 0, maxExpandDepth);
    }
    nodesJson += "]";

    for (auto* r : ctx.rootNodes) delete r;

    std::string fullResponse = "{\"type_name\":\"";
    fullResponse += typeNameStr;
    fullResponse += "\",\"address\":\"0x";
    char hexAddr[32];
    sprintf_s(hexAddr, "%llX", (unsigned long long)va);
    fullResponse += hexAddr;
    fullResponse += "\",\"total_nodes\":";
    fullResponse += std::to_string(ctx.nodeCount);
    fullResponse += ",\"truncated\":";
    fullResponse += ctx.truncated ? "true" : "false";
    fullResponse += ",\"roots\":";
    fullResponse += nodesJson;
    fullResponse += ",\"success\":true}\n";

    if (fullResponse.size() >= responseBufSize)
    {
        responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Type structure exceeds maximum response buffer size\"}}\n";
        return;
    }

    memcpy(responseBuf, fullResponse.c_str(), fullResponse.size() + 1);
    responseText = responseBuf;
}

void handle_get_type_size(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char typeNameStr[128] = { 0 };
    if (!json_get_string(readBuf, "type_name", typeNameStr, sizeof(typeNameStr)) || typeNameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'type_name' parameter\"}}\n";
        return;
    }

    VisitContext ctx;
    ctx.maxNodes = 2;

    TYPEVISITDATA data;
    memset(&data, 0, sizeof(data));
    data.typeName = typeNameStr;
    data.declName = nullptr;
    data.root = nullptr;
    data.addr = 0;
    data.maxPtrDepth = 0;
    data.maxExpandDepth = 0;
    data.maxExpandArray = 0;
    data.createLabels = false;
    data.callback = TypeVisitCallback;
    data.userdata = &ctx;

    bool visitOk = DbgTypeVisit(&data);
    duint sizeInBytes = 0;
    std::string underlyingType;

    if (visitOk && !ctx.rootNodes.empty())
    {
        sizeInBytes = (duint)(ctx.rootNodes[0]->sizeBits / 8);
        underlyingType = ctx.rootNodes[0]->typeName;
        for (auto* r : ctx.rootNodes) delete r;
    }
    else
    {
        for (auto* r : ctx.rootNodes) delete r;

        char cmd[256];
        sprintf_s(cmd, sizeof(cmd), "SizeofType %s", typeNameStr);
        if (!DbgCmdExecDirect(cmd))
        {
            responseText = "{\"error\":{\"code\":\"type_not_found\",\"message\":\"Type not found in type database\"}}\n";
            return;
        }

        const DBGFUNCTIONS* dbg = DbgFunctions();
        if (dbg && dbg->ValFromString)
        {
            dbg->ValFromString("$result", &sizeInBytes);
        }
    }

    char safeUnderlying[256] = { 0 };
    escape_json_string(underlyingType.c_str(), safeUnderlying, sizeof(safeUnderlying));

    sprintf_s(responseBuf, responseBufSize,
              "{\"type_name\":\"%s\",\"size\":%llu,\"underlying_type\":\"%s\",\"success\":true}\n",
              typeNameStr, (unsigned long long)sizeInBytes, safeUnderlying);
    responseText = responseBuf;
}

void handle_list_struct_types(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
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
    dbg->EnumStructs([](const char* str, void* ud) {
        if (str && *str) {
            auto* v = static_cast<std::vector<std::string>*>(ud);
            v->push_back(str);
        }
    }, &allStructs);

    std::sort(allStructs.begin(), allStructs.end());

    std::vector<std::string> matched;
    matched.reserve(allStructs.size());
    for (const auto& s : allStructs)
    {
        if (hasFilter)
        {
            std::string sLow = s, fLow = filterStr;
            std::transform(sLow.begin(), sLow.end(), sLow.begin(), [](char c){ return (char)::tolower((unsigned char)c); });
            std::transform(fLow.begin(), fLow.end(), fLow.begin(), [](char c){ return (char)::tolower((unsigned char)c); });
            if (sLow.find(fLow) == std::string::npos)
                continue;
        }
        matched.push_back(s);
    }

    int totalCount = (int)matched.size();
    int startIdx = offsetVal > totalCount ? totalCount : offsetVal;
    int endIdx = startIdx + limitVal;
    if (endIdx > totalCount) endIdx = totalCount;
    int returnCount = endIdx - startIdx;

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"count\":%d,\"total\":%d,\"types\":[",
                        returnCount, totalCount);

    for (int i = startIdx; i < endIdx && pos < (int)responseBufSize - 512; i++)
    {
        const std::string& name = matched[i];

        std::string category = "struct";
        duint size = 0;
        VisitContext vctx;
        vctx.maxNodes = 2;
        TYPEVISITDATA vdata;
        memset(&vdata, 0, sizeof(vdata));
        vdata.typeName = name.c_str();
        vdata.maxPtrDepth = 0;
        vdata.maxExpandDepth = 0;
        vdata.maxExpandArray = 0;
        vdata.createLabels = false;
        vdata.callback = TypeVisitCallback;
        vdata.userdata = &vctx;

        if (DbgTypeVisit(&vdata) && !vctx.rootNodes.empty())
        {
            size = (duint)(vctx.rootNodes[0]->sizeBits / 8);
            if (vctx.rootNodes[0]->name.find("union") == 0)
                category = "union";
        }
        for (auto* r : vctx.rootNodes) delete r;

        char safeName[256] = { 0 };
        escape_json_string(name.c_str(), safeName, sizeof(safeName));

        pos += sprintf_s(responseBuf + pos, responseBufSize - pos,
                         "%s{\"name\":\"%s\",\"category\":\"%s\",\"size\":%llu}",
                         (i > startIdx ? "," : ""),
                         safeName, category.c_str(), (unsigned long long)size);
    }

    pos += sprintf_s(responseBuf + pos, responseBufSize - pos, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_add_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char nameStr[128] = { 0 };
    char typeStr[128] = { 0 };
    if (!json_get_string(readBuf, "name", nameStr, sizeof(nameStr)) || nameStr[0] == '\0' ||
        !json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) || typeStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'name' or 'type' parameter\"}}\n";
        return;
    }

    for (const char* p = nameStr; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '_')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Type name contains invalid characters\"}}\n";
            return;
        }
    }

    char cmd[512];
    sprintf_s(cmd, sizeof(cmd), "AddType %s, %s", typeStr, nameStr);
    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"AddType command failed; ensure base type exists\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"name\":\"%s\",\"type\":\"%s\",\"success\":true}\n",
              nameStr, typeStr);
    responseText = responseBuf;
}

void handle_add_struct_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char nameStr[128] = { 0 };
    if (!json_get_string(readBuf, "name", nameStr, sizeof(nameStr)) || nameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'name' parameter\"}}\n";
        return;
    }

    for (const char* p = nameStr; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '_')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Struct name contains invalid characters\"}}\n";
            return;
        }
    }

    char cmd[512];
    sprintf_s(cmd, sizeof(cmd), "AddStruct %s", nameStr);
    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"AddStruct command failed; struct may already exist\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"name\":\"%s\",\"category\":\"struct\",\"success\":true}\n",
              nameStr);
    responseText = responseBuf;
}

void handle_add_union_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char nameStr[128] = { 0 };
    if (!json_get_string(readBuf, "name", nameStr, sizeof(nameStr)) || nameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'name' parameter\"}}\n";
        return;
    }

    for (const char* p = nameStr; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '_')
        {
            responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Union name contains invalid characters\"}}\n";
            return;
        }
    }

    char cmd[512];
    sprintf_s(cmd, sizeof(cmd), "AddUnion %s", nameStr);
    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"AddUnion command failed; union may already exist\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"name\":\"%s\",\"category\":\"union\",\"success\":true}\n",
              nameStr);
    responseText = responseBuf;
}

void handle_add_struct_member(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char parentStr[128] = { 0 };
    char typeStr[128] = { 0 };
    char nameStr[128] = { 0 };
    if (!json_get_string(readBuf, "parent_type", parentStr, sizeof(parentStr)) || parentStr[0] == '\0' ||
        !json_get_string(readBuf, "member_type", typeStr, sizeof(typeStr)) || typeStr[0] == '\0' ||
        !json_get_string(readBuf, "name", nameStr, sizeof(nameStr)) || nameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing parent_type, member_type, or name\"}}\n";
        return;
    }

    int arraySize = 0;
    json_get_int(readBuf, "array_size", &arraySize);

    int offset = -1;
    json_get_int(readBuf, "offset", &offset);

    char cmd[512];
    if (offset >= 0)
    {
        sprintf_s(cmd, sizeof(cmd), "AddMember %s, %s, %s, 0x%X, 0x%X",
                  parentStr, typeStr, nameStr, (unsigned int)(arraySize > 0 ? arraySize : 0), (unsigned int)offset);
    }
    else if (arraySize > 0)
    {
        sprintf_s(cmd, sizeof(cmd), "AddMember %s, %s, %s, 0x%X",
                  parentStr, typeStr, nameStr, (unsigned int)arraySize);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "AddMember %s, %s, %s",
                  parentStr, typeStr, nameStr);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"AddMember command failed; check parent/member types\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"parent_type\":\"%s\",\"member_type\":\"%s\",\"name\":\"%s\",\"array_size\":%d,\"offset\":%d,\"success\":true}\n",
              parentStr, typeStr, nameStr, arraySize, offset);
    responseText = responseBuf;
}

void handle_remove_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char nameStr[128] = { 0 };
    if (!json_get_string(readBuf, "name", nameStr, sizeof(nameStr)) || nameStr[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'name' parameter\"}}\n";
        return;
    }

    char cmd[512];
    sprintf_s(cmd, sizeof(cmd), "RemoveType %s", nameStr);
    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"RemoveType command failed; type not found or cannot be removed\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"name\":\"%s\",\"success\":true}\n",
              nameStr);
    responseText = responseBuf;
}

void handle_clear_types(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":{\"code\":\"confirmation_required\",\"message\":\"clear_types is destructive and requires confirm=true\"}}\n";
        return;
    }

    char ownerStr[64] = { 0 };
    json_get_string(readBuf, "owner", ownerStr, sizeof(ownerStr));

    char cmd[128];
    if (ownerStr[0] != '\0')
    {
        sprintf_s(cmd, sizeof(cmd), "ClearTypes %s", ownerStr);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "ClearTypes");
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"ClearTypes command failed\"}}\n";
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"owner\":\"%s\",\"success\":true}\n",
              ownerStr[0] != '\0' ? ownerStr : "cmd");
    responseText = responseBuf;
}

bool dispatch_commands_phase30(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "get_data_type") == 0)
    {
        handle_get_data_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_data_size") == 0)
    {
        handle_get_data_size(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_data_map") == 0)
    {
        handle_get_data_map(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_data_type") == 0)
    {
        handle_set_data_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_data_type_range") == 0)
    {
        handle_clear_data_type_range(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_data_type_segment") == 0)
    {
        handle_clear_data_type_segment(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "inspect_type") == 0)
    {
        handle_inspect_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_type_size") == 0)
    {
        handle_get_type_size(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "list_struct_types") == 0)
    {
        handle_list_struct_types(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_type") == 0)
    {
        handle_add_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_struct_type") == 0)
    {
        handle_add_struct_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_union_type") == 0)
    {
        handle_add_union_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "add_struct_member") == 0)
    {
        handle_add_struct_member(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "remove_type") == 0)
    {
        handle_remove_type(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "clear_types") == 0)
    {
        handle_clear_types(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}
