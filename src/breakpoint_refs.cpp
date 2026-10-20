#include "breakpoint_refs.h"
#include "common.h"
#include <string>
#include <vector>
#include <stdlib.h>
#include <string.h>

static const char* BpTypeToString(BPXTYPE type)
{
    switch (type)
    {
    case bp_none: return "none";
    case bp_normal: return "normal";
    case bp_hardware: return "hardware";
    case bp_memory: return "memory";
    case bp_dll: return "dll";
    case bp_exception: return "exception";
    default: return "unknown";
    }
}

static BPXTYPE StringToBpType(const char* str)
{
    if (!str || str[0] == '\0') return bp_none;
    if (_stricmp(str, "normal") == 0 || _stricmp(str, "bp_normal") == 0 || strcmp(str, "1") == 0) return bp_normal;
    if (_stricmp(str, "hardware") == 0 || _stricmp(str, "bp_hardware") == 0 || strcmp(str, "2") == 0) return bp_hardware;
    if (_stricmp(str, "memory") == 0 || _stricmp(str, "bp_memory") == 0 || strcmp(str, "4") == 0) return bp_memory;
    if (_stricmp(str, "dll") == 0 || _stricmp(str, "bp_dll") == 0 || strcmp(str, "8") == 0) return bp_dll;
    if (_stricmp(str, "exception") == 0 || _stricmp(str, "bp_exception") == 0 || strcmp(str, "16") == 0) return bp_exception;
    return bp_none;
}

static void TextCallback(const char* str, void* userdata)
{
    if (str && userdata)
    {
        *static_cast<std::string*>(userdata) = str;
    }
}

static std::string GetRefTextField(const BP_REF* ref, BP_FIELD field)
{
    std::string s;
    DbgFunctions()->BpGetFieldText(ref, field, TextCallback, &s);
    return s;
}

static bool GetRefNumberField(const BP_REF* ref, BP_FIELD field, duint* outVal)
{
    if (!outVal) return false;
    *outVal = 0;
    return DbgFunctions()->BpGetFieldNumber(ref, field, outVal);
}

static bool ResolveBpRef(const char* json, BP_REF& outRef)
{
    memset(&outRef, 0, sizeof(outRef));

    char typeStr[32] = { 0 };
    json_get_string(json, "type", typeStr, sizeof(typeStr));
    int typeInt = 0;
    if (typeStr[0] == '\0' && json_get_int(json, "type", &typeInt))
    {
        outRef.type = (BPXTYPE)typeInt;
    }
    else
    {
        outRef.type = StringToBpType(typeStr);
    }

    char addrStr[64] = { 0 };
    if (json_get_string(json, "address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0')
    {
        duint va = 0;
        if (resolve_address(addrStr, &va))
        {
            if (outRef.type != bp_none)
            {
                if (DbgFunctions()->BpRefVa(&outRef, outRef.type, va))
                    return true;
            }
            else
            {
                BPXTYPE tryTypes[] = { bp_normal, bp_hardware, bp_memory };
                for (BPXTYPE t : tryTypes)
                {
                    BP_REF tmp = {};
                    if (DbgFunctions()->BpRefVa(&tmp, t, va))
                    {
                        if (DbgFunctions()->BpRefExists(&tmp))
                        {
                            outRef = tmp;
                            return true;
                        }
                    }
                }
                DbgFunctions()->BpRefVa(&outRef, bp_normal, va);
                return true;
            }
        }
    }

    char modName[MAX_MODULE_SIZE] = { 0 };
    if (outRef.type == bp_dll && json_get_string(json, "module_name", modName, sizeof(modName)) && modName[0] != '\0')
    {
        DbgFunctions()->BpRefDll(&outRef, modName);
        return true;
    }

    int excCode = 0;
    if (outRef.type == bp_exception && json_get_int(json, "exception_code", &excCode))
    {
        DbgFunctions()->BpRefException(&outRef, (unsigned int)excCode);
        return true;
    }

    char modStr[64] = { 0 };
    json_get_string(json, "module", modStr, sizeof(modStr));
    duint modVal = 0;
    if (modStr[0] != '\0')
    {
        modVal = (duint)_strtoui64(modStr, nullptr, 0);
    }

    char offStr[64] = { 0 };
    json_get_string(json, "offset", offStr, sizeof(offStr));
    duint offVal = 0;
    if (offStr[0] != '\0')
    {
        offVal = (duint)_strtoui64(offStr, nullptr, 0);
    }
    else
    {
        int offInt = 0;
        if (json_get_int(json, "offset", &offInt))
            offVal = (duint)offInt;
    }

    if (outRef.type != bp_none)
    {
        outRef.module = modVal;
        outRef.offset = offVal;
        return true;
    }

    return false;
}

static void SerializeBpRefFields(const BP_REF* ref, std::string& outJson)
{
    bool exists = DbgFunctions()->BpRefExists(ref);
    const char* typeStr = BpTypeToString(ref->type);

    char buf[1024];
    sprintf_s(buf, sizeof(buf),
              "\"type\":\"%s\",\"type_id\":%u,\"module\":\"0x%llX\",\"offset\":\"0x%llX\",\"exists\":%s",
              typeStr, (unsigned int)ref->type, (unsigned long long)ref->module, (unsigned long long)ref->offset,
              exists ? "true" : "false");
    outJson += buf;

    if (!exists)
        return;

    duint addr = 0, off = 0, en = 0, single = 0, act = 0, sil = 0, tex = 0, hws = 0, hwslot = 0, oldb = 0, fr = 0, hc = 0;
    GetRefNumberField(ref, bpf_address, &addr);
    GetRefNumberField(ref, bpf_offset, &off);
    GetRefNumberField(ref, bpf_enabled, &en);
    GetRefNumberField(ref, bpf_singleshoot, &single);
    GetRefNumberField(ref, bpf_active, &act);
    GetRefNumberField(ref, bpf_silent, &sil);
    GetRefNumberField(ref, bpf_typeex, &tex);
    GetRefNumberField(ref, bpf_hwsize, &hws);
    GetRefNumberField(ref, bpf_hwslot, &hwslot);
    GetRefNumberField(ref, bpf_oldbytes, &oldb);
    GetRefNumberField(ref, bpf_fastresume, &fr);
    GetRefNumberField(ref, bpf_hitcount, &hc);

    sprintf_s(buf, sizeof(buf),
              ",\"address\":\"0x%llX\",\"offset_field\":\"0x%llX\",\"enabled\":%s,\"singleshoot\":%s,\"active\":%s,\"silent\":%s,\"typeex\":%u,\"hwsize\":%u,\"hwslot\":%u,\"oldbytes\":\"0x%04X\",\"fastresume\":%s,\"hitcount\":%u",
              (unsigned long long)addr, (unsigned long long)off,
              en ? "true" : "false", single ? "true" : "false", act ? "true" : "false", sil ? "true" : "false",
              (unsigned int)tex, (unsigned int)hws, (unsigned int)hwslot, (unsigned int)oldb,
              fr ? "true" : "false", (unsigned int)hc);
    outJson += buf;

    std::string mod = GetRefTextField(ref, bpf_module);
    std::string name = GetRefTextField(ref, bpf_name);
    std::string bc = GetRefTextField(ref, bpf_breakcondition);
    std::string lt = GetRefTextField(ref, bpf_logtext);
    std::string lc = GetRefTextField(ref, bpf_logcondition);
    std::string ct = GetRefTextField(ref, bpf_commandtext);
    std::string cc = GetRefTextField(ref, bpf_commandcondition);
    std::string lf = GetRefTextField(ref, bpf_logfile);

    char escMod[MAX_MODULE_SIZE * 2] = { 0 };
    char escName[MAX_BREAKPOINT_SIZE * 2] = { 0 };
    char escBc[512] = { 0 };
    char escLt[512] = { 0 };
    char escLc[512] = { 0 };
    char escCt[512] = { 0 };
    char escCc[512] = { 0 };
    char escLf[MAX_PATH * 2] = { 0 };

    escape_json_string(mod.c_str(), escMod, sizeof(escMod));
    escape_json_string(name.c_str(), escName, sizeof(escName));
    escape_json_string(bc.c_str(), escBc, sizeof(escBc));
    escape_json_string(lt.c_str(), escLt, sizeof(escLt));
    escape_json_string(lc.c_str(), escLc, sizeof(escLc));
    escape_json_string(ct.c_str(), escCt, sizeof(escCt));
    escape_json_string(cc.c_str(), escCc, sizeof(escCc));
    escape_json_string(lf.c_str(), escLf, sizeof(escLf));

    sprintf_s(buf, sizeof(buf),
              ",\"module_name\":\"%s\",\"name\":\"%s\",\"breakcondition\":\"%s\",\"logtext\":\"%s\",\"logcondition\":\"%s\",\"commandtext\":\"%s\",\"commandcondition\":\"%s\",\"logfile\":\"%s\"",
              escMod, escName, escBc, escLt, escLc, escCt, escCc, escLf);
    outJson += buf;
}

void handle_list_breakpoint_references(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    duint count = 0;
    BP_REF* refs = DbgFunctions()->BpRefList(&count);

    std::string json = "{\"count\":" + std::to_string(count) + ",\"references\":[";

    for (duint i = 0; i < count; i++)
    {
        if (i > 0) json += ",";
        json += "{";
        SerializeBpRefFields(&refs[i], json);
        json += "}";
    }

    if (refs)
    {
        BridgeFree(refs);
        refs = nullptr;
    }

    json += "],\"success\":true}\n";

    if (json.length() >= responseBufSize)
    {
        responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Response exceeded buffer capacity\"}}\n";
        return;
    }

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}

void handle_get_breakpoint_reference(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    BP_REF ref = {};
    if (!ResolveBpRef(readBuf, ref))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Could not resolve breakpoint reference from supplied parameters\"}}\n";
        return;
    }

    std::string json = "{\"reference\":{";
    SerializeBpRefFields(&ref, json);
    json += "},\"success\":true}\n";

    if (json.length() >= responseBufSize)
    {
        responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Response exceeded buffer capacity\"}}\n";
        return;
    }

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}

void handle_set_breakpoint_reference_fields(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    BP_REF ref = {};
    if (!ResolveBpRef(readBuf, ref))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Could not resolve breakpoint reference from supplied parameters\"}}\n";
        return;
    }

    if (!DbgFunctions()->BpRefExists(&ref))
    {
        responseText = "{\"error\":{\"code\":\"breakpoint_not_found\",\"message\":\"Target breakpoint reference does not exist\"}}\n";
        return;
    }

    // Check for explicit rejection of 'enabled'
    bool dummyBool = false;
    if (json_get_bool(readBuf, "enabled", &dummyBool))
    {
        responseText = "{\"error\":{\"code\":\"unsupported_field\",\"message\":\"'enabled' cannot be modified via breakpoint references; use enable_breakpoint / disable_breakpoint tools instead\"}}\n";
        return;
    }

    // Reject read-only fields
    const char* readOnlyFields[] = {
        "active", "oldbytes", "typeex", "hwsize", "hwslot"
    };
    for (const char* rof : readOnlyFields)
    {
        char tmpStr[64] = { 0 };
        int tmpInt = 0;
        if (json_get_string(readBuf, rof, tmpStr, sizeof(tmpStr)) || json_get_int(readBuf, rof, &tmpInt))
        {
            char errBuf[256];
            sprintf_s(errBuf, sizeof(errBuf),
                      "{\"error\":{\"code\":\"read_only_field\",\"message\":\"Field '%s' is read-only and cannot be modified\"}}\n", rof);
            std::string errStr = errBuf;
            if (errStr.length() < responseBufSize)
            {
                strcpy_s(responseBuf, responseBufSize, errStr.c_str());
                responseText = responseBuf;
                return;
            }
        }
    }

    std::vector<std::string> updatedFields;

    // 1. singleshoot (bool)
    bool single = false;
    if (json_get_bool(readBuf, "singleshoot", &single))
    {
        if (DbgFunctions()->BpSetFieldNumber(&ref, bpf_singleshoot, single ? 1 : 0))
            updatedFields.push_back("singleshoot");
    }

    // 2. silent (bool)
    bool sil = false;
    if (json_get_bool(readBuf, "silent", &sil))
    {
        if (DbgFunctions()->BpSetFieldNumber(&ref, bpf_silent, sil ? 1 : 0))
            updatedFields.push_back("silent");
    }

    // 3. fastresume (bool)
    bool fr = false;
    if (json_get_bool(readBuf, "fastresume", &fr))
    {
        if (DbgFunctions()->BpSetFieldNumber(&ref, bpf_fastresume, fr ? 1 : 0))
            updatedFields.push_back("fastresume");
    }

    // 4. hitcount (int)
    int hc = 0;
    if (json_get_int(readBuf, "hitcount", &hc) && hc >= 0)
    {
        if (DbgFunctions()->BpSetFieldNumber(&ref, bpf_hitcount, (duint)hc))
            updatedFields.push_back("hitcount");
    }

    // 5. name (string)
    char nameStr[MAX_BREAKPOINT_SIZE] = { 0 };
    if (json_get_string(readBuf, "name", nameStr, sizeof(nameStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_name, nameStr))
            updatedFields.push_back("name");
    }

    // 6. breakcondition (string)
    char bcStr[512] = { 0 };
    if (json_get_string(readBuf, "breakcondition", bcStr, sizeof(bcStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_breakcondition, bcStr))
            updatedFields.push_back("breakcondition");
    }

    // 7. logtext (string)
    char ltStr[512] = { 0 };
    if (json_get_string(readBuf, "logtext", ltStr, sizeof(ltStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_logtext, ltStr))
            updatedFields.push_back("logtext");
    }

    // 8. logcondition (string)
    char lcStr[512] = { 0 };
    if (json_get_string(readBuf, "logcondition", lcStr, sizeof(lcStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_logcondition, lcStr))
            updatedFields.push_back("logcondition");
    }

    // 9. commandtext (string)
    char ctStr[512] = { 0 };
    if (json_get_string(readBuf, "commandtext", ctStr, sizeof(ctStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_commandtext, ctStr))
            updatedFields.push_back("commandtext");
    }

    // 10. commandcondition (string)
    char ccStr[512] = { 0 };
    if (json_get_string(readBuf, "commandcondition", ccStr, sizeof(ccStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_commandcondition, ccStr))
            updatedFields.push_back("commandcondition");
    }

    // 11. logfile (string)
    char lfStr[MAX_PATH] = { 0 };
    if (json_get_string(readBuf, "logfile", lfStr, sizeof(lfStr)))
    {
        if (DbgFunctions()->BpSetFieldText(&ref, bpf_logfile, lfStr))
            updatedFields.push_back("logfile");
    }

    std::string json = "{\"updated_fields\":[";
    for (size_t i = 0; i < updatedFields.size(); i++)
    {
        if (i > 0) json += ",";
        json += "\"" + updatedFields[i] + "\"";
    }
    json += "],\"updated_count\":" + std::to_string(updatedFields.size()) + ",\"reference\":{";
    SerializeBpRefFields(&ref, json);
    json += "},\"success\":true}\n";

    if (json.length() >= responseBufSize)
    {
        responseText = "{\"error\":{\"code\":\"buffer_overflow\",\"message\":\"Response exceeded buffer capacity\"}}\n";
        return;
    }

    strcpy_s(responseBuf, responseBufSize, json.c_str());
    responseText = responseBuf;
}
