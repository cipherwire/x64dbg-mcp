#include "dbg_config.h"
#include "breakpoint_refs.h"
#include "threads.h"
#include "pe_metadata.h"
#include "memory.h"
#include <string>
#include <stdio.h>
#include <string.h>


void handle_get_mnemonic_brief(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char mnem[128] = { 0 };
    if (!json_get_string(readBuf, "mnemonic", mnem, sizeof(mnem)) || mnem[0] == '\0')
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing 'mnemonic' parameter\"}}\n";
        return;
    }

    char brief[512] = { 0 };
    DbgFunctions()->GetMnemonicBrief(mnem, sizeof(brief), brief);

    char safeMnem[256] = { 0 };
    char safeBrief[1024] = { 0 };
    escape_json_string(mnem, safeMnem, sizeof(safeMnem));
    escape_json_string(brief, safeBrief, sizeof(safeBrief));

    sprintf_s(responseBuf, responseBufSize,
              "{\"mnemonic\":\"%s\",\"brief\":\"%s\",\"found\":%s,\"success\":true}\n",
              safeMnem, safeBrief, brief[0] != '\0' ? "true" : "false");
    responseText = responseBuf;
}

void handle_get_debuggee_init_script(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    const char* script = DbgFunctions()->DbgGetDebuggeeInitScript();
    if (!script) script = "";

    char safeScript[MAX_PATH * 2] = { 0 };
    escape_json_string(script, safeScript, sizeof(safeScript));

    sprintf_s(responseBuf, responseBufSize,
              "{\"script_path\":\"%s\",\"success\":true}\n",
              safeScript);
    responseText = responseBuf;
}

void handle_set_debuggee_init_script(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char path[MAX_PATH] = { 0 };
    json_get_string(readBuf, "script_path", path, sizeof(path));

    DbgFunctions()->DbgSetDebuggeeInitScript(path);

    const char* readback = DbgFunctions()->DbgGetDebuggeeInitScript();
    if (!readback) readback = "";

    char safeScript[MAX_PATH * 2] = { 0 };
    escape_json_string(readback, safeScript, sizeof(safeScript));

    sprintf_s(responseBuf, responseBufSize,
              "{\"script_path\":\"%s\",\"success\":true}\n",
              safeScript);
    responseText = responseBuf;
}

void handle_get_jit_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    (void)readBuf;
    bool elevated = BridgeIsProcessElevated();

    char x64Jit[MAX_SETTING_SIZE] = { 0 };
    bool okX64 = DbgFunctions()->GetJit(x64Jit, true);

    char x32Jit[MAX_SETTING_SIZE] = { 0 };
    bool okX32 = DbgFunctions()->GetJit(x32Jit, false);

    char defJit[MAX_SETTING_SIZE] = { 0 };
    DbgFunctions()->GetDefJit(defJit);

    char oldJit[MAX_SETTING_SIZE] = { 0 };
    bool hasOld = BridgeSettingGet("JIT", "Old", oldJit);

    bool jitAuto = false;
    DbgFunctions()->GetJitAuto(&jitAuto);

    char safeX64[MAX_SETTING_SIZE * 2] = { 0 };
    char safeX32[MAX_SETTING_SIZE * 2] = { 0 };
    char safeDef[MAX_SETTING_SIZE * 2] = { 0 };
    char safeOld[MAX_SETTING_SIZE * 2] = { 0 };

    escape_json_string(x64Jit, safeX64, sizeof(safeX64));
    escape_json_string(x32Jit, safeX32, sizeof(safeX32));
    escape_json_string(defJit, safeDef, sizeof(safeDef));
    escape_json_string(oldJit, safeOld, sizeof(safeOld));

    sprintf_s(responseBuf, responseBufSize,
              "{\"is_elevated\":%s,\"x64\":{\"entry\":\"%s\",\"supported\":%s},\"x32\":{\"entry\":\"%s\",\"supported\":%s},\"default_entry\":\"%s\",\"old_entry\":\"%s\",\"has_old_entry\":%s,\"jit_auto\":%s,\"success\":true}\n",
              elevated ? "true" : "false",
              safeX64, okX64 ? "true" : "false",
              safeX32, okX32 ? "true" : "false",
              safeDef, safeOld,
              hasOld ? "true" : "false",
              jitAuto ? "true" : "false");
    responseText = responseBuf;
}

void handle_set_jit(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":{\"code\":\"confirmation_required\",\"message\":\"Confirmation required: set 'confirm' to true to modify system JIT configuration\"}}\n";
        return;
    }

    if (!BridgeIsProcessElevated())
    {
        responseText = "{\"error\":{\"code\":\"elevation_required\",\"message\":\"Process is not elevated; administrator privileges required to modify JIT settings\"}}\n";
        return;
    }

    char archStr[32] = { 0 };
    json_get_string(readBuf, "arch", archStr, sizeof(archStr));

    char modeStr[32] = { 0 };
    json_get_string(readBuf, "mode", modeStr, sizeof(modeStr));

    char customCmd[MAX_SETTING_SIZE] = { 0 };
    json_get_string(readBuf, "command", customCmd, sizeof(customCmd));

    char cmd[MAX_SETTING_SIZE + 64] = { 0 };

    if (customCmd[0] != '\0')
    {
        if (archStr[0] != '\0')
        {
            sprintf_s(cmd, sizeof(cmd), "setjit %s, \"%s\"", archStr, customCmd);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "setjit \"%s\"", customCmd);
        }
    }
    else if (_stricmp(modeStr, "old") == 0)
    {
        sprintf_s(cmd, sizeof(cmd), "setjit old");
    }
    else if (_stricmp(modeStr, "oldsave") == 0)
    {
        sprintf_s(cmd, sizeof(cmd), "setjit oldsave");
    }
    else if (_stricmp(modeStr, "default") == 0 || modeStr[0] == '\0')
    {
        if (archStr[0] != '\0')
        {
            sprintf_s(cmd, sizeof(cmd), "setjit %s", archStr);
        }
        else
        {
            sprintf_s(cmd, sizeof(cmd), "setjit");
        }
    }
    else
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Unsupported mode; must be 'default', 'old', 'oldsave', or provide a custom 'command'\"}}\n";
        return;
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"setjit command execution failed\"}}\n";
        return;
    }

    bool isX64 = (_stricmp(archStr, "x32") != 0);
    char readback[MAX_SETTING_SIZE] = { 0 };
    DbgFunctions()->GetJit(readback, isX64);

    char safeReadback[MAX_SETTING_SIZE * 2] = { 0 };
    escape_json_string(readback, safeReadback, sizeof(safeReadback));

    sprintf_s(responseBuf, responseBufSize,
              "{\"entry\":\"%s\",\"arch\":\"%s\",\"success\":true}\n",
              safeReadback, isX64 ? "x64" : "x32");
    responseText = responseBuf;
}

void handle_set_jit_auto(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":{\"code\":\"confirmation_required\",\"message\":\"Confirmation required: set 'confirm' to true to modify system JIT Auto settings\"}}\n";
        return;
    }

    if (!BridgeIsProcessElevated())
    {
        responseText = "{\"error\":{\"code\":\"elevation_required\",\"message\":\"Process is not elevated; administrator privileges required to modify JIT Auto settings\"}}\n";
        return;
    }

    bool enabled = false;
    if (!json_get_bool(readBuf, "enabled", &enabled))
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Missing required boolean parameter 'enabled'\"}}\n";
        return;
    }

    char archStr[32] = { 0 };
    json_get_string(readBuf, "arch", archStr, sizeof(archStr));

    char cmd[128];
    if (archStr[0] != '\0')
    {
        sprintf_s(cmd, sizeof(cmd), "setjitauto %s, %d", archStr, enabled ? 1 : 0);
    }
    else
    {
        sprintf_s(cmd, sizeof(cmd), "setjitauto %d", enabled ? 1 : 0);
    }

    bool ok = DbgCmdExecDirect(cmd);
    if (!ok)
    {
        responseText = "{\"error\":{\"code\":\"command_failed\",\"message\":\"setjitauto command execution failed\"}}\n";
        return;
    }

    bool readbackAuto = false;
    DbgFunctions()->GetJitAuto(&readbackAuto);

    sprintf_s(responseBuf, responseBufSize,
              "{\"jit_auto\":%s,\"success\":true}\n",
              readbackAuto ? "true" : "false");
    responseText = responseBuf;
}

bool dispatch_commands_phase31(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (strcmp(cmdStr, "list_breakpoint_references") == 0)
    {
        handle_list_breakpoint_references(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_breakpoint_reference") == 0)
    {
        handle_get_breakpoint_reference(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_breakpoint_reference_fields") == 0)
    {
        handle_set_breakpoint_reference_fields(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_thread_name") == 0)
    {
        handle_get_thread_name(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_thread_name") == 0)
    {
        handle_set_thread_name(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_thread_priority") == 0)
    {
        handle_set_thread_priority(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_thread_priority") == 0)
    {
        handle_get_thread_priority(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_module_party") == 0)
    {
        handle_set_module_party(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "is_code_page") == 0)
    {
        handle_is_code_page(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_mnemonic_brief") == 0)
    {
        handle_get_mnemonic_brief(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_debuggee_init_script") == 0)
    {
        handle_get_debuggee_init_script(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_debuggee_init_script") == 0)
    {
        handle_set_debuggee_init_script(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "get_jit_info") == 0)
    {
        handle_get_jit_info(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_jit") == 0)
    {
        handle_set_jit(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    else if (strcmp(cmdStr, "set_jit_auto") == 0)
    {
        handle_set_jit_auto(readBuf, responseBuf, responseBufSize, responseText);
        return true;
    }
    return false;
}

