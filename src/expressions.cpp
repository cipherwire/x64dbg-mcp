#include "expressions.h"

void handle_eval_expression(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char exprStr[512] = { 0 };
    if (!json_get_string(readBuf, "expression", exprStr, sizeof(exprStr)) || exprStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing expression parameter\"}\n";
    }
    else
    {
        const char* p = exprStr;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p == '\0')
        {
            responseText = "{\"error\":\"empty expression\"}\n";
        }
        else
        {
            duint val = 0;
            bool ok = Script::Misc::ParseExpression(exprStr, &val);
            char safeExpr[sizeof(exprStr) * 2] = { 0 };
            escape_json_string(exprStr, safeExpr, sizeof(safeExpr));

            if (ok)
            {
                sprintf_s(responseBuf, responseBufSize,
                          "{\"expression\":\"%s\",\"value\":\"0x%016llX\",\"decimal\":%llu}\n",
                          safeExpr,
                          (unsigned long long)val,
                          (unsigned long long)val);
                responseText = responseBuf;

                _plugin_logprintf("[x64dbg-MCP] eval_expression '%s' -> 0x%llX (%llu).\n",
                                  safeExpr, (unsigned long long)val, (unsigned long long)val);
            }
            else
            {
                sprintf_s(responseBuf, responseBufSize,
                          "{\"error\":\"failed to evaluate expression\",\"expression\":\"%s\"}\n",
                          safeExpr);
                responseText = responseBuf;

                _plugin_logprintf("[x64dbg-MCP] eval_expression failed for '%s'.\n", safeExpr);
            }
        }
    }
}
