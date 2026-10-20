#include "trace.h"
#include <ctype.h>
#include <stdlib.h>

static bool g_traceRecordingActive = false;
static char g_traceFilePath[MAX_PATH] = { 0 };
static SRWLOCK g_traceLock = SRWLOCK_INIT;

void on_trace_started(const char* traceFilePath)
{
    AcquireSRWLockExclusive(&g_traceLock);
    g_traceRecordingActive = true;
    if (traceFilePath)
    {
        strncpy_s(g_traceFilePath, sizeof(g_traceFilePath), traceFilePath, _TRUNCATE);
    }
    else
    {
        g_traceFilePath[0] = '\0';
    }
    ReleaseSRWLockExclusive(&g_traceLock);
}

void on_trace_stopped()
{
    AcquireSRWLockExclusive(&g_traceLock);
    g_traceRecordingActive = false;
    g_traceFilePath[0] = '\0';
    ReleaseSRWLockExclusive(&g_traceLock);
}

static const char* trace_record_type_to_string(TRACERECORDTYPE t)
{
    switch (t)
    {
    case TraceRecordNone: return "none";
    case TraceRecordBitExec: return "bit";
    case TraceRecordByteWithExecTypeAndCounter: return "byte";
    case TraceRecordWordWithExecTypeAndCounter: return "word";
    default: return "unknown";
    }
}

static const char* trace_byte_type_to_string(TRACERECORDBYTETYPE bt)
{
    switch (bt)
    {
    case InstructionBody: return "instruction_body";
    case InstructionHeading: return "instruction_heading";
    case InstructionTailing: return "instruction_tailing";
    case InstructionOverlapped: return "instruction_overlapped";
    case DataByte: return "data_byte";
    case DataWord: return "data_word";
    case DataDWord: return "data_dword";
    case DataQWord: return "data_qword";
    case DataFloat: return "data_float";
    case DataDouble: return "data_double";
    case DataLongDouble: return "data_long_double";
    case DataXMM: return "data_xmm";
    case DataYMM: return "data_ymm";
    case DataMMX: return "data_mmx";
    case DataMixed: return "data_mixed";
    case InstructionDataMixed: return "instruction_data_mixed";
    default: return "none";
    }
}

void handle_get_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
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

    auto dbg = DbgFunctions();
    if (!dbg || !dbg->GetTraceRecordType || !dbg->GetTraceRecordHitCount || !dbg->GetTraceRecordByteType)
    {
        responseText = "{\"error\":\"trace record API not available\"}\n";
        return;
    }

    duint pageAddr = va & ~((duint)4096 - 1);
    TRACERECORDTYPE pageType = dbg->GetTraceRecordType(pageAddr);
    unsigned int hitCount = dbg->GetTraceRecordHitCount(va);
    TRACERECORDBYTETYPE byteType = dbg->GetTraceRecordByteType(va);

    const char* pageTypeStr = trace_record_type_to_string(pageType);
    const char* byteTypeStr = trace_byte_type_to_string(byteType);

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"page_address\":\"0x%016llX\",\"page_record_type\":\"%s\",\"hit_count\":%u,\"byte_type\":\"%s\"}\n",
              (unsigned long long)va,
              (unsigned long long)pageAddr,
              pageTypeStr,
              hitCount,
              byteTypeStr);
    responseText = responseBuf;
}

void handle_set_trace_record_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running\"}\n";
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

    char typeStr[32] = { 0 };
    if (!json_get_string(readBuf, "type", typeStr, sizeof(typeStr)) || typeStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing type parameter\"}\n";
        return;
    }

    TRACERECORDTYPE targetType;
    if (_stricmp(typeStr, "none") == 0)
    {
        targetType = TraceRecordNone;
    }
    else if (_stricmp(typeStr, "bit") == 0)
    {
        targetType = TraceRecordBitExec;
    }
    else if (_stricmp(typeStr, "byte") == 0)
    {
        targetType = TraceRecordByteWithExecTypeAndCounter;
    }
    else if (_stricmp(typeStr, "word") == 0)
    {
        targetType = TraceRecordWordWithExecTypeAndCounter;
    }
    else
    {
        responseText = "{\"error\":\"invalid type: must be none, bit, byte, or word\"}\n";
        return;
    }

    auto dbg = DbgFunctions();
    if (!dbg || !dbg->SetTraceRecordType || !dbg->GetTraceRecordType)
    {
        responseText = "{\"error\":\"SetTraceRecordType API not available\"}\n";
        return;
    }

    duint pageAddr = va & ~((duint)4096 - 1);
    TRACERECORDTYPE curType = dbg->GetTraceRecordType(pageAddr);

    // If changing between non-none types, x64dbg requires setting TraceRecordNone first
    if (curType != targetType && curType != TraceRecordNone && targetType != TraceRecordNone)
    {
        dbg->SetTraceRecordType(pageAddr, TraceRecordNone);
    }

    bool ok = dbg->SetTraceRecordType(pageAddr, targetType);
    TRACERECORDTYPE verifiedType = dbg->GetTraceRecordType(pageAddr);

    if (!ok && verifiedType != targetType)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"failed to set trace record type for page 0x%016llX\"}\n",
                  (unsigned long long)pageAddr);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"page_address\":\"0x%016llX\",\"type\":\"%s\",\"success\":true}\n",
              (unsigned long long)pageAddr,
              trace_record_type_to_string(verifiedType));
    responseText = responseBuf;
}

void handle_get_trace_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    bool isDebugging = DbgIsDebugging();
    bool isRunning = isDebugging ? DbgIsRunning() : false;

    AcquireSRWLockShared(&g_traceLock);
    bool recordingActive = g_traceRecordingActive;
    char pathCopy[MAX_PATH];
    strncpy_s(pathCopy, sizeof(pathCopy), g_traceFilePath, _TRUNCATE);
    ReleaseSRWLockShared(&g_traceLock);

    // Check if conditional trace is active
    bool conditionalTraceActive = false;
    duint condVal = 0;
    if (isDebugging && Script::Misc::ParseExpression("$tracecondition", &condVal))
    {
        conditionalTraceActive = (condVal != 0);
    }

    char escPath[MAX_PATH * 2];
    escape_json_string(pathCopy, escPath, sizeof(escPath));

    // Optional page check if address supplied
    char addrStr[64] = { 0 };
    bool hasAddress = json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) && addrStr[0] != '\0';
    char pageInfoSnippet[128] = { 0 };

    if (hasAddress && isDebugging)
    {
        duint va = 0;
        if (resolve_address(addrStr, &va))
        {
            auto dbg = DbgFunctions();
            if (dbg && dbg->GetTraceRecordType)
            {
                duint pageAddr = va & ~((duint)4096 - 1);
                TRACERECORDTYPE pt = dbg->GetTraceRecordType(pageAddr);
                sprintf_s(pageInfoSnippet, sizeof(pageInfoSnippet),
                          ",\"page_address\":\"0x%016llX\",\"page_record_type\":\"%s\"",
                          (unsigned long long)pageAddr,
                          trace_record_type_to_string(pt));
            }
        }
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"is_debugging\":%s,\"is_running\":%s,\"trace_recording_active\":%s,\"trace_file\":\"%s\",\"conditional_trace_active\":%s%s}\n",
              isDebugging ? "true" : "false",
              isRunning ? "true" : "false",
              recordingActive ? "true" : "false",
              escPath,
              conditionalTraceActive ? "true" : "false",
              pageInfoSnippet);
    responseText = responseBuf;
}
