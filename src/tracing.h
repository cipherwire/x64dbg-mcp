#pragma once

#include "common.h"

// Phase 27 - Rich Tracing & Conditional Execution Control

void handle_trace_into_conditional(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_trace_over_conditional(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_trace_into_beyond_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_trace_over_beyond_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_trace_into_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_trace_over_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_run_to_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_trace_log(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_trace_command(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_trace_log_file(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_trace_step_filter(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_start_trace_recording(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_stop_trace_recording(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Phase 27 command dispatcher
bool dispatch_commands_phase27(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
