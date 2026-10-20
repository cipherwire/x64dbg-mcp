#pragma once

#include "common.h"

// Lifecycle hooks
void on_trace_started(const char* traceFilePath);
void on_trace_stopped();

// MCP tool handlers
void handle_get_trace_record(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_trace_record_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_trace_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
