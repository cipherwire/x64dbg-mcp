#pragma once

#include "common.h"

// Lifecycle hooks
void record_last_exception(const PLUG_CB_EXCEPTION* info);
void reset_last_exception();

// MCP tool handlers
void handle_list_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_exception_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_enable_exception_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_last_exception(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
