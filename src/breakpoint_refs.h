#pragma once

#include "_plugins.h"

// Phase 31: Breakpoint References API handlers
void handle_list_breakpoint_references(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_breakpoint_reference(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_breakpoint_reference_fields(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
