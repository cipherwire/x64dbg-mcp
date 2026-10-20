#pragma once

#include "common.h"

bool find_breakpoint_at_address(duint va, BRIDGEBP* outBp = nullptr);

void handle_set_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_breakpoints(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_enable_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
