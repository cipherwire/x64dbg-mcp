#pragma once

#include "common.h"

void handle_get_call_stack(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_thread_call_stack(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_seh_chain(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
