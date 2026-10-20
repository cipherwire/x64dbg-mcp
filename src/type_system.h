#pragma once

#include "common.h"

void handle_list_structs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_constants(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_error_codes(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_format_inline_string(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
