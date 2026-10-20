#pragma once

#include "common.h"

void handle_resolve_symbol(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_symbols(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_symbol_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_source_location(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_find_source_address(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_symbol_autocomplete(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
