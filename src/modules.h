#pragma once

#include "common.h"

void handle_list_modules(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_module_sections(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_imports(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_exports(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_va_to_file_offset(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_file_offset_to_va(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_relocation(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_relocations(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
