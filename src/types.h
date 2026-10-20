#pragma once

#include "common.h"

// Phase 30: Data Encoding Maps & Structured Type Inspection
bool dispatch_commands_phase30(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_inspect_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_type_size(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_struct_types(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_add_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_struct_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_union_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_struct_member(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_remove_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_types(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
