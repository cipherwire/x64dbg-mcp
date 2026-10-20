#pragma once

#include "common.h"

void handle_set_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_enable_hardware_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_set_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_memory_range_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_enable_memory_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_set_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_enable_dll_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_get_breakpoint_details(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_configure_breakpoint(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_reset_breakpoint_hit_count(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
