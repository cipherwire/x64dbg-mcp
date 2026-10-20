#pragma once

#include "common.h"

// Part D - Controlled Memory Extraction
void handle_dump_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_dump_module(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_create_minidump(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
