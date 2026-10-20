#pragma once

#include "common.h"

void handle_disassemble(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_test_raw_disasm(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
