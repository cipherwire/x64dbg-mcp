#pragma once

#include "common.h"

void handle_get_registers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_register(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_test_raw_regdump(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
