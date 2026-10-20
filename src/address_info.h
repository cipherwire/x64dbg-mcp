#pragma once

#include "common.h"

const char* decode_symbol_type(SYMBOLTYPE type);
void handle_get_address_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
