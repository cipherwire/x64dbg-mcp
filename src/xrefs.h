#pragma once

#include "common.h"

const char* decode_xref_type(XREFTYPE type);
void handle_get_xrefs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
