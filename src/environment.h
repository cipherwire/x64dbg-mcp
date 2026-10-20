#pragma once

#include "common.h"

void handle_get_peb_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_teb_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_command_line(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_command_line(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_security_mitigations(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
