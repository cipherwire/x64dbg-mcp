#pragma once

#include "common.h"

void handle_list_handles(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_handle_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_tcp_connections(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_windows(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
