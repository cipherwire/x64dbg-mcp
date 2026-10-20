#pragma once

#include "common.h"

// Part A - PE Image Metadata
void handle_get_pe_headers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_pe_data_directories(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Part B - TLS / Unwind Metadata
void handle_list_tls_callbacks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_runtime_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_runtime_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Explicit Investigation - Module Party (User vs System)
void handle_get_module_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_module_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

