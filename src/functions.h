#pragma once

#include "common.h"

void handle_get_function_boundary(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_function_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group E - Functions Management
void handle_add_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group C - Loops
void handle_get_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_loops(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_loop(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_loops(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group C - Arguments
void handle_get_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_arguments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_argument(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_arguments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
