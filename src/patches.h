#pragma once

#include "common.h"

void handle_patch_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_patches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_patch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_restore_patch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_restore_patches_range(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
