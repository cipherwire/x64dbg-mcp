#pragma once

#include "common.h"

// Phase 31: Debugger Metadata & Configuration
void handle_get_mnemonic_brief(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_debuggee_init_script(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_debuggee_init_script(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_jit_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_jit(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_jit_auto(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

bool dispatch_commands_phase31(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

