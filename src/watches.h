#pragma once

#include "common.h"

// Phase 28: Watch Expressions & Runtime Value Tracking
bool dispatch_commands_phase28(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

void handle_list_watches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_add_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_modify_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_rename_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_watch_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_watch(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_watches(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_watchdog(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_check_watchdogs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
