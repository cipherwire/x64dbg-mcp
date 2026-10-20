#pragma once

#include "common.h"

const char* thread_priority_string(THREADPRIORITY priority);
const char* thread_wait_reason_string(THREADWAITREASON reason);

void handle_list_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_switch_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Phase 31: Thread metadata & configuration
void handle_get_thread_name(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_thread_name(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_thread_priority(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_thread_priority(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

