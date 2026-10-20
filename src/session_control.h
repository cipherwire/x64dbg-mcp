#pragma once

#include "common.h"

// Lifecycle hooks called from plugin.cpp
void on_session_init_debug(const char* szFileName);
void on_session_attach(DWORD dwProcessId);
void on_session_detach();
void on_session_stop();

// Part A - Process Discovery
void handle_list_processes(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Part B - Debug Session Lifecycle
void handle_launch_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_attach_process(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_detach_process(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_stop_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_restart_debuggee(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);


// Part C - Thread Suspension / Resumption
void handle_suspend_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_resume_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_suspend_all_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_resume_all_threads(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_kill_thread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Part D - Process / Session State Enhancement
void handle_get_debug_session_info(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
