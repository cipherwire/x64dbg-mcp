#pragma once

#include "common.h"

void handle_get_debugger_state(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_bridge_status(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_resume(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_pause(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_into(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_over(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_out(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_run_to_address(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_run_to_user_code(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_user(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_system(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_skip_instruction(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_over_pass_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_step_out_pass_exceptions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

