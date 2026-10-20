#pragma once

#include "common.h"

void console_lock_acquire();
void console_lock_release();

void handle_send_console_input(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
