#pragma once

#include "common.h"

bool StartWorkerThread();
bool StopWorkerThread();
unsigned __stdcall PipeWorkerThreadProc(void* arg);
