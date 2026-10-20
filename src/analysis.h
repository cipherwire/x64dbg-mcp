#pragma once

#include "common.h"

// Group A - Analysis Control
void handle_analyze_code(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_control_flow(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_exception_directory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_recursive(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_advanced(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_xrefs(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_analyze_nukem(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group C - Structured Control-Flow Graph
void handle_get_control_flow_graph(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group D - Function Relationships
void handle_get_function_callers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_function_callees(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
