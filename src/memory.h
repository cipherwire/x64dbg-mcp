#pragma once

#include "common.h"

void decode_protection_string(DWORD protect, char* outStr, size_t outStrSize, char* outRawStr, size_t outRawStrSize);
void format_memory_region_entry(const MEMORY_BASIC_INFORMATION& mbi, char* buf, size_t bufSize);
void format_memory_region_json(duint va, const MEMORY_BASIC_INFORMATION& mbi, char* buf, size_t bufSize);
bool parse_memory_region_address(const char* addrStr, duint* outVa);

bool parse_hex_bytes(const char* hexStr, unsigned char* outBuf, size_t maxLen, size_t* outLen);

void handle_read_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_write_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_memory_region(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_memory_regions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_page_rights(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_page_rights(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_allocate_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_free_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_fill_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_copy_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_heaps(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_test_raw_memread(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Phase 30: Encoding / Data Map
void handle_get_data_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_data_size(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_data_map(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_set_data_type(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_data_type_range(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_data_type_segment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Phase 31: Code-page classification
void handle_is_code_page(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

