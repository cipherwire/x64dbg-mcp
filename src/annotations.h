#pragma once

#include "common.h"

// Group B - Comments
void handle_set_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_comments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_comment(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_comments(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group C - Labels
void handle_set_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_labels(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_label(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_labels(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

// Group D - Bookmarks
void handle_set_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_get_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_list_bookmarks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_delete_bookmark(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_bookmarks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
