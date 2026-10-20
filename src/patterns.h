#pragma once

#include "common.h"

struct PatternByte
{
    unsigned char data;
    unsigned char mask;
};

bool patterntransform(const std::string& patterntext, std::vector<PatternByte>& pattern);
size_t patternfind_vec(const unsigned char* data, size_t datasize, const std::vector<PatternByte>& pattern);

void handle_find_pattern(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
