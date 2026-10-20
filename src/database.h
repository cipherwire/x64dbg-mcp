#pragma once

#include "common.h"

void database_init();
void database_cleanup();
void db_mutation_lock();
void db_mutation_unlock();

class DbMutationGuard
{
public:
    DbMutationGuard() { db_mutation_lock(); }
    ~DbMutationGuard() { db_mutation_unlock(); }
};

void handle_save_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_load_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
void handle_clear_database(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);

bool dispatch_commands_phase26(const char* cmdStr, const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText);
