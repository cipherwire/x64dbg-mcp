#include "dump.h"
#include <DbgHelp.h>
#include <vector>
#include <string>
#include <cctype>

// --------------------------------------------------------------------------
// Path Safety Validation Helper
// --------------------------------------------------------------------------

static bool validate_safe_output_path(const char* path, char* errBuf, size_t errBufSize)
{
    if (!path || path[0] == '\0')
    {
        sprintf_s(errBuf, errBufSize, "output_path must not be empty");
        return false;
    }

    if (strstr(path, "..") != nullptr)
    {
        sprintf_s(errBuf, errBufSize, "output_path contains forbidden directory traversal (..)");
        return false;
    }

    if (path[0] == '\\' && path[1] == '\\')
    {
        sprintf_s(errBuf, errBufSize, "output_path must not be a UNC network path");
        return false;
    }

    size_t len = strlen(path);
    if (len > MAX_PATH)
    {
        sprintf_s(errBuf, errBufSize, "output_path exceeds maximum path length");
        return false;
    }

    for (size_t i = 0; i < len; i++)
    {
        char c = path[i];
        if (c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
        {
            sprintf_s(errBuf, errBufSize, "output_path contains invalid filename character: '%c'", c);
            return false;
        }
    }

    // Blacklist check for sensitive Windows directories
    char lowerPath[MAX_PATH + 1] = { 0 };
    for (size_t i = 0; i < len; i++)
    {
        lowerPath[i] = (char)tolower((unsigned char)path[i]);
    }

    static const char* s_forbiddenSubstrings[] = {
        "\\windows\\",
        "\\system32\\",
        "\\syswow64\\",
        "\\systemroot\\",
        "\\program files\\",
        "\\programdata\\"
    };

    for (size_t i = 0; i < sizeof(s_forbiddenSubstrings) / sizeof(s_forbiddenSubstrings[0]); i++)
    {
        if (strstr(lowerPath, s_forbiddenSubstrings[i]) != nullptr)
        {
            sprintf_s(errBuf, errBufSize, "output_path targets a protected system directory");
            return false;
        }
    }

    // Verify parent directory exists if specified
    char dirPart[MAX_PATH] = { 0 };
    strncpy_s(dirPart, path, _TRUNCATE);
    char* lastSlash = strrchr(dirPart, '\\');
    if (!lastSlash)
    {
        lastSlash = strrchr(dirPart, '/');
    }
    if (lastSlash)
    {
        *lastSlash = '\0';
        DWORD attr = GetFileAttributesA(dirPart);
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            sprintf_s(errBuf, errBufSize, "parent directory does not exist: %s", dirPart);
            return false;
        }
    }

    return true;
}

// --------------------------------------------------------------------------
// Part D - Controlled Memory Extraction
// --------------------------------------------------------------------------

void handle_dump_memory(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running; memory dump requires paused target for consistency\"}\n";
        return;
    }

    char addrStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'address' parameter\"}\n";
        return;
    }

    duint addr = DbgValFromString(addrStr);
    if (addr == 0)
    {
        responseText = "{\"error\":\"invalid address expression\"}\n";
        return;
    }

    duint dumpSize = 0;
    int sizeInt = 0;
    if (json_get_int(readBuf, "size", &sizeInt) && sizeInt > 0)
    {
        dumpSize = (duint)sizeInt;
    }
    else
    {
        char sizeStr[64] = { 0 };
        if (json_get_string(readBuf, "size", sizeStr, sizeof(sizeStr)) && sizeStr[0] != '\0')
        {
            dumpSize = DbgValFromString(sizeStr);
        }
    }

    if (dumpSize == 0)
    {
        responseText = "{\"error\":\"missing or invalid 'size' parameter (must be positive integer)\"}\n";
        return;
    }

    if (addr + dumpSize < addr)
    {
        responseText = "{\"error\":\"address range integer overflow\"}\n";
        return;
    }

    constexpr duint kMaxDumpSize = 32 * 1024 * 1024; // 32MB max
    if (dumpSize > kMaxDumpSize)
    {
        responseText = "{\"error\":\"requested dump size exceeds maximum limit of 32MB\"}\n";
        return;
    }

    char outputPath[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "output_path", outputPath, sizeof(outputPath)) || outputPath[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'output_path' parameter\"}\n";
        return;
    }

    char pathErr[256] = { 0 };
    if (!validate_safe_output_path(outputPath, pathErr, sizeof(pathErr)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", pathErr);
        responseText = responseBuf;
        return;
    }

    bool verify = true;
    json_get_bool(readBuf, "verify", &verify);

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to create destination file: %s (error %u)\"}\n",
                  outputPath, GetLastError());
        responseText = responseBuf;
        return;
    }

    constexpr size_t kChunkSize = 65536;
    std::vector<unsigned char> chunk(kChunkSize);
    duint totalWritten = 0;
    bool readError = false;
    duint failedVa = 0;

    while (totalWritten < dumpSize)
    {
        duint remaining = dumpSize - totalWritten;
        size_t toRead = (remaining < kChunkSize) ? (size_t)remaining : kChunkSize;
        duint curVa = addr + totalWritten;

        if (!DbgMemRead(curVa, chunk.data(), toRead))
        {
            readError = true;
            failedVa = curVa;
            break;
        }

        DWORD written = 0;
        if (!WriteFile(hFile, chunk.data(), (DWORD)toRead, &written, NULL) || written != (DWORD)toRead)
        {
            CloseHandle(hFile);
            DeleteFileA(outputPath);
            responseText = "{\"error\":\"failed writing data to destination file\"}\n";
            return;
        }

        totalWritten += written;
    }

    CloseHandle(hFile);

    if (readError)
    {
        DeleteFileA(outputPath);
        sprintf_s(responseBuf, responseBufSize,
                  "{\"error\":\"unreadable memory at 0x%016llX (read failed after %llu bytes; partial output deleted)\"}\n",
                  (unsigned long long)failedVa, (unsigned long long)totalWritten);
        responseText = responseBuf;
        return;
    }

    bool isVerified = true;
    if (verify)
    {
        WIN32_FILE_ATTRIBUTE_DATA fileData = { 0 };
        if (GetFileAttributesExA(outputPath, GetFileExInfoStandard, &fileData))
        {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = fileData.nFileSizeLow;
            fileSize.HighPart = fileData.nFileSizeHigh;
            isVerified = (fileSize.QuadPart == dumpSize);
        }
        else
        {
            isVerified = false;
        }
    }

    char safePath[MAX_PATH * 2] = { 0 };
    escape_json_string(outputPath, safePath, sizeof(safePath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"address\":\"0x%016llX\",\"size\":%llu,\"output_path\":\"%s\","
              "\"bytes_written\":%llu,\"verified\":%s,\"success\":true}\n",
              (unsigned long long)addr,
              (unsigned long long)dumpSize,
              safePath,
              (unsigned long long)totalWritten,
              isVerified ? "true" : "false");
    responseText = responseBuf;
}

void handle_dump_module(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running; module dump requires paused target for consistency\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    char modParam[MAX_MODULE_SIZE] = { 0 };

    if (json_get_string(readBuf, "module", modParam, sizeof(modParam)) && modParam[0] != '\0')
    {
        base = DbgFunctions()->ModBaseFromName(modParam);
        if (base == 0)
        {
            duint parsed = DbgValFromString(modParam);
            if (parsed != 0)
            {
                base = DbgFunctions()->ModBaseFromAddr(parsed);
            }
        }
    }
    else
    {
        base = DbgValFromString("mod.main()");
    }

    if (base == 0)
    {
        responseText = "{\"error\":\"module not found in debuggee\"}\n";
        return;
    }

    DbgFunctions()->ModNameFromAddr(base, modName, true);
    duint modSize = DbgFunctions()->ModSizeFromAddr(base);
    if (modSize == 0)
    {
        responseText = "{\"error\":\"unable to determine module size in memory\"}\n";
        return;
    }

    constexpr duint kMaxModuleDumpSize = 64 * 1024 * 1024; // 64MB max
    if (modSize > kMaxModuleDumpSize)
    {
        responseText = "{\"error\":\"module size exceeds maximum dump limit of 64MB\"}\n";
        return;
    }

    char outputPath[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "output_path", outputPath, sizeof(outputPath)) || outputPath[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'output_path' parameter\"}\n";
        return;
    }

    char pathErr[256] = { 0 };
    if (!validate_safe_output_path(outputPath, pathErr, sizeof(pathErr)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", pathErr);
        responseText = responseBuf;
        return;
    }

    bool verify = true;
    json_get_bool(readBuf, "verify", &verify);

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to create destination file: %s (error %u)\"}\n",
                  outputPath, GetLastError());
        responseText = responseBuf;
        return;
    }

    // Dump module runtime memory image page by page (4096 bytes)
    constexpr size_t kPageSize = 4096;
    std::vector<unsigned char> page(kPageSize);
    std::vector<unsigned char> zeroPage(kPageSize, 0);

    duint offset = 0;
    int unreadablePages = 0;
    int totalPages = (int)((modSize + kPageSize - 1) / kPageSize);

    while (offset < modSize)
    {
        duint remaining = modSize - offset;
        size_t toRead = (remaining < kPageSize) ? (size_t)remaining : kPageSize;
        duint curVa = base + offset;

        const void* writePtr = nullptr;
        if (DbgMemRead(curVa, page.data(), toRead))
        {
            writePtr = page.data();
        }
        else
        {
            // Unmapped or discarded page in runtime image layout: zero-fill to preserve VA layout
            unreadablePages++;
            writePtr = zeroPage.data();
        }

        DWORD written = 0;
        if (!WriteFile(hFile, writePtr, (DWORD)toRead, &written, NULL) || written != (DWORD)toRead)
        {
            CloseHandle(hFile);
            DeleteFileA(outputPath);
            responseText = "{\"error\":\"failed writing module image to destination file\"}\n";
            return;
        }

        offset += written;
    }

    CloseHandle(hFile);

    bool isVerified = true;
    if (verify)
    {
        WIN32_FILE_ATTRIBUTE_DATA fileData = { 0 };
        if (GetFileAttributesExA(outputPath, GetFileExInfoStandard, &fileData))
        {
            ULARGE_INTEGER fileSize;
            fileSize.LowPart = fileData.nFileSizeLow;
            fileSize.HighPart = fileData.nFileSizeHigh;
            isVerified = (fileSize.QuadPart == modSize);
        }
        else
        {
            isVerified = false;
        }
    }

    char safePath[MAX_PATH * 2] = { 0 };
    escape_json_string(outputPath, safePath, sizeof(safePath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"size\":%llu,\"output_path\":\"%s\","
              "\"bytes_written\":%llu,\"unreadable_pages\":%d,\"total_pages\":%d,"
              "\"is_memory_image\":true,\"verified\":%s,\"success\":true}\n",
              modName,
              (unsigned long long)base,
              (unsigned long long)modSize,
              safePath,
              (unsigned long long)offset,
              unreadablePages,
              totalPages,
              isVerified ? "true" : "false");
    responseText = responseBuf;
}

void handle_create_minidump(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }
    if (DbgIsRunning())
    {
        responseText = "{\"error\":\"debuggee is running; minidump requires paused target\"}\n";
        return;
    }

    bool confirm = false;
    if (!json_get_bool(readBuf, "confirm", &confirm) || !confirm)
    {
        responseText = "{\"error\":\"Destructive / large file operation: you must set 'confirm': true to create a process minidump.\"}\n";
        return;
    }

    char outputPath[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "output_path", outputPath, sizeof(outputPath)) || outputPath[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'output_path' parameter\"}\n";
        return;
    }

    char pathErr[256] = { 0 };
    if (!validate_safe_output_path(outputPath, pathErr, sizeof(pathErr)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", pathErr);
        responseText = responseBuf;
        return;
    }

    HANDLE hFile = CreateFileA(outputPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"failed to create destination file: %s (error %u)\"}\n",
                  outputPath, GetLastError());
        responseText = responseBuf;
        return;
    }

    HANDLE hProc = DbgGetProcessHandle();
    DWORD pid = DbgGetProcessId();

    BOOL dumpOk = MiniDumpWriteDump(hProc, pid, hFile, MiniDumpNormal, NULL, NULL, NULL);
    DWORD lastErr = GetLastError();
    CloseHandle(hFile);

    if (!dumpOk)
    {
        DeleteFileA(outputPath);
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"MiniDumpWriteDump failed with error code %u\"}\n", lastErr);
        responseText = responseBuf;
        return;
    }

    unsigned long long fileSizeVal = 0;
    WIN32_FILE_ATTRIBUTE_DATA fileData = { 0 };
    if (GetFileAttributesExA(outputPath, GetFileExInfoStandard, &fileData))
    {
        ULARGE_INTEGER uli;
        uli.LowPart = fileData.nFileSizeLow;
        uli.HighPart = fileData.nFileSizeHigh;
        fileSizeVal = uli.QuadPart;
    }

    char safePath[MAX_PATH * 2] = { 0 };
    escape_json_string(outputPath, safePath, sizeof(safePath));

    sprintf_s(responseBuf, responseBufSize,
              "{\"pid\":%u,\"output_path\":\"%s\",\"file_size\":%llu,\"dump_type\":\"MiniDumpNormal\",\"verified\":true,\"success\":true}\n",
              pid, safePath, fileSizeVal);
    responseText = responseBuf;
}
