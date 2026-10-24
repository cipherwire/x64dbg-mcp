#include "pe_metadata.h"
#include <vector>
#include <algorithm>

#ifndef _WIN64
// Fallback definition for 32-bit builds; x64 PE exception directory structures
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    union {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    };
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#endif

// --------------------------------------------------------------------------
// PE Header Parsing Helper
// --------------------------------------------------------------------------

struct PeHeaderInfo
{
    duint base;
    char moduleName[MAX_MODULE_SIZE];
    bool is64;
    WORD machine;
    WORD numberOfSections;
    DWORD timestamp;
    WORD characteristics;
    WORD optMagic;
    duint entryPointRva;
    duint entryPointVa;
    ULONGLONG imageBase;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    WORD subsystem;
    WORD dllCharacteristics;
    DWORD numberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY dataDirectories[16];
};

static bool resolve_target_module(const char* readBuf, duint& base, char* modName, size_t modNameSize)
{
    base = 0;
    modName[0] = '\0';

    char modParam[MAX_MODULE_SIZE] = { 0 };
    char addrParam[MAX_PATH] = { 0 };
    bool hasMod = json_get_string(readBuf, "module", modParam, sizeof(modParam)) && modParam[0] != '\0';
    bool hasAddr = json_get_string(readBuf, "address", addrParam, sizeof(addrParam)) && addrParam[0] != '\0';

    if (hasMod)
    {
        base = DbgFunctions()->ModBaseFromName(modParam);
        if (base == 0)
        {
            duint parsedAddr = DbgValFromString(modParam);
            if (parsedAddr != 0)
            {
                base = DbgFunctions()->ModBaseFromAddr(parsedAddr);
            }
        }
    }
    else if (hasAddr)
    {
        duint parsedAddr = DbgValFromString(addrParam);
        if (parsedAddr != 0)
        {
            base = DbgFunctions()->ModBaseFromAddr(parsedAddr);
        }
    }
    else
    {
        base = DbgValFromString("mod.main()");
    }

    if (base == 0)
    {
        return false;
    }

    if (!DbgFunctions()->ModNameFromAddr(base, modName, true) || modName[0] == '\0')
    {
        strncpy_s(modName, modNameSize, "unknown", _TRUNCATE);
    }
    return true;
}

static bool parse_pe_headers(duint base, PeHeaderInfo& info, char* errBuf, size_t errBufSize)
{
    memset(&info, 0, sizeof(info));
    info.base = base;

    IMAGE_DOS_HEADER dos = { 0 };
    if (!DbgMemRead(base, &dos, sizeof(dos)))
    {
        sprintf_s(errBuf, errBufSize, "failed to read DOS header at 0x%016llX", (unsigned long long)base);
        return false;
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        sprintf_s(errBuf, errBufSize, "invalid DOS signature 0x%04X (expected 0x5A4D)", dos.e_magic);
        return false;
    }

    if (dos.e_lfanew <= 0 || (duint)dos.e_lfanew > 0x10000000)
    {
        sprintf_s(errBuf, errBufSize, "invalid e_lfanew offset 0x%X in DOS header", dos.e_lfanew);
        return false;
    }

    duint ntAddr = base + dos.e_lfanew;
    DWORD ntSig = 0;
    if (!DbgMemRead(ntAddr, &ntSig, sizeof(ntSig)))
    {
        sprintf_s(errBuf, errBufSize, "failed to read NT signature at 0x%016llX", (unsigned long long)ntAddr);
        return false;
    }

    if (ntSig != IMAGE_NT_SIGNATURE)
    {
        sprintf_s(errBuf, errBufSize, "invalid NT signature 0x%08X (expected 0x00004550)", ntSig);
        return false;
    }

    IMAGE_FILE_HEADER fileHdr = { 0 };
    if (!DbgMemRead(ntAddr + 4, &fileHdr, sizeof(fileHdr)))
    {
        sprintf_s(errBuf, errBufSize, "failed to read COFF file header");
        return false;
    }

    info.machine = fileHdr.Machine;
    info.numberOfSections = fileHdr.NumberOfSections;
    info.timestamp = fileHdr.TimeDateStamp;
    info.characteristics = fileHdr.Characteristics;

    duint optAddr = ntAddr + 4 + sizeof(IMAGE_FILE_HEADER);
    WORD optMagic = 0;
    if (!DbgMemRead(optAddr, &optMagic, sizeof(optMagic)))
    {
        sprintf_s(errBuf, errBufSize, "failed to read optional header magic");
        return false;
    }

    info.optMagic = optMagic;
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        info.is64 = true;
        IMAGE_OPTIONAL_HEADER64 opt64 = { 0 };
        if (!DbgMemRead(optAddr, &opt64, sizeof(opt64)))
        {
            sprintf_s(errBuf, errBufSize, "failed to read IMAGE_OPTIONAL_HEADER64");
            return false;
        }

        info.entryPointRva = opt64.AddressOfEntryPoint;
        info.entryPointVa = base + opt64.AddressOfEntryPoint;
        info.imageBase = opt64.ImageBase;
        info.sizeOfImage = opt64.SizeOfImage;
        info.sizeOfHeaders = opt64.SizeOfHeaders;
        info.sectionAlignment = opt64.SectionAlignment;
        info.fileAlignment = opt64.FileAlignment;
        info.subsystem = opt64.Subsystem;
        info.dllCharacteristics = opt64.DllCharacteristics;
        info.numberOfRvaAndSizes = opt64.NumberOfRvaAndSizes;

        DWORD copyDirs = (opt64.NumberOfRvaAndSizes < 16) ? opt64.NumberOfRvaAndSizes : 16;
        for (DWORD i = 0; i < copyDirs; i++)
        {
            info.dataDirectories[i] = opt64.DataDirectory[i];
        }
    }
    else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        info.is64 = false;
        IMAGE_OPTIONAL_HEADER32 opt32 = { 0 };
        if (!DbgMemRead(optAddr, &opt32, sizeof(opt32)))
        {
            sprintf_s(errBuf, errBufSize, "failed to read IMAGE_OPTIONAL_HEADER32");
            return false;
        }

        info.entryPointRva = opt32.AddressOfEntryPoint;
        info.entryPointVa = base + opt32.AddressOfEntryPoint;
        info.imageBase = opt32.ImageBase;
        info.sizeOfImage = opt32.SizeOfImage;
        info.sizeOfHeaders = opt32.SizeOfHeaders;
        info.sectionAlignment = opt32.SectionAlignment;
        info.fileAlignment = opt32.FileAlignment;
        info.subsystem = opt32.Subsystem;
        info.dllCharacteristics = opt32.DllCharacteristics;
        info.numberOfRvaAndSizes = opt32.NumberOfRvaAndSizes;

        DWORD copyDirs = (opt32.NumberOfRvaAndSizes < 16) ? opt32.NumberOfRvaAndSizes : 16;
        for (DWORD i = 0; i < copyDirs; i++)
        {
            info.dataDirectories[i] = opt32.DataDirectory[i];
        }
    }
    else
    {
        sprintf_s(errBuf, errBufSize, "unrecognized optional header magic 0x%04X", optMagic);
        return false;
    }

    return true;
}

// --------------------------------------------------------------------------
// Part A - PE Image Metadata
// --------------------------------------------------------------------------

void handle_get_pe_headers(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    PeHeaderInfo info = { 0 };
    char errBuf[256] = { 0 };
    if (!parse_pe_headers(base, info, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"architecture\":\"%s\","
              "\"dos_signature\":\"0x5A4D\",\"nt_signature\":\"0x00004550\","
              "\"machine\":\"0x%04X\",\"number_of_sections\":%u,\"timestamp\":%u,"
              "\"characteristics\":\"0x%04X\",\"optional_magic\":\"0x%04X\","
              "\"file_image_base\":\"0x%016llX\",\"runtime_base\":\"0x%016llX\","
              "\"entry_point_rva\":\"0x%08X\",\"entry_point_va\":\"0x%016llX\","
              "\"size_of_image\":%u,\"size_of_headers\":%u,"
              "\"section_alignment\":%u,\"file_alignment\":%u,"
              "\"subsystem\":%u,\"dll_characteristics\":\"0x%04X\","
              "\"number_of_rva_and_sizes\":%u,\"success\":true}\n",
              modName,
              (unsigned long long)base,
              info.is64 ? "x64" : "x86",
              info.machine,
              (unsigned int)info.numberOfSections,
              (unsigned int)info.timestamp,
              info.characteristics,
              info.optMagic,
              (unsigned long long)info.imageBase,
              (unsigned long long)base,
              (unsigned int)info.entryPointRva,
              (unsigned long long)info.entryPointVa,
              info.sizeOfImage,
              info.sizeOfHeaders,
              info.sectionAlignment,
              info.fileAlignment,
              (unsigned int)info.subsystem,
              info.dllCharacteristics,
              info.numberOfRvaAndSizes);
    responseText = responseBuf;
}

static const char* s_dataDirNames[16] = {
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR_RUNTIME_HEADER",
    "RESERVED"
};

void handle_list_pe_data_directories(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    PeHeaderInfo info = { 0 };
    char errBuf[256] = { 0 };
    if (!parse_pe_headers(base, info, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"directories\":[",
                        modName, (unsigned long long)base);

    for (DWORD i = 0; i < 16; i++)
    {
        DWORD rva = info.dataDirectories[i].VirtualAddress;
        DWORD size = info.dataDirectories[i].Size;
        bool present = (rva != 0 && size != 0);
        duint va = present ? (base + rva) : 0;

        char itemBuf[256] = { 0 };
        int itemLen = sprintf_s(itemBuf, sizeof(itemBuf),
                                "%s{\"index\":%u,\"name\":\"%s\",\"rva\":\"0x%08X\",\"size\":%u,\"va\":\"0x%016llX\",\"present\":%s}",
                                (i > 0) ? "," : "",
                                (unsigned int)i,
                                s_dataDirNames[i],
                                rva,
                                size,
                                (unsigned long long)va,
                                present ? "true" : "false");

        if ((size_t)pos + itemLen + 32 >= responseBufSize)
        {
            break;
        }
        memcpy(responseBuf + pos, itemBuf, itemLen);
        pos += itemLen;
    }

    pos += sprintf_s(responseBuf + pos, responseBufSize - pos, "],\"success\":true}\n");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Part B - TLS / Unwind Metadata
// --------------------------------------------------------------------------

void handle_list_tls_callbacks(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    PeHeaderInfo info = { 0 };
    char errBuf[256] = { 0 };
    if (!parse_pe_headers(base, info, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    DWORD tlsRva = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsSize = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    if (tlsRva == 0 || tlsSize == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"has_tls_directory\":false,\"callback_count\":0,\"callbacks\":[],\"success\":true}\n",
                  modName, (unsigned long long)base);
        responseText = responseBuf;
        return;
    }

    duint callbacksArrayVa = 0;
    if (info.is64)
    {
        IMAGE_TLS_DIRECTORY64 tls64 = { 0 };
        if (!DbgMemRead(base + tlsRva, &tls64, sizeof(tls64)))
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"has_tls_directory\":true,\"error\":\"failed to read TLS directory\",\"callback_count\":0,\"callbacks\":[]}\n",
                      modName, (unsigned long long)base);
            responseText = responseBuf;
            return;
        }
        callbacksArrayVa = (duint)tls64.AddressOfCallBacks;
    }
    else
    {
        IMAGE_TLS_DIRECTORY32 tls32 = { 0 };
        if (!DbgMemRead(base + tlsRva, &tls32, sizeof(tls32)))
        {
            sprintf_s(responseBuf, responseBufSize,
                      "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"has_tls_directory\":true,\"error\":\"failed to read TLS directory\",\"callback_count\":0,\"callbacks\":[]}\n",
                      modName, (unsigned long long)base);
            responseText = responseBuf;
            return;
        }
        callbacksArrayVa = (duint)tls32.AddressOfCallBacks;
    }

    if (callbacksArrayVa == 0 || !DbgMemIsValidReadPtr(callbacksArrayVa))
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"has_tls_directory\":true,\"callback_count\":0,\"callbacks\":[],\"success\":true}\n",
                  modName, (unsigned long long)base);
        responseText = responseBuf;
        return;
    }

    constexpr int kMaxTlsCallbacks = 256;
    std::vector<duint> callbackAddresses;

    size_t ptrSize = info.is64 ? 8 : 4;
    for (int i = 0; i < kMaxTlsCallbacks; i++)
    {
        duint cbVa = 0;
        if (info.is64)
        {
            unsigned long long val = 0;
            if (!DbgMemRead(callbacksArrayVa + (duint)i * ptrSize, &val, ptrSize))
            {
                break;
            }
            cbVa = (duint)val;
        }
        else
        {
            unsigned int val = 0;
            if (!DbgMemRead(callbacksArrayVa + (duint)i * ptrSize, &val, ptrSize))
            {
                break;
            }
            cbVa = (duint)val;
        }

        if (cbVa == 0)
        {
            break; // Null terminator
        }
        callbackAddresses.push_back(cbVa);
    }

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"has_tls_directory\":true,\"callback_count\":%d,\"callbacks\":[",
                        modName, (unsigned long long)base, (int)callbackAddresses.size());

    for (size_t i = 0; i < callbackAddresses.size(); i++)
    {
        duint va = callbackAddresses[i];
        duint rva = (va >= base) ? (va - base) : 0;
        char labelBuf[MAX_LABEL_SIZE] = { 0 };
        char escapedLabel[MAX_LABEL_SIZE * 2] = { 0 };
        if (DbgGetLabelAt(va, SEG_DEFAULT, labelBuf))
        {
            escape_json_string(labelBuf, escapedLabel, sizeof(escapedLabel));
        }

        char itemBuf[512] = { 0 };
        int itemLen = sprintf_s(itemBuf, sizeof(itemBuf),
                                "%s{\"index\":%u,\"va\":\"0x%016llX\",\"rva\":\"0x%08X\",\"symbol\":\"%s\"}",
                                (i > 0) ? "," : "",
                                (unsigned int)i,
                                (unsigned long long)va,
                                (unsigned int)rva,
                                escapedLabel);

        if ((size_t)pos + itemLen + 32 >= responseBufSize)
        {
            break;
        }
        memcpy(responseBuf + pos, itemBuf, itemLen);
        pos += itemLen;
    }

    pos += sprintf_s(responseBuf + pos, responseBufSize - pos, "],\"success\":true}\n");
    responseText = responseBuf;
}

void handle_get_runtime_function(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    char addrStr[MAX_PATH] = { 0 };
    if (!json_get_string(readBuf, "address", addrStr, sizeof(addrStr)) || addrStr[0] == '\0')
    {
        responseText = "{\"error\":\"missing or empty 'address' parameter\"}\n";
        return;
    }

    duint targetAddr = DbgValFromString(addrStr);
    if (targetAddr == 0)
    {
        responseText = "{\"error\":\"invalid address expression\"}\n";
        return;
    }

    duint base = DbgFunctions()->ModBaseFromAddr(targetAddr);
    if (base == 0)
    {
        responseText = "{\"error\":\"address does not belong to any loaded module\"}\n";
        return;
    }

    char modName[MAX_MODULE_SIZE] = { 0 };
    DbgFunctions()->ModNameFromAddr(base, modName, true);

    PeHeaderInfo info = { 0 };
    char errBuf[256] = { 0 };
    if (!parse_pe_headers(base, info, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    if (!info.is64)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"address\":\"0x%016llX\",\"supported\":false,\"found\":false,\"reason\":\"PE Exception Directory RUNTIME_FUNCTION is only present in x64 modules\"}\n",
                  modName, (unsigned long long)targetAddr);
        responseText = responseBuf;
        return;
    }

    DWORD pdataRva = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdataSize = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (pdataRva == 0 || pdataSize == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"address\":\"0x%016llX\",\"found\":false,\"reason\":\"module has no exception directory\"}\n",
                  modName, (unsigned long long)targetAddr);
        responseText = responseBuf;
        return;
    }

    size_t count = pdataSize / sizeof(RUNTIME_FUNCTION);
    DWORD targetRva = (DWORD)(targetAddr - base);

    // Binary search in the sorted .pdata table
    int low = 0;
    int high = (int)count - 1;
    bool found = false;
    RUNTIME_FUNCTION match = { 0 };

    while (low <= high)
    {
        int mid = low + (high - low) / 2;
        duint entryVa = base + pdataRva + (duint)mid * sizeof(RUNTIME_FUNCTION);
        RUNTIME_FUNCTION cur = { 0 };
        if (!DbgMemRead(entryVa, &cur, sizeof(cur)))
        {
            break;
        }

        if (targetRva >= cur.BeginAddress && targetRva < cur.EndAddress)
        {
            match = cur;
            found = true;
            break;
        }
        else if (targetRva < cur.BeginAddress)
        {
            high = mid - 1;
        }
        else
        {
            low = mid + 1;
        }
    }

    if (!found)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"address\":\"0x%016llX\",\"found\":false,\"success\":true}\n",
                  modName, (unsigned long long)targetAddr);
        responseText = responseBuf;
        return;
    }

    DWORD unwindRva = match.UnwindData;
    duint unwindVa = base + unwindRva;
    BYTE unwindHdr = 0;
    bool isChained = false;
    if (DbgMemRead(unwindVa, &unwindHdr, 1))
    {
        BYTE flags = (unwindHdr >> 3) & 0x1F;
        isChained = (flags & 0x04) != 0; // UNW_FLAG_CHAININFO
    }

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"address\":\"0x%016llX\",\"found\":true,"
              "\"begin_rva\":\"0x%08X\",\"end_rva\":\"0x%08X\","
              "\"begin_va\":\"0x%016llX\",\"end_va\":\"0x%016llX\","
              "\"function_size\":%u,\"unwind_info_rva\":\"0x%08X\","
              "\"unwind_info_va\":\"0x%016llX\",\"is_chained\":%s,\"success\":true}\n",
              modName,
              (unsigned long long)targetAddr,
              match.BeginAddress,
              match.EndAddress,
              (unsigned long long)(base + match.BeginAddress),
              (unsigned long long)(base + match.EndAddress),
              match.EndAddress - match.BeginAddress,
              unwindRva,
              (unsigned long long)unwindVa,
              isChained ? "true" : "false");
    responseText = responseBuf;
}

void handle_list_runtime_functions(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    int offset = 0;
    int limit = 50;
    json_get_int(readBuf, "offset", &offset);
    json_get_int(readBuf, "limit", &limit);
    if (offset < 0) offset = 0;
    if (limit <= 0) limit = 50;
    if (limit > 500) limit = 500;

    PeHeaderInfo info = { 0 };
    char errBuf[256] = { 0 };
    if (!parse_pe_headers(base, info, errBuf, sizeof(errBuf)))
    {
        sprintf_s(responseBuf, responseBufSize, "{\"error\":\"%s\"}\n", errBuf);
        responseText = responseBuf;
        return;
    }

    if (!info.is64)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"supported\":false,\"total_count\":0,\"functions\":[],\"reason\":\"PE Exception Directory RUNTIME_FUNCTION is only present in x64 modules\"}\n",
                  modName, (unsigned long long)base);
        responseText = responseBuf;
        return;
    }

    DWORD pdataRva = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD pdataSize = info.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (pdataRva == 0 || pdataSize == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
                  "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"total_count\":0,\"offset\":%d,\"limit\":%d,\"functions\":[],\"success\":true}\n",
                  modName, (unsigned long long)base, offset, limit);
        responseText = responseBuf;
        return;
    }

    int totalCount = (int)(pdataSize / sizeof(RUNTIME_FUNCTION));
    int startIdx = (offset < totalCount) ? offset : totalCount;
    int endIdx = (startIdx + limit < totalCount) ? (startIdx + limit) : totalCount;

    int pos = sprintf_s(responseBuf, responseBufSize,
                        "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"total_count\":%d,\"offset\":%d,\"limit\":%d,\"functions\":[",
                        modName, (unsigned long long)base, totalCount, offset, limit);

    for (int i = startIdx; i < endIdx; i++)
    {
        duint entryVa = base + pdataRva + (duint)i * sizeof(RUNTIME_FUNCTION);
        RUNTIME_FUNCTION fn = { 0 };
        if (!DbgMemRead(entryVa, &fn, sizeof(fn)))
        {
            break;
        }

        duint unwindVa = base + fn.UnwindData;
        BYTE unwindHdr = 0;
        bool isChained = false;
        if (DbgMemRead(unwindVa, &unwindHdr, 1))
        {
            BYTE flags = (unwindHdr >> 3) & 0x1F;
            isChained = (flags & 0x04) != 0;
        }

        char itemBuf[384] = { 0 };
        int itemLen = sprintf_s(itemBuf, sizeof(itemBuf),
                                "%s{\"index\":%d,\"begin_rva\":\"0x%08X\",\"end_rva\":\"0x%08X\","
                                "\"begin_va\":\"0x%016llX\",\"end_va\":\"0x%016llX\","
                                "\"unwind_info_rva\":\"0x%08X\",\"unwind_info_va\":\"0x%016llX\",\"is_chained\":%s}",
                                (i > startIdx) ? "," : "",
                                i,
                                fn.BeginAddress,
                                fn.EndAddress,
                                (unsigned long long)(base + fn.BeginAddress),
                                (unsigned long long)(base + fn.EndAddress),
                                fn.UnwindData,
                                (unsigned long long)unwindVa,
                                isChained ? "true" : "false");

        if ((size_t)pos + itemLen + 32 >= responseBufSize)
        {
            break;
        }
        memcpy(responseBuf + pos, itemBuf, itemLen);
        pos += itemLen;
    }

    pos += sprintf_s(responseBuf + pos, responseBufSize - pos, "],\"success\":true}\n");
    responseText = responseBuf;
}

// --------------------------------------------------------------------------
// Explicit Investigation - Module Party (User vs System)
// --------------------------------------------------------------------------

void handle_get_module_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    MODULEPARTY party = DbgFunctions()->ModGetParty(base);
    const char* partyStr = (party == mod_user) ? "user" : "system";

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"party\":\"%s\",\"party_code\":%d,\"success\":true}\n",
              modName, (unsigned long long)base, partyStr, (int)party);
    responseText = responseBuf;
}

void handle_set_module_party(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    if (!DbgIsDebugging())
    {
        responseText = "{\"error\":\"no debuggee active\"}\n";
        return;
    }

    duint base = 0;
    char modName[MAX_MODULE_SIZE] = { 0 };
    if (!resolve_target_module(readBuf, base, modName, sizeof(modName)))
    {
        responseText = "{\"error\":\"module or address not found in debuggee\"}\n";
        return;
    }

    MODULEPARTY targetParty = mod_user;
    bool partyParsed = false;

    int partyInt = 0;
    if (json_get_int(readBuf, "party", &partyInt))
    {
        if (partyInt == 0)
        {
            targetParty = mod_user;
            partyParsed = true;
        }
        else if (partyInt == 1)
        {
            targetParty = mod_system;
            partyParsed = true;
        }
    }
    else
    {
        char partyStr[32] = { 0 };
        if (json_get_string(readBuf, "party", partyStr, sizeof(partyStr)) && partyStr[0] != '\0')
        {
            if (_stricmp(partyStr, "user") == 0 || strcmp(partyStr, "0") == 0)
            {
                targetParty = mod_user;
                partyParsed = true;
            }
            else if (_stricmp(partyStr, "system") == 0 || strcmp(partyStr, "1") == 0)
            {
                targetParty = mod_system;
                partyParsed = true;
            }
        }
    }

    if (!partyParsed)
    {
        responseText = "{\"error\":{\"code\":\"invalid_argument\",\"message\":\"Invalid 'party' parameter; must be 'user' (0) or 'system' (1)\"}}\n";
        return;
    }

    DbgFunctions()->ModSetParty(base, targetParty);

    MODULEPARTY postParty = DbgFunctions()->ModGetParty(base);
    const char* postPartyStr = (postParty == mod_user) ? "user" : "system";

    sprintf_s(responseBuf, responseBufSize,
              "{\"module\":\"%s\",\"base\":\"0x%016llX\",\"party\":\"%s\",\"party_code\":%d,\"success\":true}\n",
              modName, (unsigned long long)base, postPartyStr, (int)postParty);
    responseText = responseBuf;
}

