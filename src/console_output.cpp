#include "console_output.h"
#include "console_input.h"
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>

namespace
{
    class ConsoleLockGuard
    {
    public:
        ConsoleLockGuard() { console_lock_acquire(); }
        ~ConsoleLockGuard() { console_lock_release(); }
        ConsoleLockGuard(const ConsoleLockGuard&) = delete;
        ConsoleLockGuard& operator=(const ConsoleLockGuard&) = delete;
    };

    class ConsoleAttachmentGuard
    {
    public:
        explicit ConsoleAttachmentGuard(DWORD pid)
            : m_hOrigWnd(GetConsoleWindow()), m_attached(false), m_lastError(0)
        {
            FreeConsole();
            if (AttachConsole(pid))
            {
                m_attached = true;
            }
            else
            {
                m_lastError = GetLastError();
                if (m_hOrigWnd != NULL)
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                }
            }
        }

        ~ConsoleAttachmentGuard()
        {
            if (m_attached)
            {
                FreeConsole();
                if (m_hOrigWnd != NULL)
                {
                    AttachConsole(ATTACH_PARENT_PROCESS);
                }
            }
        }

        bool is_attached() const { return m_attached; }
        DWORD last_error() const { return m_lastError; }

    private:
        HWND m_hOrigWnd;
        bool m_attached;
        DWORD m_lastError;
    };

    void append_json_escaped(std::string& out, const std::string& s)
    {
        for (size_t i = 0; i < s.size(); ++i)
        {
            unsigned char c = (unsigned char)s[i];
            switch (c)
            {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20)
                {
                    char ubuf[8];
                    sprintf_s(ubuf, sizeof(ubuf), "\\u%04x", (unsigned int)c);
                    out += ubuf;
                }
                else
                {
                    out += (char)c;
                }
                break;
            }
        }
    }
}

void handle_read_console_output(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    int explicitPid = 0;
    bool hasPid = json_get_int(readBuf, "pid", &explicitPid);

    DWORD targetPid = 0;
    if (hasPid && explicitPid > 0)
    {
        targetPid = (DWORD)explicitPid;
    }
    else
    {
        if (!DbgIsDebugging())
        {
            sprintf_s(responseBuf, responseBufSize,
                "{\"success\":false,\"error\":\"no_debuggee\",\"message\":\"No active debuggee process\"}\n");
            responseText = responseBuf;
            return;
        }
        targetPid = DbgGetProcessId();
    }

    if (targetPid == 0)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"no_debuggee\",\"message\":\"Unable to resolve debuggee process ID\"}\n");
        responseText = responseBuf;
        return;
    }

    int maxLines = 50;
    json_get_int(readBuf, "max_lines", &maxLines);
    if (maxLines < 1) maxLines = 1;
    if (maxLines > 1000) maxLines = 1000;

    bool visibleOnly = false;
    json_get_bool(readBuf, "visible_only", &visibleOnly);

    bool includeEmpty = false;
    json_get_bool(readBuf, "include_empty", &includeEmpty);

    ConsoleLockGuard lockGuard;
    ConsoleAttachmentGuard attachGuard(targetPid);

    if (!attachGuard.is_attached())
    {
        DWORD dwErr = attachGuard.last_error();
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"debuggee_not_console_attached\","
            "\"win32_error\":%lu,\"message\":\"Failed to attach to target console (PID %lu)\"}\n",
            dwErr, targetPid);
        responseText = responseBuf;
        return;
    }

    HANDLE hConOut = CreateFileW(
        L"CONOUT$",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hConOut == INVALID_HANDLE_VALUE)
    {
        DWORD dwErr = GetLastError();
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"stdout_unavailable\","
            "\"win32_error\":%lu,\"message\":\"Failed to open CONOUT$ for target console\"}\n",
            dwErr);
        responseText = responseBuf;
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
    if (!GetConsoleScreenBufferInfo(hConOut, &csbi))
    {
        DWORD dwErr = GetLastError();
        CloseHandle(hConOut);
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"buffer_info_failed\","
            "\"win32_error\":%lu,\"message\":\"GetConsoleScreenBufferInfo failed\"}\n",
            dwErr);
        responseText = responseBuf;
        return;
    }

    SHORT width = csbi.dwSize.X;
    SHORT totalHeight = csbi.dwSize.Y;
    SHORT startRow = 0;
    SHORT endRow = 0;

    if (visibleOnly)
    {
        startRow = csbi.srWindow.Top;
        endRow = csbi.srWindow.Bottom;
        if (startRow < 0) startRow = 0;
        if (endRow >= totalHeight) endRow = totalHeight - 1;
    }
    else
    {
        SHORT activeBottom = csbi.dwCursorPosition.Y;
        if (csbi.srWindow.Bottom > activeBottom)
        {
            activeBottom = csbi.srWindow.Bottom;
        }
        if (activeBottom >= totalHeight)
        {
            activeBottom = totalHeight - 1;
        }

        SHORT count = (SHORT)maxLines;
        if (count > activeBottom + 1)
        {
            count = activeBottom + 1;
        }
        startRow = (activeBottom + 1) - count;
        endRow = activeBottom;
    }

    std::vector<std::string> lines;
    if (width > 0 && startRow <= endRow)
    {
        std::vector<wchar_t> lineChars((size_t)width + 1, L'\0');
        for (SHORT r = startRow; r <= endRow; ++r)
        {
            COORD coord = { 0, r };
            DWORD charsRead = 0;
            if (ReadConsoleOutputCharacterW(hConOut, lineChars.data(), (DWORD)width, coord, &charsRead))
            {
                while (charsRead > 0 && (lineChars[charsRead - 1] == L' ' || lineChars[charsRead - 1] == L'\t' || lineChars[charsRead - 1] == L'\0'))
                {
                    charsRead--;
                }
                lineChars[charsRead] = L'\0';

                std::string utf8Line;
                if (charsRead > 0)
                {
                    int needed = WideCharToMultiByte(CP_UTF8, 0, lineChars.data(), (int)charsRead, NULL, 0, NULL, NULL);
                    if (needed > 0)
                    {
                        utf8Line.resize((size_t)needed);
                        WideCharToMultiByte(CP_UTF8, 0, lineChars.data(), (int)charsRead, &utf8Line[0], needed, NULL, NULL);
                    }
                }
                lines.push_back(std::move(utf8Line));
            }
            else
            {
                lines.push_back("");
            }
        }
    }

    CloseHandle(hConOut);

    if (!includeEmpty)
    {
        while (!lines.empty() && lines.back().empty())
        {
            lines.pop_back();
        }
    }

    static thread_local std::string s_responseStr;
    s_responseStr.clear();
    s_responseStr.reserve(4096);

    char numBuf[128];
    s_responseStr += "{\"success\":true,";
    sprintf_s(numBuf, sizeof(numBuf), "\"pid\":%lu,", targetPid);
    s_responseStr += numBuf;
    sprintf_s(numBuf, sizeof(numBuf), "\"cursor_position\":{\"x\":%d,\"y\":%d},", (int)csbi.dwCursorPosition.X, (int)csbi.dwCursorPosition.Y);
    s_responseStr += numBuf;
    sprintf_s(numBuf, sizeof(numBuf), "\"buffer_size\":{\"width\":%d,\"height\":%d},", (int)csbi.dwSize.X, (int)csbi.dwSize.Y);
    s_responseStr += numBuf;
    sprintf_s(numBuf, sizeof(numBuf), "\"window_rect\":{\"left\":%d,\"top\":%d,\"right\":%d,\"bottom\":%d},",
        (int)csbi.srWindow.Left, (int)csbi.srWindow.Top, (int)csbi.srWindow.Right, (int)csbi.srWindow.Bottom);
    s_responseStr += numBuf;
    sprintf_s(numBuf, sizeof(numBuf), "\"line_count\":%zu,", lines.size());
    s_responseStr += numBuf;

    s_responseStr += "\"lines\":[";
    for (size_t i = 0; i < lines.size(); ++i)
    {
        if (i > 0) s_responseStr += ",";
        s_responseStr += "\"";
        append_json_escaped(s_responseStr, lines[i]);
        s_responseStr += "\"";
    }
    s_responseStr += "],";

    s_responseStr += "\"text\":\"";
    for (size_t i = 0; i < lines.size(); ++i)
    {
        if (i > 0) s_responseStr += "\\n";
        append_json_escaped(s_responseStr, lines[i]);
    }
    s_responseStr += "\"}\n";

    responseText = s_responseStr.c_str();
}
