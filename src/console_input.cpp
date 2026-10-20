#include "console_input.h"

static SRWLOCK g_consoleLock = SRWLOCK_INIT;

void console_lock_acquire()
{
    AcquireSRWLockExclusive(&g_consoleLock);
}

void console_lock_release()
{
    ReleaseSRWLockExclusive(&g_consoleLock);
}

void handle_send_console_input(const char* readBuf, char* responseBuf, size_t responseBufSize, const char*& responseText)
{
    char textBuf[4096] = { 0 };
    if (!json_get_string(readBuf, "text", textBuf, sizeof(textBuf)))
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"missing_argument\",\"message\":\"Missing required 'text' parameter\"}\n");
        responseText = responseBuf;
        return;
    }

    bool sendEnter = true;
    json_get_bool(readBuf, "send_enter", &sendEnter);

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

    AcquireSRWLockExclusive(&g_consoleLock);

    HWND hOrigConsoleWnd = GetConsoleWindow();

    // Detach from any existing console before attaching to target
    FreeConsole();

    if (!AttachConsole(targetPid))
    {
        DWORD dwErr = GetLastError();
        if (hOrigConsoleWnd != NULL)
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
        ReleaseSRWLockExclusive(&g_consoleLock);

        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"debuggee_not_console_attached\","
            "\"win32_error\":%lu,\"message\":\"Failed to attach to target console (PID %lu)\"}\n",
            dwErr, targetPid);
        responseText = responseBuf;
        return;
    }

    HANDLE hConIn = CreateFileW(
        L"CONIN$",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hConIn == INVALID_HANDLE_VALUE)
    {
        DWORD dwErr = GetLastError();
        FreeConsole();
        if (hOrigConsoleWnd != NULL)
        {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
        ReleaseSRWLockExclusive(&g_consoleLock);

        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"stdin_unavailable\","
            "\"win32_error\":%lu,\"message\":\"Failed to open CONIN$ for target console\"}\n",
            dwErr);
        responseText = responseBuf;
        return;
    }

    int wLen = MultiByteToWideChar(CP_UTF8, 0, textBuf, -1, NULL, 0);
    std::vector<wchar_t> wBuf;
    if (wLen > 1)
    {
        wBuf.resize(wLen);
        MultiByteToWideChar(CP_UTF8, 0, textBuf, -1, wBuf.data(), wLen);
    }

    std::vector<INPUT_RECORD> records;
    size_t charCount = 0;

    if (!wBuf.empty() && wLen > 1)
    {
        for (size_t i = 0; i < (size_t)(wLen - 1); ++i)
        {
            wchar_t wc = wBuf[i];
            SHORT vk = VkKeyScanW(wc);
            WORD vkey = (vk != -1) ? (WORD)(vk & 0xFF) : 0;
            WORD vscan = (WORD)MapVirtualKeyW(vkey, MAPVK_VK_TO_VSC);
            DWORD ctrl = 0;
            if (vk != -1)
            {
                if (vk & 0x0100) ctrl |= SHIFT_PRESSED;
                if (vk & 0x0200) ctrl |= LEFT_CTRL_PRESSED;
                if (vk & 0x0400) ctrl |= LEFT_ALT_PRESSED;
            }

            INPUT_RECORD recDown = { 0 };
            recDown.EventType = KEY_EVENT;
            recDown.Event.KeyEvent.bKeyDown = TRUE;
            recDown.Event.KeyEvent.wRepeatCount = 1;
            recDown.Event.KeyEvent.wVirtualKeyCode = vkey;
            recDown.Event.KeyEvent.wVirtualScanCode = vscan;
            recDown.Event.KeyEvent.uChar.UnicodeChar = wc;
            recDown.Event.KeyEvent.dwControlKeyState = ctrl;
            records.push_back(recDown);

            INPUT_RECORD recUp = { 0 };
            recUp.EventType = KEY_EVENT;
            recUp.Event.KeyEvent.bKeyDown = FALSE;
            recUp.Event.KeyEvent.wRepeatCount = 1;
            recUp.Event.KeyEvent.wVirtualKeyCode = vkey;
            recUp.Event.KeyEvent.wVirtualScanCode = vscan;
            recUp.Event.KeyEvent.uChar.UnicodeChar = wc;
            recUp.Event.KeyEvent.dwControlKeyState = ctrl;
            records.push_back(recUp);

            charCount++;
        }
    }

    if (sendEnter)
    {
        INPUT_RECORD recDown = { 0 };
        recDown.EventType = KEY_EVENT;
        recDown.Event.KeyEvent.bKeyDown = TRUE;
        recDown.Event.KeyEvent.wRepeatCount = 1;
        recDown.Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        recDown.Event.KeyEvent.wVirtualScanCode = (WORD)MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC);
        recDown.Event.KeyEvent.uChar.UnicodeChar = L'\r';
        recDown.Event.KeyEvent.dwControlKeyState = 0;
        records.push_back(recDown);

        INPUT_RECORD recUp = { 0 };
        recUp.EventType = KEY_EVENT;
        recUp.Event.KeyEvent.bKeyDown = FALSE;
        recUp.Event.KeyEvent.wRepeatCount = 1;
        recUp.Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
        recUp.Event.KeyEvent.wVirtualScanCode = (WORD)MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC);
        recUp.Event.KeyEvent.uChar.UnicodeChar = L'\r';
        recUp.Event.KeyEvent.dwControlKeyState = 0;
        records.push_back(recUp);

        charCount++;
    }

    DWORD recordsWritten = 0;
    BOOL bWriteOk = TRUE;
    if (!records.empty())
    {
        bWriteOk = WriteConsoleInputW(hConIn, records.data(), (DWORD)records.size(), &recordsWritten);
    }
    DWORD writeErr = bWriteOk ? 0 : GetLastError();

    CloseHandle(hConIn);
    FreeConsole();
    if (hOrigConsoleWnd != NULL)
    {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
    ReleaseSRWLockExclusive(&g_consoleLock);

    if (!bWriteOk)
    {
        sprintf_s(responseBuf, responseBufSize,
            "{\"success\":false,\"error\":\"delivery_failed\","
            "\"win32_error\":%lu,\"message\":\"WriteConsoleInputW failed\"}\n",
            writeErr);
        responseText = responseBuf;
        return;
    }

    sprintf_s(responseBuf, responseBufSize,
        "{\"success\":true,\"pid\":%lu,\"characters_sent\":%zu,\"records_written\":%lu}\n",
        targetPid, charCount, recordsWritten);
    responseText = responseBuf;
}
