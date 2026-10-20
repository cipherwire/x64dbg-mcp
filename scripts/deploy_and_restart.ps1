[CmdletBinding()]
param(
    [string]$Target = $env:X64DBG_TEST_TARGET,
    [string]$DebuggerExe = $env:X64DBG_EXE,
    [string]$TargetDir = $env:X64DBG_PLUGINS_DIR,
    [string]$PythonExe = $env:PYTHON_EXE
)

$ErrorActionPreference = "Stop"

if (Test-Path (Join-Path $PSScriptRoot "src")) {
    $rootDir = $PSScriptRoot
} else {
    $rootDir = Split-Path -Parent $PSScriptRoot
}

if (-not $DebuggerExe -and $env:X64DBG_DIR) {
    $DebuggerExe = Join-Path $env:X64DBG_DIR "release\x64\x64dbg.exe"
}
if (-not $TargetDir -and $env:X64DBG_DIR) {
    $TargetDir = Join-Path $env:X64DBG_DIR "release\x64\plugins"
}
if (-not $PythonExe) {
    $PythonExe = "python"
}

Write-Host "Stopping any running x64dbg instances..." -ForegroundColor Yellow
Get-Process x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

$pluginSrc = Join-Path $rootDir "bin\x64dbg_mcp.dp64"
if (-not (Test-Path $pluginSrc)) {
    Write-Host "Plugin binary not found at $pluginSrc. Building plugin first..." -ForegroundColor Yellow
    & (Join-Path $rootDir "scripts\build.ps1")
}

if ($TargetDir -and (Test-Path $TargetDir)) {
    $pluginDst = Join-Path $TargetDir "x64dbg_mcp.dp64"
    Write-Host "Deploying plugin to $pluginDst..." -ForegroundColor Yellow
    Copy-Item -Path $pluginSrc -Destination $pluginDst -Force
    Write-Host "[SUCCESS] Plugin deployed successfully!" -ForegroundColor Green
}

if ($DebuggerExe -and (Test-Path $DebuggerExe)) {
    Write-Host "Launching x64dbg with target: $Target..." -ForegroundColor Yellow
    if ($Target -and (Test-Path $Target)) {
        Start-Process -FilePath $DebuggerExe -ArgumentList "`"$Target`""
    } else {
        Start-Process -FilePath $DebuggerExe
    }
    Start-Sleep -Seconds 4

    Write-Host "Dismissing any initial dialogs..." -ForegroundColor DarkGray
    & $PythonExe -c "
import ctypes, time
from ctypes import wintypes
user32 = ctypes.windll.user32
def enum_cb(hwnd, extra):
    if user32.IsWindowVisible(hwnd):
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            b = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, b, length + 1)
            if b.value in ['Question', 'Warning', 'Information']:
                user32.PostMessageW(hwnd, 0x0100, 0x0D, 0)
                user32.PostMessageW(hwnd, 0x0101, 0x0D, 0)
    return True
WNDENUM = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
for _ in range(4):
    user32.EnumWindows(WNDENUM(enum_cb), 0)
    time.sleep(0.5)
"
    Start-Sleep -Seconds 2
    Write-Host "[SUCCESS] x64dbg session is ready." -ForegroundColor Green
} else {
    Write-Host "[INFO] Deployment completed. Set X64DBG_DIR or specify -DebuggerExe to launch x64dbg." -ForegroundColor Cyan
}
