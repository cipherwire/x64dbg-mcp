<#
.SYNOPSIS
    Runs the full 234-tool x64dbg-MCP automated regression test suite against a target binary.

.PARAMETER Target
    Path to the test executable fixture. Defaults to $env:X64DBG_TEST_TARGET.

.PARAMETER DebuggerExe
    Path to x64dbg.exe (64-bit). Defaults to $env:X64DBG_EXE or $env:X64DBG_DIR\release\x64\x64dbg.exe.

.PARAMETER SdkDir
    Path to x64dbg pluginsdk folder. Forwarded to build.ps1.

.PARAMETER TargetDir
    Path to x64dbg plugins deploy folder. Forwarded to build.ps1.

.PARAMETER PythonExe
    Path to Python interpreter. Defaults to python in PATH or $env:PYTHON_EXE.
#>
[CmdletBinding()]
param(
    [string]$Target = $env:X64DBG_TEST_TARGET,
    [string]$DebuggerExe = $env:X64DBG_EXE,
    [string]$SdkDir = $env:X64DBG_SDK_DIR,
    [string]$TargetDir = $env:X64DBG_PLUGINS_DIR,
    [string]$PythonExe = $env:PYTHON_EXE
)

$ErrorActionPreference = "Continue"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "=== x64dbg-MCP Full 234-Tool Regression Test   ===" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Determine Repository Root Directory
if (Test-Path (Join-Path $PSScriptRoot "src")) {
    $rootDir = $PSScriptRoot
} else {
    $rootDir = Split-Path -Parent $PSScriptRoot
}

# 2. Resolve Test Target
if (-not $Target -or -not (Test-Path $Target)) {
    Write-Error @"
ERROR: Test fixture executable not specified or not found!
Please specify a target binary using:
    .\scripts\run_regression_test.ps1 -Target <path_to_fixture.exe>
or set the X64DBG_TEST_TARGET environment variable.
"@
    exit 1
}

# 3. Resolve x64dbg Executable
if (-not $DebuggerExe -and $env:X64DBG_DIR) {
    $DebuggerExe = Join-Path $env:X64DBG_DIR "release\x64\x64dbg.exe"
}

if (-not $DebuggerExe -or -not (Test-Path $DebuggerExe)) {
    Write-Error @"
ERROR: x64dbg executable not found!
Please specify the debugger using:
    .\scripts\run_regression_test.ps1 -DebuggerExe <path_to_x64dbg.exe>
or set the X64DBG_EXE (or X64DBG_DIR) environment variable.
"@
    exit 1
}

# 4. Resolve Python Executable
if (-not $PythonExe) {
    $candidates = @()
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pyCmd) { $candidates += $pyCmd.Source }
    if (Test-Path "C:\Program Files\Python314\python.exe") { $candidates += "C:\Program Files\Python314\python.exe" }
    
    foreach ($cand in $candidates) {
        & $cand -c "import mcp" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $PythonExe = $cand
            break
        }
    }
    if (-not $PythonExe -and $candidates.Count -gt 0) {
        $PythonExe = $candidates[0]
    }
}

if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    Write-Error @"
ERROR: Python executable not found!
Please specify Python using -PythonExe or ensure python is on your PATH.
"@
    exit 1
}

# 5. Record Target Fixture Hash
$hashBefore = (Get-FileHash -Algorithm SHA256 $Target).Hash
Write-Host "[Fixture Check] Target SHA256 before: $hashBefore" -ForegroundColor DarkGray

# 6. Build and Deploy Plugin
Write-Host "`n[Step 1] Building and deploying plugin..." -ForegroundColor Yellow
Get-Process x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

$buildScript = Join-Path $rootDir "scripts\build.ps1"
$buildParams = @("-Deploy")
if ($SdkDir) { $buildParams += @("-SdkDir", $SdkDir) }
if ($TargetDir) { $buildParams += @("-TargetDir", $TargetDir) }

& powershell -ExecutionPolicy Bypass -File $buildScript @buildParams
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit 1
}

# 7. Helper functions for debugger session management
function Start-TargetDebugger($targetPath) {
    Get-Process x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Write-Host "Launching x64dbg with $targetPath..." -ForegroundColor DarkGray
    $proc = Start-Process -FilePath $DebuggerExe -ArgumentList ('"{0}"' -f $targetPath) -PassThru
    Start-Sleep -Seconds 3
    & $PythonExe -c "import ctypes, time; from ctypes import wintypes; user32 = ctypes.windll.user32;
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
    return $proc
}

function Stop-TargetDebugger($proc) {
    Write-Host "Stopping x64dbg..." -ForegroundColor DarkGray
    if ($proc) {
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Get-Process x64dbg -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# 8. Launch Debugger and Execute Regression Test Suite
Write-Host "`n[Step 2] Executing 234-Tool MCP Client Regression Suite..." -ForegroundColor Yellow
$dbgProc = Start-TargetDebugger $Target

$testClientScript = Join-Path $rootDir "tests\test_mcp_client.py"
& $PythonExe -u $testClientScript
$testExitCode = $LASTEXITCODE

Stop-TargetDebugger $dbgProc

# 9. Verify Fixture Integrity
$hashAfter = (Get-FileHash -Algorithm SHA256 $Target).Hash
$hashMatch = ($hashBefore -eq $hashAfter)

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "=== Final Verification Summary                 ===" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "MCP Regression Exit Code: $testExitCode" -ForegroundColor $(if ($testExitCode -eq 0) { "Green" } else { "Red" })
Write-Host "Target SHA256: $hashAfter $(if ($hashMatch) { '[MATCH]' } else { '[MISMATCH]' })" -ForegroundColor $(if ($hashMatch) { "Green" } else { "Red" })

if ($testExitCode -eq 0 -and $hashMatch) {
    Write-Host "`n>>> ALL 234-TOOL REGRESSION CHECKS PASSED SUCCESSFULLY! <<<" -ForegroundColor Green
    exit 0
} else {
    Write-Error "`n>>> REGRESSION VERIFICATION FAILED! <<<"
    exit 1
}
