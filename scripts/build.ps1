<#
.SYNOPSIS
    Builds the x64dbg-MCP native 64-bit plugin (x64dbg_mcp.dp64) using MSVC with /W4 /WX.

.PARAMETER SdkDir
    Path to the x64dbg pluginsdk folder containing _plugins.h, bridgemain.h, x64dbg.lib, etc.
    Defaults to $env:X64DBG_SDK_DIR, or $env:X64DBG_DIR\pluginsdk, or standard user snapshot.

.PARAMETER TargetDir
    Destination plugins directory for -Deploy. Defaults to $env:X64DBG_PLUGINS_DIR or $env:X64DBG_DIR\release\x64\plugins.

.PARAMETER X64DbgDir
    Root directory of an x64dbg release installation (automatically resolves pluginsdk and release\x64\plugins).

.PARAMETER Deploy
    Switch to copy the built .dp64 plugin directly to TargetDir after successful link.
#>
[CmdletBinding()]
param(
    [string]$SdkDir = $env:X64DBG_SDK_DIR,
    [string]$TargetDir = $env:X64DBG_PLUGINS_DIR,
    [string]$X64DbgDir = $env:X64DBG_DIR,
    [switch]$Deploy
)

$ErrorActionPreference = "Stop"

Write-Host "=== x64dbg-MCP Plugin Build (MSVC x64 /W4 /WX) ===" -ForegroundColor Cyan

# 1. Determine Repository Root Directory
if (Test-Path (Join-Path $PSScriptRoot "src")) {
    $rootDir = $PSScriptRoot
} else {
    $rootDir = Split-Path -Parent $PSScriptRoot
}

if (-not $SdkDir -and $X64DbgDir) {
    $SdkDir = Join-Path $X64DbgDir "pluginsdk"
}

if (-not $SdkDir -or -not (Test-Path -Path $SdkDir -PathType Container)) {
    Write-Error @"
ERROR: x64dbg Plugin SDK directory not found!
Please specify the SDK directory using:
    .\scripts\build.ps1 -SdkDir <path_to_pluginsdk>
or set the X64DBG_SDK_DIR (or X64DBG_DIR) environment variable.
Required files: _plugins.h, _plugin_types.h, bridgemain.h, x64dbg.lib, x64bridge.lib.
"@
    exit 1
}

# 3. Verify Required SDK Files
$requiredFiles = @(
    (Join-Path $SdkDir "_plugins.h"),
    (Join-Path $SdkDir "_plugin_types.h"),
    (Join-Path $SdkDir "bridgemain.h"),
    (Join-Path $SdkDir "x64dbg.lib"),
    (Join-Path $SdkDir "x64bridge.lib")
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path -Path $file -PathType Leaf)) {
        Write-Error "ERROR: Required SDK file missing: $file"
        exit 1
    }
}
Write-Host "[OK] SDK files verified at: $SdkDir" -ForegroundColor Green

# 4. Locate MSVC 64-bit Build Environment (vcvars64.bat)
$vcvars = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (Test-Path $vswhere) {
    $vsInstall = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstall) {
        $cand = Join-Path $vsInstall "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $cand) { $vcvars = $cand }
    }
}

if (-not $vcvars) {
    $standardPaths = @(
        "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )
    foreach ($p in $standardPaths) {
        if (Test-Path $p) {
            $vcvars = $p
            break
        }
    }
}

if (-not $vcvars) {
    Write-Error @"
ERROR: Microsoft Visual Studio (vcvars64.bat) not found.
Please install Visual Studio with the 'Desktop development with C++' workload,
or execute this script from a Visual Studio x64 Native Tools Command Prompt.
"@
    exit 1
}
Write-Host "[OK] MSVC environment script: $vcvars" -ForegroundColor Green

# 5. Prepare Output Directories
$buildDir = Join-Path $rootDir "build"
$binDir = Join-Path $rootDir "bin"

if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir | Out-Null }
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir | Out-Null }

# Clean old object files in build directory
Get-ChildItem -Path $buildDir -Filter "*.obj" | Remove-Item -Force -ErrorAction SilentlyContinue

$srcPattern = Join-Path $rootDir "src\*.cpp"
$outputDll = Join-Path $binDir "x64dbg_mcp.dp64"

# 6. Execute Build via cmd.exe calling vcvars64.bat
$cmdScript = @"
@echo off
call "$vcvars" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /MD /O2 /EHsc /I "$SdkDir" /c "$srcPattern" /Fo"$buildDir\\"
if errorlevel 1 exit /b 2
link.exe /nologo /DLL /OUT:"$outputDll" "$buildDir\*.obj" "$SdkDir\x64dbg.lib" "$SdkDir\x64bridge.lib" kernel32.lib user32.lib dbghelp.lib advapi32.lib
if errorlevel 1 exit /b 3
"@

$cmdTempFile = Join-Path $buildDir "build_temp.bat"
Set-Content -Path $cmdTempFile -Value $cmdScript -Encoding ASCII

Write-Host "Compiling and linking x64dbg_mcp.dp64..." -ForegroundColor Yellow
& cmd.exe /c "$cmdTempFile"
$buildExitCode = $LASTEXITCODE

Remove-Item -Path $cmdTempFile -Force -ErrorAction SilentlyContinue

if ($buildExitCode -ne 0) {
    Write-Error "ERROR: Build failed with exit code $buildExitCode"
    exit $buildExitCode
}

# 7. Verify Output
if (-not (Test-Path -Path $outputDll -PathType Leaf)) {
    Write-Error "ERROR: Expected output file was not generated: $outputDll"
    exit 1
}

$fileInfo = Get-Item $outputDll
Write-Host "[SUCCESS] Plugin built successfully: $outputDll ($($fileInfo.Length) bytes)" -ForegroundColor Green

# 8. Optional Deployment
if ($Deploy) {
    if (-not $TargetDir -and $X64DbgDir) {
        $TargetDir = Join-Path $X64DbgDir "release\x64\plugins"
    }
    if (-not $TargetDir -or -not (Test-Path -Path $TargetDir -PathType Container)) {
        Write-Error @"
ERROR: Deploy target directory not found!
Please specify the plugins directory using:
    .\scripts\build.ps1 -TargetDir <path_to_x64_plugins> -Deploy
or set the X64DBG_PLUGINS_DIR (or X64DBG_DIR) environment variable.
"@
        exit 1
    }
    $targetFile = Join-Path $TargetDir "x64dbg_mcp.dp64"
    $copied = $false
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Copy-Item -Path $outputDll -Destination $targetFile -Force -ErrorAction Stop
            $copied = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $copied) {
        Copy-Item -Path $outputDll -Destination $targetFile -Force
    }
    Write-Host "[SUCCESS] Deployed to: $targetFile" -ForegroundColor Green
}
