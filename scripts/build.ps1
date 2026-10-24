<#
.SYNOPSIS
    Builds the x64dbg-MCP native plugin for x64 (.dp64), x86 (.dp32), or both using MSVC with /W4 /WX.

.PARAMETER Platform
    Target architecture to build: 'x64', 'x86', or 'All'. Defaults to 'x64'.

.PARAMETER SdkDir
    Path to the x64dbg pluginsdk folder containing _plugins.h, bridgemain.h, x64dbg.lib, x32dbg.lib, etc.
    Defaults to $env:X64DBG_SDK_DIR, or $env:X64DBG_DIR\pluginsdk, or standard user snapshot.

.PARAMETER TargetDir
    Destination plugins directory for -Deploy. Defaults to $env:X64DBG_PLUGINS_DIR or $env:X64DBG_DIR\release\<arch>\plugins.

.PARAMETER X64DbgDir
    Root directory of an x64dbg release installation.

.PARAMETER Deploy
    Switch to copy the built plugin directly to TargetDir after successful link.
#>
[CmdletBinding()]
param(
    [ValidateSet("x64", "x86", "All")]
    [string]$Platform = "x64",
    [string]$SdkDir = $env:X64DBG_SDK_DIR,
    [string]$TargetDir = $env:X64DBG_PLUGINS_DIR,
    [string]$X64DbgDir = $env:X64DBG_DIR,
    [switch]$Deploy
)

$ErrorActionPreference = "Stop"

# 1. Determine Repository Root Directory
if (Test-Path (Join-Path $PSScriptRoot "src")) {
    $rootDir = $PSScriptRoot
} else {
    $rootDir = Split-Path -Parent $PSScriptRoot
}

if (-not $SdkDir -and $X64DbgDir) {
    $SdkDir = Join-Path $X64DbgDir "pluginsdk"
}

if (-not $SdkDir) {
    $standardSnap = "C:\Users\AnonNp\Downloads\snapshot_2026-05-27_12-11\pluginsdk"
    if (Test-Path $standardSnap) {
        $SdkDir = $standardSnap
    }
}

if (-not $SdkDir -or -not (Test-Path -Path $SdkDir -PathType Container)) {
    Write-Error @"
ERROR: x64dbg Plugin SDK directory not found!
Please specify the SDK directory using:
    .\scripts\build.ps1 -SdkDir <path_to_pluginsdk>
or set the X64DBG_SDK_DIR (or X64DBG_DIR) environment variable.
Required files: _plugins.h, _plugin_types.h, bridgemain.h, x64dbg.lib, x32dbg.lib.
"@
    exit 1
}

# 2. Verify Common SDK Headers
$commonHeaders = @(
    (Join-Path $SdkDir "_plugins.h"),
    (Join-Path $SdkDir "_plugin_types.h"),
    (Join-Path $SdkDir "bridgemain.h")
)
foreach ($file in $commonHeaders) {
    if (-not (Test-Path -Path $file -PathType Leaf)) {
        Write-Error "ERROR: Required SDK header missing: $file"
        exit 1
    }
}
Write-Host "[OK] SDK directory verified at: $SdkDir" -ForegroundColor Green

# 3. Locate Visual Studio vcvars scripts
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsAuxBuild = $null

if (Test-Path $vswhere) {
    $vsInstall = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsInstall) {
        $cand = Join-Path $vsInstall "VC\Auxiliary\Build"
        if (Test-Path $cand) { $vsAuxBuild = $cand }
    }
}

if (-not $vsAuxBuild) {
    $standardDirs = @(
        "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build"
    )
    foreach ($d in $standardDirs) {
        if (Test-Path $d) {
            $vsAuxBuild = $d
            break
        }
    }
}

if (-not $vsAuxBuild) {
    Write-Error "ERROR: Visual Studio VC\Auxiliary\Build directory not found."
    exit 1
}

function Build-TargetArchitecture {
    param(
        [string]$Arch # 'x64' or 'x86'
    )

    Write-Host "`n=== Building x64dbg-MCP Plugin for [$Arch] (MSVC /W4 /WX) ===" -ForegroundColor Cyan

    $is64 = ($Arch -eq "x64")
    $vcvarsBat = if ($is64) { Join-Path $vsAuxBuild "vcvars64.bat" } else { Join-Path $vsAuxBuild "vcvars32.bat" }

    if (-not (Test-Path $vcvarsBat)) {
        Write-Error "ERROR: Environment script missing: $vcvarsBat"
        exit 1
    }

    $dbgLib = if ($is64) { Join-Path $SdkDir "x64dbg.lib" } else { Join-Path $SdkDir "x32dbg.lib" }
    $bridgeLib = if ($is64) { Join-Path $SdkDir "x64bridge.lib" } else { Join-Path $SdkDir "x32bridge.lib" }

    if (-not (Test-Path $dbgLib) -or -not (Test-Path $bridgeLib)) {
        Write-Error "ERROR: Missing import libraries for ${Arch}: $dbgLib or $bridgeLib"
        exit 1
    }

    $buildSubDir = Join-Path $rootDir "build\$Arch"
    $binDir = Join-Path $rootDir "bin"

    if (-not (Test-Path $buildSubDir)) { New-Item -ItemType Directory -Path $buildSubDir -Force | Out-Null }
    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }

    # Clean old object files for this architecture
    Get-ChildItem -Path $buildSubDir -Filter "*.obj" | Remove-Item -Force -ErrorAction SilentlyContinue

    $ext = if ($is64) { "dp64" } else { "dp32" }
    $dllName = if ($is64) { "x64dbg_mcp.$ext" } else { "x32dbg_mcp.$ext" }
    $outputDll = Join-Path $binDir $dllName
    $srcPattern = Join-Path $rootDir "src\*.cpp"

    $cmdScript = @"
@echo off
call "$vcvarsBat" >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /wd4324 /MD /O2 /EHsc /I "$SdkDir" /c "$srcPattern" /Fo"$buildSubDir\\"
if errorlevel 1 exit /b 2
link.exe /nologo /DLL /OUT:"$outputDll" "$buildSubDir\*.obj" "$dbgLib" "$bridgeLib" kernel32.lib user32.lib dbghelp.lib advapi32.lib
if errorlevel 1 exit /b 3
"@

    $cmdTempFile = Join-Path $buildSubDir "build_temp.bat"
    Set-Content -Path $cmdTempFile -Value $cmdScript -Encoding ASCII

    Write-Host "Compiling and linking $dllName..." -ForegroundColor Yellow
    & cmd.exe /c "$cmdTempFile"
    $buildExitCode = $LASTEXITCODE

    Remove-Item -Path $cmdTempFile -Force -ErrorAction SilentlyContinue

    if ($buildExitCode -ne 0) {
        Write-Error "ERROR: Build failed for $Arch with exit code $buildExitCode"
        exit $buildExitCode
    }

    if (-not (Test-Path -Path $outputDll -PathType Leaf)) {
        Write-Error "ERROR: Expected output binary was not generated: $outputDll"
        exit 1
    }

    $fileInfo = Get-Item $outputDll
    Write-Host "[SUCCESS] Plugin built for ${Arch}: $outputDll ($($fileInfo.Length) bytes)" -ForegroundColor Green

    # Optional Deployment
    if ($Deploy) {
        $destDir = $TargetDir
        if (-not $destDir -and $X64DbgDir) {
            $destDir = if ($is64) { Join-Path $X64DbgDir "release\x64\plugins" } else { Join-Path $X64DbgDir "release\x32\plugins" }
        }
        if ($destDir -and (Test-Path $destDir)) {
            $destFile = Join-Path $destDir $dllName
            Copy-Item -Path $outputDll -Destination $destFile -Force
            Write-Host "[SUCCESS] Deployed $dllName to $destFile" -ForegroundColor Green
        }
    }
}

if ($Platform -eq "x64" -or $Platform -eq "All") {
    Build-TargetArchitecture -Arch "x64"
}

if ($Platform -eq "x86" -or $Platform -eq "All") {
    Build-TargetArchitecture -Arch "x86"
}
