<#
.SYNOPSIS
    Build wireguard-windows amd64 (full exe with icons and resources)
.DESCRIPTION
    Usage: .\build-amd64.ps1
    Prerequisite: run build.bat once to download .deps toolchain
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# ========== Version ==========
$versionLine = Select-String -Path "$root\version\version.go" -Pattern 'Number\s*=\s*"([0-9.]+)"'
$version = $versionLine.Matches.Groups[1].Value
$verParts = $version.Split('.')
$verArr = (@($verParts) + @('0', '0', '0', '0'))[0..3] -join ','
Write-Host "[*] Version: $version  Array: $verArr"

# ========== Env ==========
$llvmBin = "$root\.deps\llvm-mingw\bin"
$gopath  = "$root\.deps\gopath"

Remove-Item Env:\GOROOT -ErrorAction SilentlyContinue
$env:Path = "${llvmBin};${root}\.deps;$env:Path"
$env:GOPATH = $gopath
$env:GOOS = "windows"
$env:GOARCH = "amd64"

Write-Host "[*] $(go.exe version 2>&1)"

# ========== 1/3: Icons ==========
Write-Host "[1/3] Rendering icons"
Get-ChildItem "$root\ui\icon\*.svg" | ForEach-Object {
    $ico = $_.FullName -replace '\.svg$', '.ico'
    & "$root\.deps\convert.exe" -background none $_.FullName `
        -define icon:auto-resize="256,192,128,96,64,48,40,32,24,20,16" `
        -compress zip $ico 2>&1 | Out-Null
}
Write-Host "      done"

# ========== 2/3: Resources ==========
Write-Host "[2/3] Compiling resources"
$windres = "$llvmBin\x86_64-w64-mingw32-windres.exe"
& cmd /c "`"$windres`" -I `"$root\.deps\wireguard-nt\bin\amd64`" -DWIREGUARD_VERSION_ARRAY=$verArr -DWIREGUARD_VERSION_STR=`"$version`" -i `"$root\resources.rc`" -o `"$root\resources_amd64.syso`" -O coff -c 65001 2>&1"
if ($LASTEXITCODE -ne 0) { throw "windres failed" }
Write-Host "      done"

# ========== 3/3: exe ==========
Write-Host "[3/3] Building wireguard.exe"
& go.exe build -tags load_wgnt_from_rsrc -ldflags="-H windowsgui -s -w" -trimpath -buildvcs=false -o "$root\amd64\wireguard.exe"
if ($LASTEXITCODE -ne 0) { throw "go build failed" }

Write-Host "[OK] Build succeeded!" -ForegroundColor Green
Write-Host "     $root\amd64\wireguard.exe" -ForegroundColor Cyan
