# Build script for Scout Standalone Packaging
param(
    [string]$ToolsDir = "tools",
    [string]$ClamAvDir = "clamav",
    [string]$RulesDir = "rules"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Scout: Building Standalone Executable (ScannerApp)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Ensure pyinstaller is available
$PyInstallerExe = Join-Path $ScriptDir ".venv\Scripts\pyinstaller.exe"
if (-not (Test-Path $PyInstallerExe)) {
    $PyInstallerExe = (Get-Command pyinstaller -ErrorAction SilentlyContinue).Source
}
if (-not $PyInstallerExe -or -not (Test-Path $PyInstallerExe)) {
    Write-Error "PyInstaller not found. Please run 'pip install pyinstaller' in your venv."
}
Write-Host "[1/7] Using PyInstaller at: $PyInstallerExe" -ForegroundColor Green

# 2. Verify pre-built web dist exists
$WebDistDir = Join-Path $ScriptDir "app\web\dist"
if (-not (Test-Path (Join-Path $WebDistDir "index.html"))) {
    Write-Host "[2/7] Precompiled web dist not found. Building with npm..." -ForegroundColor Yellow
    Push-Location (Join-Path $ScriptDir "app\web")
    try {
        npm ci
        npm run build
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[2/7] Using precompiled web dist at: $WebDistDir" -ForegroundColor Green
}

# 3. Clean previous build artifacts
Write-Host "[3/7] Cleaning previous dist\ScannerApp..." -ForegroundColor Green
$DistDir = Join-Path $ScriptDir "dist\ScannerApp"
$BuildDir = Join-Path $ScriptDir "build\ScannerApp"
if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }

# 4. Run PyInstaller
Write-Host "[4/7] Running PyInstaller build..." -ForegroundColor Green
& $PyInstallerExe --noconfirm ScannerApp.spec
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path (Join-Path $DistDir "ScannerApp.exe"))) {
    Write-Error "Build finished but ScannerApp.exe was not found in $DistDir"
}

# 5. Populate tools, clamav, and rules
Write-Host "[5/7] Copying external security tools and rules..." -ForegroundColor Green

# Sigcheck
$DestTools = Join-Path $DistDir "tools"
New-Item -ItemType Directory -Force -Path $DestTools | Out-Null
$SrcSigcheck = Join-Path $ScriptDir "$ToolsDir\sigcheck.exe"
if (Test-Path $SrcSigcheck) {
    Copy-Item $SrcSigcheck -Destination $DestTools -Force
    Write-Host "  - Copied sigcheck.exe" -ForegroundColor Gray
} else {
    Write-Host "  - Warning: sigcheck.exe not found at $SrcSigcheck" -ForegroundColor Yellow
}

# ClamAV
$DestClamAv = Join-Path $DistDir "tools\clamav"
$SrcClamAv = Join-Path $ScriptDir $ClamAvDir
if (Test-Path $SrcClamAv) {
    Copy-Item -Recurse -Force $SrcClamAv $DestClamAv
    # Ensure database directory exists but strip definitions for lightweight packaging
    $DestDb = Join-Path $DestClamAv "database"
    if (Test-Path $DestDb) {
        Remove-Item "$DestDb\*.cvd", "$DestDb\*.cld", "$DestDb\*.sign", "$DestDb\freshclam.dat" -Force -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Force -Path $DestDb | Out-Null
    }
    # Ensure certs directory is preserved with clamav.crt for code-signature verification
    $DestCerts = Join-Path $DestClamAv "certs"
    New-Item -ItemType Directory -Force -Path $DestCerts | Out-Null
    $SrcCert = Join-Path $SrcClamAv "certs\clamav.crt"
    if (Test-Path $SrcCert) {
        Copy-Item $SrcCert -Destination $DestCerts -Force
        Write-Host "  - Preserved ClamAV signature cert (certs\clamav.crt)" -ForegroundColor Gray
    } else {
        Write-Host "  - Warning: ClamAV cert not found at $SrcCert" -ForegroundColor Yellow
    }
    Write-Host "  - Copied ClamAV runtime binaries (definitions excluded for lightweight packaging)" -ForegroundColor Gray
} else {
    Write-Host "  - Warning: ClamAV directory not found at $SrcClamAv" -ForegroundColor Yellow
}


# YARA Rules
$SrcYara = Join-Path $ScriptDir "$RulesDir\signature-base\yara"
$DestYara = Join-Path $DistDir "rules\signature-base\yara"
if (Test-Path $SrcYara) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DestYara) | Out-Null
    Copy-Item -Recurse -Force $SrcYara $DestYara
    Write-Host "  - Copied YARA signature rules" -ForegroundColor Gray
} else {
    Write-Host "  - Warning: YARA rules not found at $SrcYara" -ForegroundColor Yellow
}

# 6. Create runtime working folders and config
Write-Host "[6/7] Initializing runtime directories and configuration..." -ForegroundColor Green
$Folders = @("inbox", "processing", "clean", "review", "quarantine", "data", "data\logs", "data\feeds")
foreach ($f in $Folders) {
    New-Item -ItemType Directory -Force -Path (Join-Path $DistDir $f) | Out-Null
}

# Create config.yaml with relative paths
$ConfigYamlContent = @"
paths:
  inbox: "inbox"
  processing: "processing"
  clean: "clean"
  review: "review"
  quarantine: "quarantine"
  data: "data"
  tools: "tools"
  rules: "rules"
  clamav: "tools/clamav"

clamav:
  host: "127.0.0.1"
  port: 3310
  auto_start: true

trusted_signers:
  - "Oracle America, Inc."
  - "The Document Foundation"
  - "Wireshark Foundation"
  - "Simon Bennetts"
  - "ZAP"

vendor_hashes:
  - pattern: "*VirtualBox*"
    source_type: "virtualbox_sums"
    url: "https://www.virtualbox.org/download/hashes/6.1.30/SHA256SUMS"
    manual_sha256: null

  - pattern: "*ZAP*"
    source_type: "zap_xml"
    url: "https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions-2.11.xml"
    manual_sha256: null

  - pattern: "*Wireshark*"
    source_type: "wireshark_sigs"
    url: "https://www.wireshark.org/download/src/all-versions/SIGNATURES-3.6.0.txt"
    fallback_urls:
      - "https://www.wireshark.org/download/SIGNATURES-3.6.0.txt"
    manual_sha256: null

  - pattern: "*LibreOffice*"
    source_type: "libreoffice_page"
    url: "https://downloadarchive.documentfoundation.org/libreoffice/old/7.2.3.2/win/x86_64/LibreOffice_7.2.3.2_Win_x64.msi.mirrorlist"
    fallback_urls:
      - "https://download.documentfoundation.org/libreoffice/stable/7.2.3/win/x86_64/LibreOffice_7.2.3_Win_x64.msi.mirrorlist"
    manual_sha256: null
"@
Set-Content -Path (Join-Path $DistDir "config.yaml") -Value $ConfigYamlContent -Encoding UTF8

# Create default .env
$EnvContent = "ABUSECH_KEY=`nNVD_KEY=`n"
Set-Content -Path (Join-Path $DistDir ".env") -Value $EnvContent -Encoding UTF8

# 7. Calculate and display package statistics
Write-Host "[7/7] Packaging completed successfully!" -ForegroundColor Green

$TotalBytes = (Get-ChildItem -Recurse $DistDir | Measure-Object -Property Length -Sum).Sum
$SizeMB = [math]::Round($TotalBytes / 1MB, 2)
$ItemCount = (Get-ChildItem -Recurse $DistDir).Count

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  BUILD SUCCESS" -ForegroundColor Green
Write-Host "  Location: $DistDir" -ForegroundColor White
Write-Host "  Executable: $DistDir\ScannerApp.exe" -ForegroundColor White
Write-Host "  Total Size: $SizeMB MB ($ItemCount items)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
