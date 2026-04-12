#requires -Version 5.1
<#
.SYNOPSIS
Guided Windows setup for ESP32 Wake-on-LAN via Tailscale.

.DESCRIPTION
Checks for ESP-IDF, installs Espressif EIM CLI with winget when possible,
collects project configuration, builds the firmware, and flashes an ESP32
using a Windows COM port.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$IdfVersion = "v5.5.3"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $ProjectRoot

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "     $Message"
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERR] $Message" -ForegroundColor Red
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function ConvertTo-PlainText {
    param([securestring]$SecureText)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureText)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Escape-KconfigString {
    param([string]$Value)
    $escaped = $Value -replace '\\', '\\'
    return ($escaped -replace '"', '\"')
}

function Find-EspIdfExport {
    $candidates = @()

    if ($env:IDF_PATH) {
        $candidates += (Join-Path $env:IDF_PATH "export.ps1")
    }

    $candidates += @(
        (Join-Path $HOME "esp\esp-idf\export.ps1"),
        (Join-Path $HOME "esp-idf\export.ps1"),
        (Join-Path $HOME "Desktop\esp-idf\export.ps1"),
        "C:\Espressif\frameworks\esp-idf-$IdfVersion\export.ps1",
        "C:\Espressif\frameworks\esp-idf\export.ps1"
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Ensure-EspIdf {
    if (Test-Command "idf.py") {
        Write-Ok "ESP-IDF tools are already on PATH"
        return
    }

    $exportScript = Find-EspIdfExport
    if ($exportScript) {
        Write-Info "Activating ESP-IDF environment from $exportScript"
        . $exportScript
        if (Test-Command "idf.py") {
            Write-Ok "ESP-IDF environment activated"
            return
        }
    }

    Write-Warn "ESP-IDF $IdfVersion was not found on PATH"

    if (-not (Test-Command "eim")) {
        if (-not (Test-Command "winget")) {
            throw "winget is not available. Install ESP-IDF $IdfVersion with Espressif's Windows installer, then rerun .\scripts\setup.ps1."
        }

        Write-Info "Installing Espressif EIM CLI with winget..."
        Invoke-External `
            -Command "winget" `
            -Arguments @("install", "--id", "Espressif.EIM-CLI", "--source", "winget", "--accept-package-agreements", "--accept-source-agreements") `
            -FailureMessage "Failed to install Espressif EIM CLI"
    }

    if (-not (Test-Command "eim")) {
        throw "EIM CLI was installed but is not on PATH yet. Open a new PowerShell window and rerun .\scripts\setup.ps1."
    }

    Write-Info "Installing ESP-IDF $IdfVersion with EIM..."
    Invoke-External `
        -Command "eim" `
        -Arguments @("install", "-i", $IdfVersion) `
        -FailureMessage "Failed to install ESP-IDF $IdfVersion with EIM"

    $exportScript = Find-EspIdfExport
    if ($exportScript) {
        Write-Info "Activating ESP-IDF environment from $exportScript"
        . $exportScript
    }

    if (-not (Test-Command "idf.py")) {
        throw "ESP-IDF installed, but idf.py is still unavailable. Open the ESP-IDF PowerShell shortcut or rerun this script from a new PowerShell window."
    }

    Write-Ok "ESP-IDF environment activated"
}

function Get-IdfVersionText {
    if (-not (Test-Command "idf.py")) {
        return $null
    }

    try {
        return (& idf.py --version 2>$null | Select-Object -First 1)
    }
    catch {
        return $null
    }
}

function Get-SerialPorts {
    $ports = @()

    try {
        $ports = Get-CimInstance Win32_SerialPort -ErrorAction Stop |
            Sort-Object DeviceID |
            ForEach-Object {
                [PSCustomObject]@{
                    Port = $_.DeviceID
                    Name = $_.Name
                }
            }
    }
    catch {
        $ports = @()
    }

    if (-not $ports -or $ports.Count -eq 0) {
        try {
            $ports = [System.IO.Ports.SerialPort]::GetPortNames() |
                Sort-Object |
                ForEach-Object {
                    [PSCustomObject]@{
                        Port = $_
                        Name = "Serial port"
                    }
                }
        }
        catch {
            $ports = @()
        }
    }

    return @($ports)
}

function Read-Required {
    param([string]$Prompt)

    do {
        $value = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }
        Write-Warn "This value is required."
    } while ($true)
}

function Read-Default {
    param(
        [string]$Prompt,
        [string]$Default
    )

    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }
    return $value.Trim()
}

function Assert-ProjectRoot {
    if (-not (Test-Path "CMakeLists.txt") -or -not (Test-Path "sdkconfig.defaults")) {
        throw "Run this script from the esp32-wakeonlan project root, or run .\scripts\setup.ps1 from the repository."
    }

    if (-not (Test-Path "lib\tailscale\src")) {
        throw "Vendored Tailscale library not found in lib\tailscale\. Is the repo intact?"
    }
}

function Write-TempConfig {
    param(
        [string]$WifiSsid,
        [string]$WifiPassword,
        [string]$TailscaleAuthKey,
        [string]$TargetMac,
        [string]$DeviceName,
        [int]$ListenPort,
        [string]$BroadcastIp
    )

    $path = Join-Path ([IO.Path]::GetTempPath()) ("wol_config_{0}.defaults" -f ([Guid]::NewGuid().ToString("N")))
    $lines = @(
        'CONFIG_WOL_WIFI_SSID="{0}"' -f (Escape-KconfigString $WifiSsid),
        'CONFIG_WOL_WIFI_PASSWORD="{0}"' -f (Escape-KconfigString $WifiPassword),
        'CONFIG_WOL_TAILSCALE_AUTH_KEY="{0}"' -f (Escape-KconfigString $TailscaleAuthKey),
        'CONFIG_WOL_TARGET_MAC="{0}"' -f (Escape-KconfigString $TargetMac),
        'CONFIG_WOL_DEVICE_NAME="{0}"' -f (Escape-KconfigString $DeviceName),
        'CONFIG_WOL_LISTEN_PORT={0}' -f $ListenPort,
        'CONFIG_WOL_BROADCAST_IP="{0}"' -f (Escape-KconfigString $BroadcastIp)
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($path, (($lines -join [Environment]::NewLine) + [Environment]::NewLine), $utf8NoBom)
    return $path
}

function Invoke-IdfWithDefaults {
    param(
        [string]$UserConfig,
        [string[]]$IdfArguments,
        [string]$FailureMessage
    )

    $oldDefaults = $env:SDKCONFIG_DEFAULTS
    try {
        $env:SDKCONFIG_DEFAULTS = "sdkconfig.defaults;$UserConfig"
        Invoke-External -Command "idf.py" -Arguments $IdfArguments -FailureMessage $FailureMessage
    }
    finally {
        $env:SDKCONFIG_DEFAULTS = $oldDefaults
    }
}

try {
    Write-Host ""
    Write-Host "esp32-wol - Windows setup" -ForegroundColor Cyan
    Write-Host "ESP32 Wake-on-LAN via Tailscale" -ForegroundColor Cyan
    Write-Host ""

    Assert-ProjectRoot
    Write-Ok "Project layout verified"

    if (-not (Test-Command "git")) {
        Write-Warn "git was not found on PATH. ESP-IDF installers usually include Git, but repair steps may need it."
    }

    if (-not (Test-Command "python")) {
        Write-Warn "python was not found on PATH. ESP-IDF may provide its own Python after activation."
    }

    Ensure-EspIdf

    $idfVersionText = Get-IdfVersionText
    if ($idfVersionText) {
        Write-Info $idfVersionText
        if ($idfVersionText -notmatch [regex]::Escape($IdfVersion)) {
            Write-Warn "This project is tuned for ESP-IDF $IdfVersion. Continuing with the active ESP-IDF, but $IdfVersion is recommended."
        }
    }

    $ports = Get-SerialPorts
    $defaultPort = "COM3"
    if ($ports.Count -gt 0) {
        Write-Host ""
        Write-Host "Detected serial ports:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $ports.Count; $i++) {
            Write-Host ("  {0}. {1} - {2}" -f ($i + 1), $ports[$i].Port, $ports[$i].Name)
        }
        $defaultPort = $ports[0].Port
    }
    else {
        Write-Warn "No serial ports detected. You can still enter a COM port manually, such as COM3."
    }

    Write-Host ""
    Write-Host "Configuration" -ForegroundColor Cyan

    $wifiSsid = Read-Required "  WiFi SSID"
    $wifiPasswordSecure = Read-Host "  WiFi Password" -AsSecureString
    $wifiPassword = ConvertTo-PlainText $wifiPasswordSecure

    $tailscaleKeySecure = Read-Host "  Tailscale Auth Key" -AsSecureString
    $tailscaleKey = ConvertTo-PlainText $tailscaleKeySecure
    if ([string]::IsNullOrWhiteSpace($tailscaleKey)) {
        throw "Tailscale auth key cannot be empty."
    }

    Write-Info "Get a key at https://login.tailscale.com/admin/settings/keys"

    $targetMac = Read-Required "  Target PC MAC address"
    if ($targetMac -notmatch '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') {
        throw "Invalid MAC address: '$targetMac' (expected format: AA:BB:CC:DD:EE:FF)."
    }

    $deviceName = Read-Default "  Device name" "esp32-wol"
    $listenPortText = Read-Default "  Listen port" "9999"
    $broadcastIp = Read-Default "  Broadcast IP" "255.255.255.255"
    $serialPort = Read-Default "  Serial port" $defaultPort

    $listenPort = 0
    if (-not [int]::TryParse($listenPortText, [ref]$listenPort) -or $listenPort -lt 1024 -or $listenPort -gt 65535) {
        throw "Listen port must be a number between 1024 and 65535."
    }

    if ($ports.Count -gt 0 -and ($ports.Port -notcontains $serialPort)) {
        Write-Warn "Serial port $serialPort was not in the detected list. Continuing anyway."
    }

    Write-Host ""
    Write-Host "Summary" -ForegroundColor Cyan
    Write-Info "WiFi SSID     : $wifiSsid"
    Write-Info "Target MAC    : $targetMac"
    Write-Info "Device name   : $deviceName"
    Write-Info "Listen port   : $listenPort"
    Write-Info "Broadcast IP  : $broadcastIp"
    Write-Info "Serial port   : $serialPort"

    $userConfig = Write-TempConfig `
        -WifiSsid $wifiSsid `
        -WifiPassword $wifiPassword `
        -TailscaleAuthKey $tailscaleKey `
        -TargetMac $targetMac `
        -DeviceName $deviceName `
        -ListenPort $listenPort `
        -BroadcastIp $broadcastIp

    try {
        Remove-Item -Path "sdkconfig", "sdkconfig.old" -Force -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host "Building firmware..." -ForegroundColor Cyan
        Invoke-IdfWithDefaults -UserConfig $userConfig -IdfArguments @("build") -FailureMessage "idf.py build failed"
        Write-Ok "Build complete"

        Write-Host ""
        Write-Host "Flashing to $serialPort..." -ForegroundColor Cyan
        Invoke-IdfWithDefaults -UserConfig $userConfig -IdfArguments @("flash", "-p", $serialPort) -FailureMessage "idf.py flash failed"
        Write-Ok "Flash complete"
    }
    catch {
        Write-Err $_.Exception.Message
        Write-Host ""
        Write-Host "If the build failed inside ESP-IDF's mbedtls component, repair the ESP-IDF install:" -ForegroundColor Yellow
        Write-Host "  cd `$env:IDF_PATH"
        Write-Host "  git submodule update --init --recursive"
        Write-Host "  .\install.ps1"
        Write-Host "  . .\export.ps1"
        Write-Host ""
        throw
    }
    finally {
        if ($userConfig -and (Test-Path $userConfig)) {
            Remove-Item $userConfig -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ""
    Write-Host "Done! ESP32 flashed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Open the serial monitor to see the ESP32 Tailscale IP:"
    Write-Host "  idf.py monitor -p $serialPort" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Then wake your PC from any Tailscale peer by sending UDP traffic to:"
    Write-Host "  <esp32-tailscale-ip>:$listenPort" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Err $_.Exception.Message
    exit 1
}
