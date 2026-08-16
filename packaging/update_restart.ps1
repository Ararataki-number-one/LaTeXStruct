param(
    [Parameter(Mandatory = $true)]
    [string]$AppPath,
    [string]$PreviousVersion = "",
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion,
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$healthUrl = "http://127.0.0.1:$Port/api/health"
$logRoot = Join-Path $env:LOCALAPPDATA "LaTeXStruct"
$logPath = Join-Path $logRoot "update-restart.log"

function Write-UpdateLog([string]$Message) {
    try {
        New-Item -ItemType Directory -Path $logRoot -Force -ErrorAction Stop | Out-Null
        $line = "{0:o} {1}" -f [DateTime]::Now, $Message
        Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Logging must never prevent a valid update from starting.
    }
}

function Get-RunningVersion {
    try {
        $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2 -ErrorAction Stop
        if ($health.ok) { return [string]$health.version }
    } catch {
    }
    return ""
}

function Wait-ForExpectedVersion([int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $observed = Get-RunningVersion
        if ($observed -eq $ExpectedVersion) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Start-UpdatedApplication {
    if (-not (Test-Path -LiteralPath $AppPath -PathType Leaf)) {
        throw "installed executable is missing"
    }
    $arguments = @()
    if (-not [string]::IsNullOrWhiteSpace($PreviousVersion)) {
        $arguments = @("--updated-from", $PreviousVersion)
    }
    $workingDirectory = Split-Path -Parent $AppPath
    if ($arguments.Count -gt 0) {
        Start-Process -FilePath $AppPath -ArgumentList $arguments `
            -WorkingDirectory $workingDirectory -WindowStyle Normal | Out-Null
    } else {
        Start-Process -FilePath $AppPath -WorkingDirectory $workingDirectory `
            -WindowStyle Normal | Out-Null
    }
}

try {
    Write-UpdateLog "restart helper started; expected=$ExpectedVersion"

    # A previous PyInstaller child can briefly keep the default server port even
    # after the visible window closes.  Starting the new build during that gap
    # makes uvicorn fail and leaves the user with no window.
    $staleDeadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $runningVersion = Get-RunningVersion
        if ($runningVersion -eq $ExpectedVersion) {
            Write-UpdateLog "updated application was already healthy"
            exit 0
        }
        if ([string]::IsNullOrEmpty($runningVersion)) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $staleDeadline)

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Write-UpdateLog "starting updated application; attempt=$attempt"
        Start-UpdatedApplication
        if (Wait-ForExpectedVersion 45) {
            Write-UpdateLog "updated application is healthy; version=$ExpectedVersion"
            exit 0
        }
    }
    throw "updated application did not become healthy"
} catch {
    Write-UpdateLog ("restart failed: " + $_.Exception.Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        # Windows PowerShell 5.1 reads UTF-8 files without a BOM through the
        # active ANSI code page. Keep this script ASCII-only and decode the
        # localized fallback text at runtime so every Windows locale parses it.
        $dialogText = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String(
                "5paw54mI5pys5bey57uP5a6J6KOF77yM5L2G5rKh5pyJ6Ieq5Yqo5ZCv5Yqo44CC6K+35LuO5qGM6Z2i5oiW5byA5aeL6I+c5Y2V6YeN5paw5omT5byAIExhVGVYU3RydWN044CCCgror4rmlq3ml6Xlv5fvvJp7TE9HfQ=="
            )
        ).Replace("{LOG}", $logPath)
        $dialogTitle = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String(
                "TGFUZVhTdHJ1Y3Qg5pu05paw5ZCO5ZCv5Yqo5aSx6LSl"
            )
        )
        [System.Windows.Forms.MessageBox]::Show(
            $dialogText,
            $dialogTitle,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    } catch {
    }
    exit 41
}
