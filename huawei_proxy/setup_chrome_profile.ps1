param(
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 8080,
    [string]$ChromeProfileName = "Huawei-Proxy"
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Huawei ONT Proxy - Chrome Profile Configurator" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

$chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"

if (-NOT (Test-Path $chromeUserData)) {
    Write-Host "ERROR: Chrome user data directory not found" -ForegroundColor Red
    Write-Host "Please ensure Google Chrome is installed" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

$profilePath = Join-Path $chromeUserData $ChromeProfileName

if (-NOT (Test-Path $profilePath)) {
    Write-Host "Creating new Chrome profile: $ChromeProfileName" -ForegroundColor Green
    New-Item -ItemType Directory -Path $profilePath -Force | Out-Null
} else {
    Write-Host "Using existing Chrome profile: $ChromeProfileName" -ForegroundColor Yellow
}

$prefsPath = Join-Path $profilePath "Preferences"

$preferences = @{
    "proxy" = @{
        "mode" = "fixed_servers"
        "server" = "http://${ProxyHost}:${ProxyPort};https://${ProxyHost}:${ProxyPort}"
    }
    "ssl" = @{
        "rev_checking" = @{
            "enabled" = $false
        }
    }
}

$prefsJson = $preferences | ConvertTo-Json -Depth 10

try {
    $prefsJson | Out-File -FilePath $prefsPath -Encoding UTF8 -Force
    Write-Host "Chrome profile configured successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Profile Details:" -ForegroundColor Cyan
    Write-Host "  Profile Name: $ChromeProfileName" -ForegroundColor Gray
    Write-Host "  Profile Path: $profilePath" -ForegroundColor Gray
    Write-Host "  Proxy: ${ProxyHost}:${ProxyPort}" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "ERROR: Failed to configure Chrome profile" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    pause
    exit 1
}

$chromePath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (-NOT (Test-Path $chromePath)) {
    $chromePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
}

if (Test-Path $chromePath) {
    Write-Host "To launch Chrome with this profile, run:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  `"$chromePath`" --user-data-dir=`"$chromeUserData`" --profile-directory=`"$ChromeProfileName`" http://192.168.100.1" -ForegroundColor Yellow
    Write-Host ""

    $response = Read-Host "Would you like to launch Chrome now? (Y/N)"
    if ($response -eq "Y" -or $response -eq "y") {
        Write-Host "Launching Chrome with proxy profile..." -ForegroundColor Green
        Start-Process $chromePath -ArgumentList "--user-data-dir=`"$chromeUserData`"", "--profile-directory=`"$ChromeProfileName`"", "http://192.168.100.1"
    }
} else {
    Write-Host "Chrome executable not found. Please launch manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Configuration complete!" -ForegroundColor Green
Write-Host ""
pause
