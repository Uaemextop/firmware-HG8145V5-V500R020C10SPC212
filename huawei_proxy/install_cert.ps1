param(
    [string]$CertPath = ".\certs\mitmproxy-ca-cert.cer"
)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Huawei ONT Proxy - Certificate Installer" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

if (-NOT (Test-Path $CertPath)) {
    Write-Host "ERROR: Certificate not found at: $CertPath" -ForegroundColor Red
    Write-Host "Please run generate_cert.py first to create the certificate." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host "Installing certificate to Trusted Root Certification Authorities..." -ForegroundColor Green
Write-Host "Certificate: $CertPath" -ForegroundColor Gray
Write-Host ""

try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($CertPath)

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")

    $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

    if ($existingCert) {
        Write-Host "Certificate already installed. Removing old certificate..." -ForegroundColor Yellow
        $store.Remove($existingCert)
    }

    $store.Add($cert)
    $store.Close()

    Write-Host ""
    Write-Host "SUCCESS: Certificate installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Certificate Details:" -ForegroundColor Cyan
    Write-Host "  Subject: $($cert.Subject)" -ForegroundColor Gray
    Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor Gray
    Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
    Write-Host "  Valid From: $($cert.NotBefore)" -ForegroundColor Gray
    Write-Host "  Valid To: $($cert.NotAfter)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The proxy can now intercept HTTPS traffic from 192.168.100.1" -ForegroundColor Green
    Write-Host ""

} catch {
    Write-Host ""
    Write-Host "ERROR: Failed to install certificate" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    pause
    exit 1
}

Write-Host "Press any key to continue..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
