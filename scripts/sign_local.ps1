# 本地代码签名（自签证书，仅本机/内网信任；消除 SmartScreen 需购买 EV/OV 证书）
# 用法：powershell -ExecutionPolicy Bypass -File scripts/sign_local.ps1
param(
    [string]$CertName = "LaTeXStruct Self-Signed",
    [string]$Target = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Target) { $Target = Join-Path $root "dist\LaTeXStruct.exe" }
if (-not (Test-Path $Target)) { throw "目标不存在：$Target" }

# 1) 查找或创建代码签名证书
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=$CertName" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "创建自签代码签名证书：$CertName"
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$CertName" -CertStoreLocation Cert:\CurrentUser\My
}
$pfx = Join-Path $root "packaging\selfsign.pfx"
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString "latexstruct" -AsPlainText -Force) | Out-Null

# 2) 签名
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
if (-not $signtool) { throw "未找到 signtool.exe（需安装 Windows SDK）" }
& $signtool.FullName sign /f $pfx /p latexstruct /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Target
Write-Host "已签名：$Target（自签证书仅本机信任；分发请改用 EV 证书并配置 GitHub secrets）"
