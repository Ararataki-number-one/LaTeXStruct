# LaTeXStruct 本地构建脚本：PyInstaller exe + （可选）Inno Setup 安装器
param(
    [string]$Version = "0.2.0"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/3] PyInstaller 构建单文件 exe ..."
python -m PyInstaller packaging/LaTeXStruct.spec --noconfirm --clean --distpath dist --workpath build 2>&1 | Select-Object -Last 3
if (-not (Test-Path "dist/LaTeXStruct.exe")) { throw "PyInstaller 构建失败" }
Write-Host "  -> dist/LaTeXStruct.exe"

Write-Host "[2/3] 查找 Inno Setup 编译器 ..."
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    foreach ($p in @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $p) { $iscc = Get-Item $p; break }
    }
}
if ($iscc) {
    Write-Host "[3/3] 构建安装器 ..."
    & $iscc.Source "/DAppVersion=$Version" packaging/installer.iss | Select-Object -Last 3
    Get-ChildItem dist/*setup*.exe | ForEach-Object { Write-Host "  -> $($_.FullName)" }
} else {
    Write-Host "[3/3] 未找到 Inno Setup（仅生成便携 exe；安装器由 GitHub Actions 构建）"
}
