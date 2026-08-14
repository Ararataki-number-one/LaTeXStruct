# LaTeXStruct 本地构建脚本：PyInstaller exe + （可选）Inno Setup 安装器
param(
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = (python -c "from latexstruct._version import __version__; print(__version__)").Trim()
    if ($LASTEXITCODE -ne 0) { throw "无法读取应用版本号" }
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "版本号格式无效：$Version" }
python packaging/sync_version.py --version $Version
if ($LASTEXITCODE -ne 0) { throw "Windows 版本资源同步失败" }

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) { throw "未找到 npm；请先安装 Node.js，再运行本地发布构建" }
Write-Host "[1/4] 构建 React 前端 ..."
Push-Location frontend
try {
    & $npm.Source ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw "前端依赖安装失败" }
    & $npm.Source run build
    if ($LASTEXITCODE -ne 0) { throw "前端构建失败" }
} finally {
    Pop-Location
}

Write-Host "[2/4] PyInstaller 构建单文件 exe ..."
python -m PyInstaller packaging/LaTeXStruct.spec --noconfirm --clean --distpath dist --workpath build 2>&1 | Select-Object -Last 3
if (-not (Test-Path "dist/LaTeXStruct.exe")) { throw "PyInstaller 构建失败" }
Write-Host "  -> dist/LaTeXStruct.exe"

Write-Host "[3/4] 查找 Inno Setup 编译器 ..."
$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    foreach ($p in @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")) {
        if (Test-Path $p) { $iscc = Get-Item $p; break }
    }
}
if ($iscc) {
    Write-Host "[4/4] 构建安装器 ..."
    & $iscc.Source "/DAppVersion=$Version" packaging/installer.iss | Select-Object -Last 3
    Get-ChildItem dist/*setup*.exe | ForEach-Object { Write-Host "  -> $($_.FullName)" }
} else {
    Write-Host "[4/4] 未找到 Inno Setup（仅生成便携 exe；安装器由 GitHub Actions 构建）"
}
