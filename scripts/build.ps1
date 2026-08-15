# LaTeXStruct 本地构建脚本：PyInstaller exe + （可选）Inno Setup 安装器
param(
    [string]$Version = ""
)
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
Set-Location $root

$appVersionOutput = python -B -c "from latexstruct._version import __version__; print(__version__)"
if ($LASTEXITCODE -ne 0) { throw "无法读取应用版本号" }
$appVersion = ([string]$appVersionOutput).Trim()
if ($appVersion -notmatch '^\d+\.\d+\.\d+$') { throw "应用版本号格式无效：$appVersion" }
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = $appVersion
}
$Version = $Version.Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "版本号格式无效：$Version" }
if ($Version -ne $appVersion) {
    throw "构建版本 $Version 与 latexstruct._version $appVersion 不一致"
}

$distDir = [IO.Path]::GetFullPath((Join-Path $root "dist"))
$distParent = [IO.Path]::GetDirectoryName($distDir)
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($distParent, $root)) {
    throw "dist 路径校验失败：$distDir"
}
if (Test-Path -LiteralPath $distDir) {
    $distItem = Get-Item -LiteralPath $distDir -Force
    if (-not $distItem.PSIsContainer) { throw "dist 不是目录：$distDir" }
    if (($distItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "拒绝在重解析点 dist 中清理构建产物：$distDir"
    }
}

function Get-ValidatedDistOutput([string]$LeafName) {
    if ($LeafName -notmatch '^LaTeXStruct(?:-setup-\d+\.\d+\.\d+)?\.exe$') {
        throw "非法构建输出文件名：$LeafName"
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path $distDir $LeafName))
    $parent = [IO.Path]::GetDirectoryName($candidate)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($parent, $distDir)) {
        throw "构建输出不在 repo/dist：$candidate"
    }
    return $candidate
}

function Remove-StaleDistOutput([string]$Path) {
    $validated = Get-ValidatedDistOutput ([IO.Path]::GetFileName($Path))
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($validated, [IO.Path]::GetFullPath($Path))) {
        throw "构建输出路径校验失败：$Path"
    }
    if (-not (Test-Path -LiteralPath $validated)) { return }
    $item = Get-Item -LiteralPath $validated -Force
    if ($item.PSIsContainer) { throw "拒绝删除目录型构建输出：$validated" }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "拒绝删除重解析点构建输出：$validated"
    }
    Remove-Item -LiteralPath $validated -Force
    if (Test-Path -LiteralPath $validated) { throw "旧构建输出清理失败：$validated" }
}

$portableExe = Get-ValidatedDistOutput "LaTeXStruct.exe"
$installerExe = Get-ValidatedDistOutput "LaTeXStruct-setup-$Version.exe"

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
Remove-StaleDistOutput $portableExe
$pyInstallerOutput = python -m PyInstaller packaging/LaTeXStruct.spec --noconfirm --clean --distpath dist --workpath build 2>&1
$pyInstallerExit = $LASTEXITCODE
$pyInstallerOutput | Select-Object -Last 3
if ($pyInstallerExit -ne 0) { throw "PyInstaller 构建失败（退出码 $pyInstallerExit）" }
if (-not (Test-Path -LiteralPath $portableExe -PathType Leaf)) { throw "PyInstaller 未生成预期 exe：$portableExe" }
Write-Host "  -> $portableExe"

Write-Host "[3/4] 查找 Inno Setup 编译器 ..."
$isccCommand = Get-Command iscc -ErrorAction SilentlyContinue
$isccPath = if ($isccCommand) { $isccCommand.Source } else { $null }
if (-not $isccPath) {
    foreach ($p in @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")) {
        if (Test-Path -LiteralPath $p -PathType Leaf) { $isccPath = [IO.Path]::GetFullPath($p); break }
    }
}
if ($isccPath) {
    Write-Host "[4/4] 构建安装器 ..."
    Remove-StaleDistOutput $installerExe
    $isccOutput = & $isccPath "/DAppVersion=$Version" packaging/installer.iss 2>&1
    $isccExit = $LASTEXITCODE
    $isccOutput | Select-Object -Last 3
    if ($isccExit -ne 0) { throw "Inno Setup 构建失败（退出码 $isccExit）" }
    if (-not (Test-Path -LiteralPath $installerExe -PathType Leaf)) {
        throw "Inno Setup 未生成预期安装器：$installerExe"
    }
    Write-Host "  -> $installerExe"
} else {
    Write-Host "[4/4] 未找到 Inno Setup（仅生成便携 exe；安装器由 GitHub Actions 构建）"
}
