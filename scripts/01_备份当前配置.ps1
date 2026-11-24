<#
.SYNOPSIS
    备份当前鼠标常规配置（DPI/回报率/消抖/LOD/键映射/休眠等）到 backups\ 目录。
#>
param(
    [ValidateSet('wired', 'wireless')]
    [string]$Mode = 'wired'
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONDONTWRITEBYTECODE = '1'

$Root = Split-Path -Parent $PSScriptRoot
$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
$ToolDir = Join-Path $Root 'tool'
if (-not (Test-Path $VenvPy)) { throw '请先运行 scripts\00_环境安装.ps1 初始化环境。' }
$env:PYTHONPATH = $ToolDir

$pidHex = if ($Mode -eq 'wired') { '0x3508' } else { '0x3517' }
$cls = if ($Mode -eq 'wired') { 'mouse_app' } else { 'receiver_app' }
$target = if ($Mode -eq 'wired') { 'mouse-usb' } else { 'receiver-to-mouse' }

$enumOut = (& $VenvPy -B -m fenrir.probe enumerate) -join "`n"
$pattern = "0x33E4:$pidHex \| class=$cls \| if=2 up=0xFFFF usage=0x0000 exact_feat=True[^\n]*\n\s+path=(\S+)"
$m = [regex]::Match($enumOut, $pattern)
if (-not $m.Success) {
    throw "未找到 $Mode 模式下的目标设备 (0x33E4:$pidHex)。请确认连接正确，或运行 fenrir.probe enumerate 查看。"
}
$hidPath = $m.Groups[1].Value.Trim()

$backupDir = Join-Path $Root 'backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$outFile = Join-Path $backupDir ("backup_{0}_{1}.json" -f $Mode, $ts)

Write-Host "正在导出 $Mode ($target) 配置..." -ForegroundColor Cyan
& $VenvPy -B -m fenrir.config export --target $target --path $hidPath --output $outFile
if ($LASTEXITCODE -ne 0) { throw '配置导出失败。' }
Write-Host "备份已保存: $outFile" -ForegroundColor Green