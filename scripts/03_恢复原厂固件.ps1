<#
.SYNOPSIS
    使用官方原厂 HEX 安全有线回滚并彻底擦净 Phase 3+ 扩展区 (--wipe-ext)。
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$StockHex
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONDONTWRITEBYTECODE = '1'

$Root = Split-Path -Parent $PSScriptRoot
$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
$ToolDir = Join-Path $Root 'tool'

if (-not (Test-Path $VenvPy)) { throw '请先运行 scripts\00_环境安装.ps1 初始化环境。' }
if (-not (Test-Path $StockHex)) { throw "未找到原厂 HEX 文件: $StockHex" }
$env:PYTHONPATH = $ToolDir

Write-Host '=== 第 1 步：官方原厂 HEX 校验与只读预检 (--dry-run --wipe-ext) ===' -ForegroundColor Cyan
& $VenvPy -B -m fenrir.flasher flash-stock --hex $StockHex --wipe-ext
if ($LASTEXITCODE -ne 0) {
    throw '原厂固件预检失败（必须为官方 Fenrir+035-8K v1.00.39.00 HEX 且仅保留有线连接）。'
}

Write-Host ''
$confirm = Read-Host '预检通过！确认刷回纯净原厂固件并擦净扩展区？全程切勿拔线（输入大写的 YES 继续）'
if ($confirm -ne 'YES') {
    Write-Host '已取消回滚。' -ForegroundColor Yellow
    exit 0
}

$backupDir = Join-Path $Root 'backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$reportPath = Join-Path $backupDir ("rollback_stock_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Host '=== 第 2 步：正在回滚纯净原厂固件并擦净 0x22A0C..0x24FFF ===' -ForegroundColor Cyan
& $VenvPy -B -m fenrir.flasher flash-stock --hex $StockHex --wipe-ext --yes --confirm-stock-s3 --report $reportPath
if ($LASTEXITCODE -ne 0) {
    throw '回滚失败，请勿拔线并参考 docs\01_刷入固件与安全回滚教程.md。'
}
Write-Host "已干净恢复官方原厂固件！报告已保存至: $reportPath" -ForegroundColor Green