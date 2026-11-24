<#
.SYNOPSIS
    安全有线刷入 Fenrir Asym 8K UltraWolves 增强版鼠标固件（需拔掉接收器并有线直连）。
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONDONTWRITEBYTECODE = '1'

$Root = Split-Path -Parent $PSScriptRoot
$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
$ToolDir = Join-Path $Root 'tool'
$HexPath = Join-Path $Root 'firmware\UltraWolves_Fenrir_Asym_8K_v1.00.39.00.hex'
$S4Gate = Join-Path $Root 'firmware\s4_bootloader_B0.02.03.00_verified.json'
$ExpectedSha = 'F12621981F4AE57C8624606F60548827B2304D89AD647795224809F90346F8BD'

if (-not (Test-Path $VenvPy)) { throw '请先运行 scripts\00_环境安装.ps1 初始化环境。' }
$env:PYTHONPATH = $ToolDir

if (-not (Test-Path $HexPath)) { throw "未找到固件文件: $HexPath" }
$actualSha = (Get-FileHash $HexPath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualSha -ne $ExpectedSha) {
    throw "固件 SHA-256 校验不一致！期望 $ExpectedSha，实际 $actualSha，拒绝刷写。"
}

Write-Host '=== 第 1 步：只读安全预检 (--dry-run) ===' -ForegroundColor Cyan
Write-Host '提示：请确认已拔掉 8K 无线接收器、仅用 USB-C 线连接鼠标本体，并关闭官方驱动/WebHID页面。' -ForegroundColor Yellow
& $VenvPy -B -m fenrir.flasher flash-phase3plus --hex $HexPath --s4-canary-report $S4Gate
if ($LASTEXITCODE -ne 0) {
    throw '安全预检未通过，已自动中止（0 写入）。请检查上面的报错信息。'
}

Write-Host ''
$confirm = Read-Host '预检通过！确认开始刷入 UltraWolves 增强固件？全程约 50 秒切勿拔线（输入大写的 YES 继续）'
if ($confirm -ne 'YES') {
    Write-Host '已取消刷写（0 写入）。' -ForegroundColor Yellow
    exit 0
}

$backupDir = Join-Path $Root 'backups'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$reportPath = Join-Path $backupDir ("flash_phase3plus_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Host '=== 第 2 步：正在执行有线刷写 (3,968 包 + 逐字节校验)... ===' -ForegroundColor Cyan
& $VenvPy -B -m fenrir.flasher flash-phase3plus --hex $HexPath --s4-canary-report $S4Gate --yes --confirm-phase3plus-s6 --report $reportPath
if ($LASTEXITCODE -ne 0) {
    throw '刷写过程中出错！请勿拔线，查看上方错误信息并对照 docs\01_刷入固件与安全回滚教程.md 处理。'
}
Write-Host "刷写成功并已回到 0x3508 正常模式！报告已保存至: $reportPath" -ForegroundColor Green