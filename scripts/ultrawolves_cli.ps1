<#
.SYNOPSIS
    自动定位当前鼠标/接收器 HID 路径并转发 fenrir.config 参数命令的便捷包装器。
.EXAMPLE
    .\scripts\ultrawolves_cli.ps1 -Mode wireless adv status
    .\scripts\ultrawolves_cli.ps1 -Mode wired adv fix-a --enable --yes
    .\scripts\ultrawolves_cli.ps1 -Mode wireless adv persist --action save --yes
    .\scripts\ultrawolves_cli.ps1 -Mode wireless set --polling-rate 128 --yes
#>
param(
    [ValidateSet('wired', 'wireless')]
    [string]$Mode = 'wireless',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ArgsRest
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONDONTWRITEBYTECODE = '1'

$Root = Split-Path -Parent $PSScriptRoot
$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
$ToolDir = Join-Path $Root 'tool'
if (-not (Test-Path $VenvPy)) { throw '请先运行 scripts\00_环境安装.ps1 初始化环境。' }
$env:PYTHONPATH = $ToolDir

if (-not $ArgsRest -or $ArgsRest.Count -eq 0 -or $ArgsRest[0] -in @('-h', '--help')) {
    & $VenvPy -B -m fenrir.config --help
    exit $LASTEXITCODE
}

$noTargetTop = @('selftest')
$noTargetAdv = @('fps-presets', 'selftest')
$needsTarget = $true
if ($ArgsRest[0] -in $noTargetTop) {
    $needsTarget = $false
} elseif ($ArgsRest[0] -eq 'adv' -and ($ArgsRest.Count -lt 2 -or $ArgsRest[1] -in $noTargetAdv -or $ArgsRest[1] -in @('-h', '--help'))) {
    $needsTarget = $false
} elseif ($ArgsRest -contains '--target' -or $ArgsRest -contains '--path' -or $ArgsRest -contains '-h' -or $ArgsRest -contains '--help') {
    $needsTarget = $false
}

if (-not $needsTarget) {
    & $VenvPy -B -m fenrir.config @ArgsRest
    exit $LASTEXITCODE
}

$pidHex = if ($Mode -eq 'wired') { '0x3508' } else { '0x3517' }
$cls = if ($Mode -eq 'wired') { 'mouse_app' } else { 'receiver_app' }
$target = if ($Mode -eq 'wired') { 'mouse-usb' } else { 'receiver-to-mouse' }

$enumOut = (& $VenvPy -B -m fenrir.probe enumerate) -join "`n"
$pattern = "0x33E4:$pidHex \| class=$cls \| if=2 up=0xFFFF usage=0x0000 exact_feat=True[^\n]*\n\s+path=(\S+)"
$m = [regex]::Match($enumOut, $pattern)
if (-not $m.Success) {
    throw "未检测到 $Mode 模式下的精确 Feature 接口 (0x33E4:$pidHex)。请确认鼠标已连接且开机。"
}
$hidPath = $m.Groups[1].Value.Trim()

if ($ArgsRest[0] -eq 'adv') {
    $head = @($ArgsRest[0], $ArgsRest[1])
    $tail = if ($ArgsRest.Count -gt 2) { $ArgsRest[2..($ArgsRest.Count - 1)] } else { @() }
} else {
    $head = @($ArgsRest[0])
    $tail = if ($ArgsRest.Count -gt 1) { $ArgsRest[1..($ArgsRest.Count - 1)] } else { @() }
}

$finalArgs = $head + @('--target', $target, '--path', $hidPath) + $tail
& $VenvPy -B -m fenrir.config @finalArgs
exit $LASTEXITCODE