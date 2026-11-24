<#
.SYNOPSIS
    一键初始化 UltraWolves 工具所需的独立 Python 虚拟环境与依赖。
#>
param(
    [string]$PythonPath = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONDONTWRITEBYTECODE = '1'

$Root = Split-Path -Parent $PSScriptRoot
$VenvDir = Join-Path $Root '.venv'
$VenvPy = Join-Path $VenvDir 'Scripts\python.exe'
$ToolDir = Join-Path $Root 'tool'
$ReqFile = Join-Path $ToolDir 'requirements.txt'

function Test-Python312 {
    param(
        [string]$Exe,
        [string[]]$BaseArgs = @()
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $probeArgs = @()
        if ($BaseArgs) { $probeArgs += $BaseArgs }
        $probeArgs += @('-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
        $out = & $Exe @probeArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $verLine = $out | Select-Object -First 1
        if ($null -eq $verLine) { return $null }
        $ver = $verLine.ToString().Trim()
        if ($ver -match '^(\d+)\.(\d+)\.(\d+)$') {
            $maj = [int]$Matches[1]
            $min = [int]$Matches[2]
            if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 12)) {
                return $ver
            }
        }
        return $null
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

function Find-UvExe {
    $cmd = Get-Command uv -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        return $cmd.Source
    }
    $fallbacks = @(
        (Join-Path $env:USERPROFILE '.local\bin\uv.exe'),
        (Join-Path $env:USERPROFILE '.cargo\bin\uv.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\uv.exe')
    )
    foreach ($p in $fallbacks) {
        if ($p -and (Test-Path $p)) {
            return $p
        }
    }
    return $null
}

Write-Host '=== UltraWolves 工具环境安装 ===' -ForegroundColor Cyan

$uvExe = Find-UvExe

if (-not (Test-Path $VenvPy)) {
    if ($PythonPath) {
        if (-not (Test-Path $PythonPath)) {
            throw "指定的 Python 路径不存在: $PythonPath"
        }
        $ver = Test-Python312 -Exe $PythonPath
        if (-not $ver) {
            throw "指定的 Python 版本低于 3.12 或无法执行: $PythonPath"
        }
        Write-Host "使用指定 Python $ver ($PythonPath)" -ForegroundColor Green
        Write-Host "正在创建独立虚拟环境: $VenvDir"
        & $PythonPath -m venv $VenvDir
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) {
            throw '使用指定 Python 创建虚拟环境失败。'
        }
    }

    if (-not (Test-Path $VenvPy) -and $uvExe) {
        Write-Host "检测到 uv ($uvExe)，正在创建 Python 3.12+ 独立虚拟环境: $VenvDir" -ForegroundColor Green
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $uvExe venv --python '>=3.12' $VenvDir
            $uvExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($uvExit -ne 0 -or -not (Test-Path $VenvPy)) {
            Write-Host 'uv 创建虚拟环境未成功，尝试自动扫描系统 Python 3.12+ ...' -ForegroundColor Yellow
        }
    }

    if (-not (Test-Path $VenvPy)) {
        $selected = $null
        $cliCandidates = @(
            @{ Cmd = 'py'; Args = @('-3.14') },
            @{ Cmd = 'py'; Args = @('-3.13') },
            @{ Cmd = 'py'; Args = @('-3.12') },
            @{ Cmd = 'py'; Args = @('-3') },
            @{ Cmd = 'python'; Args = @() },
            @{ Cmd = 'python3'; Args = @() }
        )

        foreach ($c in $cliCandidates) {
            $cmdInfo = Get-Command $c.Cmd -ErrorAction SilentlyContinue
            if (-not $cmdInfo -or -not $cmdInfo.Source) { continue }
            if ($cmdInfo.Source -like '*\WindowsApps\*') { continue }
            $ver = Test-Python312 -Exe $cmdInfo.Source -BaseArgs $c.Args
            if ($ver) {
                $selected = @{ Cmd = $cmdInfo.Source; Args = $c.Args; Ver = $ver }
                break
            }
        }

        if (-not $selected) {
            $globPatterns = @(
                (Join-Path $env:APPDATA 'uv\python\cpython-3.1[2-9]*\python.exe'),
                (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python31[2-9]*\python.exe'),
                'C:\Program Files\Python31[2-9]*\python.exe',
                'C:\Python31[2-9]*\python.exe',
                (Join-Path $env:USERPROFILE 'scoop\apps\python*\current\python.exe'),
                (Join-Path $env:LOCALAPPDATA 'miniconda3\python.exe'),
                (Join-Path $env:USERPROFILE 'miniconda3\python.exe'),
                (Join-Path $env:USERPROFILE 'anaconda3\python.exe'),
                (Join-Path $env:LOCALAPPDATA 'anaconda3\python.exe')
            )
            $foundExes = @()
            foreach ($pat in $globPatterns) {
                $globHits = Get-Item -Path $pat -ErrorAction SilentlyContinue
                if ($globHits) { $foundExes += $globHits }
            }
            foreach ($item in ($foundExes | Sort-Object -Property FullName -Descending)) {
                $ver = Test-Python312 -Exe $item.FullName
                if ($ver) {
                    $selected = @{ Cmd = $item.FullName; Args = @(); Ver = $ver }
                    break
                }
            }
        }

        if (-not $selected) {
            throw '未找到 Python 3.12 或更高版本！请先从 python.org 安装 Python 3.12+（勾选 Add to PATH），或安装 uv，或通过 -PythonPath "C:\path\to\python.exe" 指定路径。'
        }

        $argHint = if ($selected.Args.Count -gt 0) { " $($selected.Args -join ' ')" } else { '' }
        Write-Host "检测到 Python $($selected.Ver) ($($selected.Cmd)$argHint)" -ForegroundColor Green
        Write-Host "正在创建独立虚拟环境: $VenvDir"
        $venvArgs = $selected.Args + @('-m', 'venv', $VenvDir)
        & $selected.Cmd @venvArgs
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) {
            throw '创建虚拟环境失败。'
        }
    }
} else {
    Write-Host "已存在虚拟环境: $VenvDir" -ForegroundColor Yellow
}

Write-Host '正在安装依赖 (hidapi / unicorn / capstone)...'
if ($uvExe) {
    & $uvExe pip install --python $VenvPy -r $ReqFile
} else {
    & $VenvPy -m pip install -r $ReqFile
}
if ($LASTEXITCODE -ne 0) {
    throw '依赖安装失败，请检查网络连接或 pip 源配置。'
}

# 写入 .pth 以便任意目录调用 .venv python -B -m fenrir.* 都可无需额外编译安装
$sitePkgs = (& $VenvPy -B -c "import sysconfig; print(sysconfig.get_path('purelib'))").Trim()
$pthPath = Join-Path $sitePkgs 'fenrir_community_tool.pth'
[System.IO.File]::WriteAllText($pthPath, "$ToolDir`r`n", (New-Object System.Text.UTF8Encoding $false))

Write-Host '正在运行离线自检 (adv fps-presets & hid)...'
& $VenvPy -B -c "import hid, unicorn, capstone; print('DEPS_OK')"
if ($LASTEXITCODE -ne 0) { throw '依赖导入校验失败。' }
$presetsJson = & $VenvPy -B -m fenrir.config adv fps-presets | ConvertFrom-Json
Write-Host ("环境就绪！已内置 {0} 档 PAW3950 FPS 预设 (custom_code={1})。" -f $presetsJson.count, $presetsJson.custom_code) -ForegroundColor Green