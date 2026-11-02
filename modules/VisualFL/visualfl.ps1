param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'setup', 'plan')][string]$Action = 'start',
    [int]$Port = 8000,
    [switch]$NoBuild,
    [switch]$SkipFrontend,
    [ValidateSet('auto', 'cpu', 'cu118')][string]$TorchVariant = 'auto'
)
$ErrorActionPreference = 'Stop'

# Shared Conda entry point. No machine-specific installation paths are stored.
function Invoke-VisualFLConda {
    param([Parameter(Mandatory = $true)][string[]]$CondaArguments)

    $basePython = $env:CONDA_PYTHON_EXE
    if (-not $basePython -or -not (Test-Path -LiteralPath $basePython)) {
        $condaCommand = Get-Command conda -ErrorAction SilentlyContinue
        if (-not $condaCommand) {
            throw 'Conda not found. Open Anaconda PowerShell Prompt or install Miniconda.'
        }
        $candidate = Split-Path -Parent $condaCommand.Source
        $basePython = $null
        for ($level = 0; $candidate -and $level -lt 4; $level++) {
            $python = Join-Path $candidate 'python.exe'
            if ((Test-Path -LiteralPath $python) -and
                (Test-Path -LiteralPath (Join-Path $candidate 'Lib\site-packages\conda\__main__.py'))) {
                $basePython = $python
                break
            }
            $candidate = Split-Path -Parent $candidate
        }
        if (-not $basePython) {
            & $condaCommand @CondaArguments
            if ($LASTEXITCODE -ne 0) { throw 'Conda command failed.' }
            return
        }
    }

    # Works even when an old conda.exe launcher has a stale interpreter path.
    # Conda's Windows activation subprocesses inherit these settings.
    $env:CONDA_EXE = $basePython
    $env:_CE_M = '-m'
    $env:_CE_CONDA = 'conda'
    & $basePython -m conda @CondaArguments
    if ($LASTEXITCODE -ne 0) { throw 'Conda command failed. See the output above.' }
}

function Get-VisualFLTorchProfile {
    param([ValidateSet('auto', 'cpu', 'cu118')][string]$Variant = 'auto')
    if ($Variant -ne 'auto') { return $Variant }
    $nvidia = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if ($nvidia) {
        $rows = & $nvidia --query-gpu=driver_version,compute_cap --format=csv,noheader,nounits 2>$null
        if ($LASTEXITCODE -eq 0) {
            foreach ($row in $rows) {
                $fields = $row.Split(',')
                $driver = $null
                $capability = 0.0
                if ($fields.Count -eq 2 -and
                    [version]::TryParse($fields[0].Trim(), [ref]$driver) -and
                    [double]::TryParse($fields[1].Trim(), [Globalization.NumberStyles]::Float,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$capability) -and
                    $driver -ge [version]'520.06' -and $capability -ge 5.0 -and $capability -lt 10.0) {
                    return 'cu118'
                }
            }
        }
    }
    # The locked PyTorch 2.6 cu118 build does not support every GPU generation.
    return 'cpu'
}

if ($Action -in @('setup', 'plan')) {
    $torchProfile = Get-VisualFLTorchProfile -Variant $TorchVariant
    $packageIndex = 'https://mirrors.aliyun.com/pypi/simple/'
    $torchMirror = "https://mirrors.aliyun.com/pytorch-wheels/$torchProfile/"
    Write-Host "PyTorch: 2.6.0+$torchProfile; PyPI: $packageIndex; wheels: $torchMirror"
    if ($Action -eq 'plan') { return }
    Push-Location -LiteralPath $PSScriptRoot
    try {
        $environments = (Invoke-VisualFLConda -CondaArguments @('env', 'list', '--json')) | ConvertFrom-Json
        $existing = @($environments.envs | Where-Object { (Split-Path -Leaf $_) -eq 'visualfl' })
        if ($existing.Count -eq 0) {
            Invoke-VisualFLConda -CondaArguments @('env', 'create', '--file', 'environment.yml', '--yes')
        }
        Invoke-VisualFLConda -CondaArguments @('run', '--no-capture-output', '-n', 'visualfl', 'python', '-c',
            'import sys; assert sys.version_info[:2] == (3, 12), "visualfl requires Python 3.12"; print(sys.executable)')
        Invoke-VisualFLConda -CondaArguments @('run', '--no-capture-output', '-n', 'visualfl', 'python', '-m',
            'pip', '--isolated', 'install', '--no-cache-dir', '-r', 'requirements.txt', "torch==2.6.0+$torchProfile",
            '--index-url', $packageIndex, '--find-links', $torchMirror)
        Invoke-VisualFLConda -CondaArguments @('run', '--no-capture-output', '-n', 'visualfl', 'python', '-m', 'pip', 'check')
        if (-not $SkipFrontend) {
            & npm.cmd --prefix frontend ci --registry=https://registry.npmmirror.com
            if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
        }
        Write-Host 'Setup complete. Run .\visualfl.ps1 to build and start VisualFL.' -ForegroundColor Green
    } finally { Pop-Location }
    return
}

$workspacePath = $PSScriptRoot
$frontendPath = Join-Path $workspacePath 'frontend'
Push-Location -LiteralPath $workspacePath
try {
    Invoke-VisualFLConda -CondaArguments @('run', '--no-capture-output', '-n', 'visualfl', 'python', '-c',
        'import sys, torch, fastapi; assert sys.version_info[:2] == (3, 12), "visualfl requires Python 3.12"; print("Python environment: visualfl", sys.version.split()[0])')
    if (-not $NoBuild) {
        if (-not (Test-Path -LiteralPath (Join-Path $frontendPath 'node_modules'))) {
            throw 'Run npm.cmd --prefix frontend ci first.'
        }
        Push-Location -LiteralPath $frontendPath
        try {
            & node node_modules/typescript/bin/tsc -b
            if ($LASTEXITCODE -ne 0) { throw 'TypeScript check failed.' }
            & node node_modules/vite/bin/vite.js build
            if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        } finally { Pop-Location }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $frontendPath 'dist\index.html'))) {
        throw 'Missing frontend/dist/index.html. Run visualfl.ps1 without -NoBuild.'
    }
    Write-Host "VisualFL: http://127.0.0.1:$Port" -ForegroundColor Green
    Write-Host 'Press Ctrl+C to stop. Experiments are stored in data/.'
    Invoke-VisualFLConda -CondaArguments @('run', '--no-capture-output', '-n', 'visualfl', 'python', '-m',
        'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', "$Port")
} finally { Pop-Location }
