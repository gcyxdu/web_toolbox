$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (Test-Path '.runtime\visualfl-env\Scripts\python.exe') {
    $port=Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue
    if (-not $port) {
        Start-Process -FilePath (Join-Path $projectRoot '.runtime\visualfl-env\Scripts\python.exe') -ArgumentList @('-m','uvicorn','backend.app:app','--host','127.0.0.1','--port','8000') -WorkingDirectory (Join-Path $projectRoot 'modules\VisualFL') -WindowStyle Hidden
    }
}
$portal=Get-NetTCPConnection -State Listen -LocalPort 8090 -ErrorAction SilentlyContinue
if ($portal) { Write-Host '8090 已有服务，请访问 http://127.0.0.1:8090' } else { python portal\serve.py }
