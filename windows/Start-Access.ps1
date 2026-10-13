param([ValidateSet('demo','ad')][string]$Mode = 'demo', [int]$Port = 8765)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:FK_MODE = $Mode
if ($Mode -eq 'ad') {
    foreach ($name in @('FK_MASTER_KEY','FK_AD_SERVER','FK_AD_OU','FK_AD_UPN_SUFFIX','FK_TRUSTED_HOSTS')) {
        if (-not [Environment]::GetEnvironmentVariable($name)) { throw "Configura $name antes de iniciar en modo AD." }
    }
    Import-Module ActiveDirectory
}
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear el entorno Python.' }
    & .venv\Scripts\python.exe -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'No se pudieron instalar las dependencias.' }
}
$configured = & .venv\Scripts\python.exe -c 'from app import create_app; import sqlite3; a=create_app(); print(bool(sqlite3.connect(a.db_path).execute("SELECT 1 FROM admin").fetchone()))'
if ($LASTEXITCODE -ne 0) { throw 'La configuración de arranque es inválida.' }
if ($configured -ne 'True') {
    & .venv\Scripts\python.exe app.py --init-admin
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo configurar el administrador.' }
}
& .venv\Scripts\python.exe app.py --port $Port
