# One command for the whole lab on Windows, through WSL (Docker Desktop with the WSL 2 back end).
# Usage: .\run.ps1 [S0 S1 S2L TRAP]   (default: all four)
param([string[]]$Steps = @("S0", "S1", "S2L", "TRAP"))
$ErrorActionPreference = "Stop"
if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Error "WSL is required: the lab scripts run under Linux. Install WSL and Docker Desktop, then try again."
}
$here = (wsl wslpath -a ($PSScriptRoot -replace '\\', '/')).Trim()
wsl bash -lc "cd '$here' && ./run.sh $($Steps -join ' ')"
exit $LASTEXITCODE
