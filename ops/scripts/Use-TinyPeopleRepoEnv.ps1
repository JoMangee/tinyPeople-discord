param(
    [string]$KeyPath = "",
    [string]$HostName = "",
    [string]$HostUser = "",
    [int]$Port = 0,
    [bool]$PersistLocalGitConfig = $true,
    [switch]$Push
)

$ErrorActionPreference = "Stop"

# Environment discovery
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$sshAgentService = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
$sshAgentRunning = $sshAgentService -and $sshAgentService.Status -eq 'Running'
if (-not $isAdmin -and -not $sshAgentRunning) {
    Write-Host "INFO: Non-admin session, ssh-agent not running. Using SSH_ASKPASS dialog for passphrase."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$localEnvFile = Join-Path $repoRoot "ops/.env"

function Get-LocalEnvMap {
    param([string]$Path)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $map
    }

    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }
        $name = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($name) {
            $map[$name] = $value
        }
    }
    return $map
}

function Pick-Setting {
    param(
        [string]$Explicit,
        [string]$FromFile,
        [string]$FromEnv,
        [string]$Fallback = ""
    )
    if ($Explicit) { return $Explicit }
    if ($FromFile) { return $FromFile }
    if ($FromEnv) { return $FromEnv }
    return $Fallback
}

function Pick-IntSetting {
    param(
        [int]$Explicit,
        [string]$FromFile,
        [string]$FromEnv,
        [int]$Fallback
    )
    if ($Explicit -gt 0) { return $Explicit }
    foreach ($candidate in @($FromFile, $FromEnv)) {
        if ($candidate -and ($candidate -as [int])) {
            $value = [int]$candidate
            if ($value -gt 0) {
                return $value
            }
        }
    }
    return $Fallback
}

$localEnv = Get-LocalEnvMap -Path $localEnvFile

$KeyPath = Pick-Setting -Explicit $KeyPath -FromFile $localEnv["TP_SSH_KEY_PATH"] -FromEnv $env:TP_SSH_KEY_PATH
$HostName = Pick-Setting -Explicit $HostName -FromFile $localEnv["TP_SSH_HOST"] -FromEnv $env:TP_SSH_HOST -Fallback "example.com"
$HostUser = Pick-Setting -Explicit $HostUser -FromFile $localEnv["TP_SSH_USER"] -FromEnv $env:TP_SSH_USER -Fallback "user"
$Port = Pick-IntSetting -Explicit $Port -FromFile $localEnv["TP_SSH_PORT"] -FromEnv $env:TP_SSH_PORT -Fallback 22

if (-not $KeyPath) {
    throw "SSH key path not set. Provide -KeyPath, set TP_SSH_KEY_PATH env var, or add TP_SSH_KEY_PATH to ops/.env (ignored by git)."
}

$homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } elseif ($HOME) { $HOME } else { throw "Unable to resolve home directory." }
$sshDir = Join-Path $homeDir ".ssh"
$knownHosts = Join-Path $sshDir "known_hosts"

function Test-PathAccessible {
    param([string]$Path)
    try {
        $null = Test-Path -LiteralPath $Path -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Ensure-File {
    param([string]$Path)
    if (-not (Test-PathAccessible $Path)) {
        New-Item -ItemType File -Path $Path -Force | Out-Null
    }
}

try {
    if (-not (Test-PathAccessible $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    }
    Ensure-File -Path $knownHosts
}
catch {
    $knownHosts = Join-Path $repoRoot ".git\known_hosts"
    Ensure-File -Path $knownHosts
}

$resolvedKeyPath = (Resolve-Path -LiteralPath $KeyPath).Path
$normalizedKeyPath = $resolvedKeyPath -replace "\\", "/"
$normalizedKnownHosts = $knownHosts -replace "\\", "/"
$askPassPath = (Join-Path $scriptDir "ssh-askpass.bat") -replace "\\", "/"
$env:TP_SSH_KEY_PATH = $normalizedKeyPath
$env:TP_SSH_HOST = $HostName
$env:TP_SSH_USER = $HostUser
$env:TP_SSH_PORT = [string]$Port
$env:GIT_TERMINAL_PROMPT = "1"
$env:SSH_ASKPASS = $askPassPath
$env:SSH_ASKPASS_REQUIRE = "force"
$env:GIT_SSH_COMMAND = "ssh -p $Port -o BatchMode=no -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -o NumberOfPasswordPrompts=1 -o UserKnownHostsFile=$normalizedKnownHosts -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $normalizedKeyPath"

if ($PersistLocalGitConfig) {
    git -C $repoRoot config --local core.sshCommand "ssh -p $Port -o BatchMode=no -o UserKnownHostsFile=$normalizedKnownHosts -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $normalizedKeyPath"
}

Write-Host "Repo root: $repoRoot"
Write-Host "Key path:  $normalizedKeyPath"
Write-Host "KnownHosts: $normalizedKnownHosts"
Write-Host "Host target: $HostUser@$HostName"
Write-Host "SSH port: $Port"
Write-Host "SSH_ASKPASS: $askPassPath"
Write-Host "GIT_SSH_COMMAND set for this shell session."
if ($PersistLocalGitConfig) {
    Write-Host "git core.sshCommand saved in local repo config."
}
Write-Host ""
if ($Push) {
    Write-Host "Running: git push cpanel-tinyPeople master"
    git -C $repoRoot push cpanel-tinyPeople master
} else {
    Write-Host "A GUI passphrase dialog will appear when git connects. Run:"
    Write-Host "  git push cpanel-tinyPeople master"
}
