#Requires -Version 5.1
# Harpoc deployment model B on Windows: the vault daemon as a startup Scheduled Task running as
# the vault account, unlocked from the DPAPI-sealed unlock key (README.md, "Deployment models").
# Run from an elevated Windows PowerShell after install-two-identity.ps1 and enroll-unlock-key.ps1:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy\windows\register-service.ps1 [-Proxy] [-SshAgent]
[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$VaultUser = 'harpoc',
  [string]$Node = '',
  [string]$Cli = '',
  [string]$ProgramData = $env:ProgramData,
  [switch]$Proxy,
  [switch]$SshAgent,
  [string[]]$IssueToken = @(),
  [SecureString]$Password,
  [switch]$DryRun,
  [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Prog = 'register-service.ps1'
$TaskName = 'Harpoc'
$Usage = @"
Usage: $Prog [-VaultUser harpoc] [-Node <node.exe>] [-Cli <the cli package directory>]
         [-ProgramData <path>] [-Proxy] [-SshAgent] [-IssueToken <spec>] [-DryRun]
         [-Password <SecureString>]

Registers the Scheduled Task '$TaskName': at startup, as the local account <VaultUser>
(default harpoc) with its password stored by the Task Scheduler (logon type Password), it runs

  <node> <cli>\dist\index.js --vault-dir <ProgramData>\harpoc\vault server start --rest
    --session memory --unlock-key-dpapi <ProgramData>\harpoc\vault\unlock.key.dpapi
    --runtime-dir <ProgramData>\harpoc\run [--proxy] [--ssh-agent] [--issue-token <spec>]...

with no execution time limit (the Task Scheduler's default stops a task after 72 hours), on
battery too, one instance, and at most two restarts a minute apart: each failed start with a
wrong or revoked key counts against the lockout the password shares (the fifth locks it).
Stop-ScheduledTask ends the daemon without its shutdown path (no server.stop row); lock it
first with harpoc --url <base> --token-file <admin token> lock. <node> defaults to the node.exe
on PATH, <cli> to $env:ProgramFiles\harpoc\packages\cli: both must be readable by the vault
account. -DryRun prints the registration and registers nothing. The password is read as a
SecureString and handed to Register-ScheduledTask alone; no secret is printed. A re-run
replaces the task. For several -IssueToken specs use -Command "& '<this script>' -IssueToken
'<spec>','<spec>'" (-File passes one string per parameter).

Exit status: 0 done, 1 not elevated or a command failed, 2 usage error.
"@

function Stop-WithError([string]$Message, [int]$Code) {
  [Console]::Error.WriteLine("${Prog}: $Message")
  exit $Code
}

function Test-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# One argument as the Windows C runtime parses a command line (CommandLineToArgvW's rules).
function ConvertTo-Argument([string]$Value) {
  if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
  $text = '"'
  $slashes = 0
  foreach ($ch in $Value.ToCharArray()) {
    if ($ch -eq '\') {
      $slashes++
    } elseif ($ch -eq '"') {
      $text += ('\' * (2 * $slashes + 1)) + '"'
      $slashes = 0
    } else {
      $text += ('\' * $slashes) + $ch
      $slashes = 0
    }
  }
  return $text + ('\' * (2 * $slashes)) + '"'
}

if ($Help) {
  [Console]::Out.Write($Usage)
  exit 0
}

if ($VaultUser -cnotmatch '^[a-z0-9_][a-z0-9_-]{0,19}$') {
  Stop-WithError "not an account name (lowercase letters, digits, '_', '-'; not dash-led; at most 20): $VaultUser" 2
}
if ([string]::IsNullOrEmpty($ProgramData) -or -not [System.IO.Path]::IsPathRooted($ProgramData)) {
  Stop-WithError "-ProgramData must be an absolute path (default `$env:ProgramData)" 2
}
if ($Node -eq '') {
  $found = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $found) { Stop-WithError 'node.exe is not on PATH; name it with -Node <path>' 2 }
  $Node = $found.Source
}
if (-not [System.IO.Path]::IsPathRooted($Node) -or -not (Test-Path -LiteralPath $Node -PathType Leaf)) {
  Stop-WithError "-Node: no such file: $Node" 2
}
if ($Cli -eq '') { $Cli = Join-Path $env:ProgramFiles 'harpoc\packages\cli' }
$entry = Join-Path $Cli 'dist\index.js'
if (-not [System.IO.Path]::IsPathRooted($entry) -or -not (Test-Path -LiteralPath $entry -PathType Leaf)) {
  Stop-WithError "-Cli: no built CLI at $entry (pnpm build)" 2
}
foreach ($spec in $IssueToken) {
  if ($spec -eq '' -or $spec.StartsWith('-') -or $spec.Contains('"')) {
    Stop-WithError "-IssueToken: not a spec: '$spec' (agent=<name>,file=<path>,scope=...,secrets=...)" 2
  }
}

$base = Join-Path $ProgramData 'harpoc'
$vaultDir = Join-Path $base 'vault'
$arguments = @(
  $entry, '--vault-dir', $vaultDir, 'server', 'start', '--rest', '--session', 'memory',
  '--unlock-key-dpapi', (Join-Path $vaultDir 'unlock.key.dpapi'),
  '--runtime-dir', (Join-Path $base 'run')
)
if ($Proxy) { $arguments += '--proxy' }
if ($SshAgent) { $arguments += '--ssh-agent' }
foreach ($spec in $IssueToken) { $arguments += @('--issue-token', $spec) }
$argumentLine = ($arguments | ForEach-Object { ConvertTo-Argument $_ }) -join ' '
$principalName = "$env:COMPUTERNAME\$VaultUser"
$settingsLine = 'ExecutionTimeLimit=PT0S RestartCount=2 RestartInterval=PT1M MultipleInstances=IgnoreNew StartWhenAvailable AllowStartIfOnBatteries DontStopIfGoingOnBatteries'

if ($DryRun) {
  [Console]::Out.WriteLine("task $TaskName")
  [Console]::Out.WriteLine("principal $principalName (logon type Password, run level Limited)")
  [Console]::Out.WriteLine("execute $Node")
  [Console]::Out.WriteLine("argument $argumentLine")
  [Console]::Out.WriteLine("working directory $base")
  [Console]::Out.WriteLine('trigger at startup')
  [Console]::Out.WriteLine("settings $settingsLine")
  [Console]::Out.WriteLine('dry run: nothing registered')
  exit 0
}

if (-not (Test-Elevated)) { Stop-WithError 'must run elevated (an Administrator PowerShell)' 1 }
if ($null -eq (Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue)) {
  Stop-WithError "no such local account: $VaultUser (install-two-identity.ps1 creates it)" 2
}
if ($null -eq $Password) {
  $Password = Read-Host -AsSecureString -Prompt "Windows password of $principalName (stored by the Task Scheduler)"
}

$action = New-ScheduledTaskAction -Execute $Node -Argument $argumentLine -WorkingDirectory $base
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$plain = (New-Object System.Net.NetworkCredential('', $Password)).Password
try {
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User $principalName -Password $plain -RunLevel Limited -Force | Out-Null
} finally {
  $plain = $null
}
[Console]::Out.WriteLine("task $TaskName registered: at startup as $principalName")
[Console]::Out.WriteLine("start it now with Start-ScheduledTask -TaskName $TaskName")
