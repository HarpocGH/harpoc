#Requires -Version 5.1
#Requires -PSEdition Desktop
# Harpoc deployment model B on Windows: enrol the unlock key sealed with DPAPI under the vault
# account (README.md, "Deployment models"). Run from an elevated Windows PowerShell after
# install-two-identity.ps1 and the vault's init:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy\windows\enroll-unlock-key.ps1
[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$VaultUser = 'harpoc',
  [string]$Node = '',
  [string]$Cli = '',
  [string]$ProgramData = $env:ProgramData,
  [string]$Out = '',
  [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'

# Import an in-box module by its manifest's path under $PSHOME, never through PSModulePath;
# a module not found there exactly once ends the script (exit 1).
function Import-InBoxModule([string]$Name) {
  $manifests = @()
  try {
    $manifests = [System.IO.Directory]::GetFiles([System.IO.Path]::Combine($PSHOME, 'Modules', $Name), "$Name.psd1", [System.IO.SearchOption]::AllDirectories)
  } catch {
    $manifests = @()
  }
  if ($manifests.Count -ne 1) {
    [Console]::Error.WriteLine("the in-box module $Name was not found under $PSHOME")
    exit 1
  }
  Import-Module -Name $manifests[0]
}

Import-InBoxModule 'Microsoft.PowerShell.Utility'
Import-InBoxModule 'Microsoft.PowerShell.Management'

$Prog = 'enroll-unlock-key.ps1'
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$Usage = @"
Usage: $Prog [-VaultUser harpoc] [-Node <node.exe>] [-Cli <the cli package directory>]
         [-ProgramData <path>] [-Out <path>]

Enrols the unlock key of the vault in <ProgramData>\harpoc\vault and seals it with DPAPI under
the local account <VaultUser> (default harpoc), the account the daemon runs as: it asks for that
account's Windows password, then starts, as that account and with its profile loaded,

  <node> <cli>\dist\index.js --vault-dir <ProgramData>\harpoc\vault unlock-key enroll
    --out <Out> --dpapi

in a new console window, where you type the vault's master password. The key is sealed in that
process and written only sealed (default <Out>: <ProgramData>\harpoc\vault\unlock.key.dpapi);
no plaintext key file is ever written. Re-enrolling replaces the vault's enrolled key; remove
the old sealed file first (this script never overwrites one), then restart the daemon.
<node> defaults to the node.exe on PATH, <cli> to $env:ProgramFiles\harpoc\packages\cli: both
must be readable by the vault account. No byte of the key and no password is printed.

Run it in an elevated PowerShell window on the machine's own desktop (the console or a Remote
Desktop session): it asks for a password and opens a console window. If the launch as
<VaultUser> ends before the CLI starts with exit 0xC0000142 - seen for the same Win32 call
from a scheduled task - the script says so; nothing is sealed.

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

# The item at a path, or $null; before elevation a path this account may not open reads as absent.
function Get-ExistingItem([string]$Path) {
  try {
    return Get-Item -LiteralPath $Path -Force
  } catch [System.Management.Automation.ItemNotFoundException] {
    return $null
  } catch [System.UnauthorizedAccessException] {
    if (Test-Elevated) { throw }
    return $null
  }
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

if ($VaultUser -cnotmatch '^[a-z0-9_][a-z0-9_-]{0,19}\z') {
  Stop-WithError "not an account name (lowercase letters, digits, '_', '-'; not dash-led; at most 20): $VaultUser" 2
}
if ([string]::IsNullOrEmpty($ProgramData) -or -not [System.IO.Path]::IsPathRooted($ProgramData)) {
  Stop-WithError "-ProgramData must be an absolute path (default `$env:ProgramData)" 2
}
$vaultDir = Join-Path (Join-Path $ProgramData 'harpoc') 'vault'
if ($Out -eq '') { $Out = Join-Path $vaultDir 'unlock.key.dpapi' }
if ($Out.StartsWith('-') -or -not [System.IO.Path]::IsPathRooted($Out)) {
  Stop-WithError "-Out must be an absolute path: $Out" 2
}
if ($null -ne (Get-ExistingItem $Out)) {
  Stop-WithError "-Out: $Out exists; the sealed key is written to a new file only (remove it after revoking, or name another)" 2
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

if (-not (Test-Elevated)) { Stop-WithError 'must run elevated (an Administrator PowerShell)' 1 }
Import-InBoxModule 'Microsoft.PowerShell.LocalAccounts'
Import-InBoxModule 'Microsoft.PowerShell.Security'
if (-not (Test-Path -LiteralPath (Split-Path -Parent $Out) -PathType Container)) {
  Stop-WithError "-Out: no such directory: $(Split-Path -Parent $Out)" 2
}
$vaultAccount = Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue
if ($null -eq $vaultAccount) {
  Stop-WithError "no such local account: $VaultUser (install-two-identity.ps1 creates it)" 2
}

$credential = Get-Credential -UserName "$env:COMPUTERNAME\$VaultUser" -Message "Windows password of ${VaultUser}, the account the unlock key is sealed for"
if ($null -eq $credential) { Stop-WithError 'no credential was entered (the prompt was cancelled); nothing sealed' 1 }
if (@($VaultUser, ".\$VaultUser", "$([Environment]::MachineName)\$VaultUser") -notcontains $credential.UserName) {
  Stop-WithError "the credential names another account than $VaultUser; nothing sealed" 1
}
$arguments = @($entry, '--vault-dir', $vaultDir, 'unlock-key', 'enroll', '--out', $Out, '--dpapi')
$argumentLine = ($arguments | ForEach-Object { ConvertTo-Argument $_ }) -join ' '
$process = Start-Process -FilePath $Node -ArgumentList $argumentLine -Credential $credential -LoadUserProfile -WorkingDirectory (Split-Path -Parent $vaultDir) -Wait -PassThru
if ($process.ExitCode -eq -1073741502) {
  Stop-WithError "the CLI could not start as $VaultUser (exit 0xC0000142: the process could not initialise): a launch as another account needs this session's desktop - run this script in an elevated PowerShell window on the machine's own desktop (the console or a Remote Desktop session), not from a scheduled task or a service; nothing sealed" 1
}
if ($process.ExitCode -ne 0) {
  Stop-WithError "the enrolment as $VaultUser failed (exit $($process.ExitCode)); nothing sealed" 1
}
if (-not (Test-Path -LiteralPath $Out -PathType Leaf)) {
  Stop-WithError "the enrolment as $VaultUser wrote no $Out" 1
}
$trusted = @($vaultAccount.SID.Value, $SystemSid, $AdministratorsSid)
$acl = Get-Acl -LiteralPath $Out
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value) {
    Stop-WithError "$Out grants access to $($rule.IdentityReference.Value); the daemon would refuse it" 1
  }
}
[Console]::Out.WriteLine("$Out written (sealed with DPAPI for $VaultUser)")
[Console]::Out.WriteLine("the daemon reads it as $VaultUser with server start --unlock-key-dpapi $Out (register-service.ps1)")
