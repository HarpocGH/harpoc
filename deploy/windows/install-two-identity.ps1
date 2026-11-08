#Requires -Version 5.1
# Harpoc deployment model B on Windows: the two-identity layout (README.md, "Deployment models").
# Run from an elevated Windows PowerShell:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy\windows\install-two-identity.ps1 -AgentUser <agent>[,<agent>...]
[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$VaultUser = 'harpoc',
  [string[]]$AgentUser = @(),
  [string]$ProgramData = $env:ProgramData,
  [SecureString]$Password,
  [switch]$Help
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Prog = 'install-two-identity.ps1'
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$UsersSid = 'S-1-5-32-545'
# Windows' reserved device names: a directory so named is the device, not a directory (RD-B7-5).
$ReservedDeviceName = '^(con|prn|aux|nul|com[1-9]|lpt[1-9])$'
$Usage = @"
Usage: $Prog [-VaultUser harpoc] [-AgentUser <agent>[,<agent>...]] [-ProgramData <path>]
         [-Password <SecureString>]

Creates the two-identity layout of Harpoc deployment model B on Windows. Idempotent: a
second run with the same arguments changes nothing.

  account <VaultUser>                  local account (default harpoc), password never
                                       expires, member of Users; created with the password
                                       you type (an existing account's password is left as
                                       it is: a reset would orphan its DPAPI master key)
  <ProgramData>\harpoc                 the vault account, SYSTEM, Administrators: full
  <ProgramData>\harpoc\vault           the vault account, SYSTEM, Administrators: full
  <ProgramData>\harpoc\run             the vault account, SYSTEM, Administrators: full
  <ProgramData>\harpoc\run\<agent>     the same, and the agent read and execute, which the
                                       files the vault writes there inherit (token.jwt)

Every directory's inherited entries are removed (icacls /inheritance:r), its owner is the
vault account, and an entry for any other account is removed. Agents get no entry on harpoc
or run: Windows lets every account pass through a directory it cannot list (Bypass traverse
checking), so an agent opens its own directory's files by their full path and lists no other
agent's directory. An agent user's name is its consumer name: lowercase letters, digits, '_'
and '-', not dash-led, at most 20, and not a Windows reserved device name (con, prn, aux, nul,
com1-com9, lpt1-lpt9; nor is the vault account's); each must be an existing local account that
is not an administrator. Agent accounts are not created. Run from an elevated PowerShell. No secret is
printed; the password is read as a SecureString and handed to New-LocalUser alone.

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

function Get-GroupSids([string]$Sid, [string]$Label) {
  try {
    return @(Get-LocalGroupMember -SID $Sid | ForEach-Object { $_.SID.Value })
  } catch {
    Stop-WithError "could not list the $Label group: $($_.Exception.Message)" 1
  }
}

if ($Help) {
  [Console]::Out.Write($Usage)
  exit 0
}

$agents = @($AgentUser | ForEach-Object { $_ -split ',' })
if ($VaultUser -cnotmatch '^[a-z0-9_][a-z0-9_-]{0,19}$') {
  Stop-WithError "not an account name (lowercase letters, digits, '_', '-'; not dash-led; at most 20): $VaultUser" 2
}
if ($VaultUser -match $ReservedDeviceName) {
  Stop-WithError "a Windows reserved device name cannot be the vault account: $VaultUser" 2
}
if ([string]::IsNullOrEmpty($ProgramData) -or -not [System.IO.Path]::IsPathRooted($ProgramData)) {
  Stop-WithError "-ProgramData must be an absolute path (default `$env:ProgramData)" 2
}
if (-not (Test-Path -LiteralPath $ProgramData -PathType Container)) {
  Stop-WithError "no such directory: $ProgramData" 2
}
$administratorSids = $null
$agentSids = @{}
foreach ($agent in $agents) {
  if ($agent -cnotmatch '^[a-z0-9_][a-z0-9_-]{0,19}$') {
    Stop-WithError "not a consumer name (lowercase letters, digits, '_', '-'; not dash-led; at most 20): $agent" 2
  }
  if ($agent -match $ReservedDeviceName) {
    Stop-WithError "a Windows reserved device name cannot be a consumer name: $agent" 2
  }
  if ($agent -eq $VaultUser) { Stop-WithError 'the vault user cannot be an agent user' 2 }
}
foreach ($agent in $agents) {
  $account = Get-LocalUser -Name $agent -ErrorAction SilentlyContinue
  if ($null -eq $account) { Stop-WithError "no such local account: $agent" 2 }
  if ($null -eq $administratorSids) { $administratorSids = Get-GroupSids $AdministratorsSid 'Administrators' }
  if ($administratorSids -contains $account.SID.Value) {
    Stop-WithError "an administrator cannot be an agent user: $agent" 2
  }
  $agentSids[$agent] = $account.SID.Value
}
$base = Join-Path $ProgramData 'harpoc'
$run = Join-Path $base 'run'
foreach ($path in @($base, (Join-Path $base 'vault'), $run) + @($agents | ForEach-Object { Join-Path $run $_ })) {
  $item = Get-ExistingItem $path
  if ($null -ne $item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Stop-WithError "$path is a reparse point (junction or symbolic link); remove it" 2
  }
  if ($null -ne $item -and ($item.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
    Stop-WithError "$path exists and is not a directory; remove it" 2
  }
}

if (-not (Test-Elevated)) { Stop-WithError 'must run elevated (an Administrator PowerShell)' 1 }

$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$vaultAccount = Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue
if ($null -eq $vaultAccount) {
  if ($null -eq $Password) {
    $Password = Read-Host -AsSecureString -Prompt "Password for the new local account $VaultUser"
  }
  New-LocalUser -Name $VaultUser -Password $Password -PasswordNeverExpires -AccountNeverExpires -Description 'Harpoc vault (deployment model B)' | Out-Null
  $vaultAccount = Get-LocalUser -Name $VaultUser
  [Console]::Out.WriteLine("account $VaultUser created")
} else {
  if ((Get-GroupSids $AdministratorsSid 'Administrators') -contains $vaultAccount.SID.Value) {
    Stop-WithError "the vault account must not be an administrator: $VaultUser" 2
  }
  [Console]::Out.WriteLine("account $VaultUser exists (its password is unchanged)")
}
$vaultSid = $vaultAccount.SID.Value
if (-not (@(Get-GroupSids $UsersSid 'Users') -contains $vaultSid)) {
  Add-LocalGroupMember -SID $UsersSid -Member $vaultSid
}

function Set-HarpocDirectory([string]$Path, [string]$AgentSid) {
  $existing = Get-ExistingItem $Path
  if ($null -ne $existing -and ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    Stop-WithError "$Path is a reparse point (junction or symbolic link); remove it" 2
  }
  if ($null -ne $existing -and ($existing.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
    Stop-WithError "$Path exists and is not a directory; remove it" 2
  }
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
  if ($null -ne $existing) {
    foreach ($rule in (Get-Acl -LiteralPath $Path).GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Deny') {
        Stop-WithError "$Path carries a deny entry for $($rule.IdentityReference.Value); remove it" 1
      }
    }
  }
  $allowed = @($vaultSid, $SystemSid, $AdministratorsSid)
  $grants = @("*${vaultSid}:(OI)(CI)F", "*${SystemSid}:(OI)(CI)F", "*${AdministratorsSid}:(OI)(CI)F")
  if ($AgentSid -ne '') {
    $allowed += $AgentSid
    $grants += "*${AgentSid}:(OI)(CI)(RX)"
  }
  & $icacls $Path /inheritance:r /grant:r @grants | Out-Null
  if ($LASTEXITCODE -ne 0) { Stop-WithError "icacls /grant:r failed on $Path (exit $LASTEXITCODE)" 1 }
  $acl = Get-Acl -LiteralPath $Path
  foreach ($rule in $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
    $sid = $rule.IdentityReference.Value
    if ($allowed -notcontains $sid) {
      & $icacls $Path /remove "*$sid" | Out-Null
      if ($LASTEXITCODE -ne 0) { Stop-WithError "icacls /remove failed on $Path (exit $LASTEXITCODE)" 1 }
    }
  }
  & $icacls $Path /setowner "*$vaultSid" | Out-Null
  if ($LASTEXITCODE -ne 0) { Stop-WithError "icacls /setowner failed on $Path (exit $LASTEXITCODE)" 1 }
  [Console]::Out.WriteLine("$Path $((Get-Acl -LiteralPath $Path).Sddl)")
}

Set-HarpocDirectory $base ''
Set-HarpocDirectory (Join-Path $base 'vault') ''
Set-HarpocDirectory $run ''
foreach ($agent in $agents) {
  Set-HarpocDirectory (Join-Path $run $agent) $agentSids[$agent]
}
