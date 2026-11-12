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
  [switch]$Unregister,
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

$Prog = 'register-service.ps1'
$TaskName = 'Harpoc'
$BatchLogonRight = 'SeBatchLogonRight'
$DenyBatchLogonRight = 'SeDenyBatchLogonRight'
$Usage = @"
Usage: $Prog [-VaultUser harpoc] [-Node <node.exe>] [-Cli <the cli package directory>]
         [-ProgramData <path>] [-Proxy] [-SshAgent] [-IssueToken <spec>] [-DryRun]
         [-Password <SecureString>]
       $Prog -Unregister [-VaultUser harpoc]

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

The Task Scheduler starts a task with a stored password only if its account may log on as a
batch job, which a member of Users alone may not: before it registers the task the script
grants <VaultUser> the user right Log on as a batch job ($BatchLogonRight) in the local
security policy, unless the account holds it already, and stops if the account itself is
denied it ($DenyBatchLogonRight). A denial that reaches the account through a group, or a
domain policy that rewrites the user rights, still keeps the task from starting.
-Unregister removes the task and that right (the account, the layout and the sealed key stay,
and a running daemon is not ended: lock and stop it first). It takes the right from the
account also where the account held it before this script ran. The right is granted before
the password is asked for and stays granted if the registration then fails or is aborted,
until -Unregister removes it.

Exit status: 0 done, 1 not elevated or a command failed, 2 usage error.
"@

# The user rights an account holds itself, by SID, through the Local Security Authority
# (LsaEnumerateAccountRights, LsaAddAccountRights, LsaRemoveAccountRights): Windows PowerShell
# 5.1 has no cmdlet for them. No secret passes through it.
$AccountRightsSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Harpoc.Deploy
{
    public static class AccountRights
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct LsaUnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaObjectAttributes
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint access, out IntPtr policy);

        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);

        [DllImport("advapi32.dll")]
        private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LsaUnicodeString[] rights, uint count);

        [DllImport("advapi32.dll")]
        private static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool all, LsaUnicodeString[] rights, uint count);

        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr buffer);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr handle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);

        private const uint PolicyCreateAccount = 0x00000010;
        private const uint PolicyLookupNames = 0x00000800;
        private const uint ErrorFileNotFound = 2;

        private static byte[] SidBytes(string sid)
        {
            SecurityIdentifier identifier = new SecurityIdentifier(sid);
            byte[] bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private static void Check(uint status, string call)
        {
            if (status == 0) return;
            int error = (int)LsaNtStatusToWinError(status);
            throw new Win32Exception(error, call + " failed (Win32 error " + error + ")");
        }

        private static IntPtr Open(uint access)
        {
            LsaObjectAttributes attributes = new LsaObjectAttributes();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LsaObjectAttributes));
            IntPtr policy;
            Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out policy), "LsaOpenPolicy");
            return policy;
        }

        public static string[] Enumerate(string sid)
        {
            IntPtr policy = Open(PolicyLookupNames);
            try
            {
                IntPtr buffer;
                uint count;
                uint status = LsaEnumerateAccountRights(policy, SidBytes(sid), out buffer, out count);
                if (status != 0 && LsaNtStatusToWinError(status) == ErrorFileNotFound) return new string[0];
                Check(status, "LsaEnumerateAccountRights");
                try
                {
                    string[] names = new string[count];
                    int size = Marshal.SizeOf(typeof(LsaUnicodeString));
                    for (int i = 0; i < names.Length; i++)
                    {
                        LsaUnicodeString item = (LsaUnicodeString)Marshal.PtrToStructure(new IntPtr(buffer.ToInt64() + (long)i * size), typeof(LsaUnicodeString));
                        names[i] = Marshal.PtrToStringUni(item.Buffer, item.Length / 2);
                    }
                    return names;
                }
                finally
                {
                    LsaFreeMemory(buffer);
                }
            }
            finally
            {
                LsaClose(policy);
            }
        }

        private static void Change(string sid, string right, bool add)
        {
            IntPtr policy = Open(PolicyLookupNames | PolicyCreateAccount);
            try
            {
                LsaUnicodeString[] rights = new LsaUnicodeString[1];
                rights[0].Buffer = Marshal.StringToHGlobalUni(right);
                rights[0].Length = (ushort)(right.Length * 2);
                rights[0].MaximumLength = (ushort)(right.Length * 2 + 2);
                try
                {
                    if (add)
                    {
                        Check(LsaAddAccountRights(policy, SidBytes(sid), rights, 1), "LsaAddAccountRights");
                        return;
                    }
                    uint status = LsaRemoveAccountRights(policy, SidBytes(sid), false, rights, 1);
                    if (status != 0 && LsaNtStatusToWinError(status) == ErrorFileNotFound) return;
                    Check(status, "LsaRemoveAccountRights");
                }
                finally
                {
                    Marshal.FreeHGlobal(rights[0].Buffer);
                }
            }
            finally
            {
                LsaClose(policy);
            }
        }

        public static void Add(string sid, string right)
        {
            Change(sid, right, true);
        }

        public static void Remove(string sid, string right)
        {
            Change(sid, right, false);
        }
    }
}
'@

function Stop-WithError([string]$Message, [int]$Code) {
  [Console]::Error.WriteLine("${Prog}: $Message")
  exit $Code
}

function Test-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# list, add or remove a user right of the account with this SID; a failure ends the script (exit 1).
function Invoke-AccountRights([string]$Operation, [string]$Sid, [string]$Right) {
  try {
    if ($null -eq ('Harpoc.Deploy.AccountRights' -as [type])) { Add-Type -TypeDefinition $AccountRightsSource }
    if ($Operation -eq 'list') { return @([Harpoc.Deploy.AccountRights]::Enumerate($Sid)) }
    if ($Operation -eq 'add') { [Harpoc.Deploy.AccountRights]::Add($Sid, $Right) }
    if ($Operation -eq 'remove') { [Harpoc.Deploy.AccountRights]::Remove($Sid, $Right) }
  } catch {
    $cause = $_.Exception
    while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
    Stop-WithError "could not $Operation the user rights of ${Sid}: $($cause.Message)" 1
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
$principalName = "$env:COMPUTERNAME\$VaultUser"

if ($Unregister) {
  if ($DryRun -or $Proxy -or $SshAgent -or $IssueToken.Count -gt 0 -or $Node -ne '' -or $Cli -ne '' -or $null -ne $Password -or $PSBoundParameters.ContainsKey('ProgramData')) {
    Stop-WithError '-Unregister takes -VaultUser alone' 2
  }
  if (-not (Test-Elevated)) { Stop-WithError 'must run elevated (an Administrator PowerShell)' 1 }
  Import-InBoxModule 'Microsoft.PowerShell.LocalAccounts'
  Import-InBoxModule 'ScheduledTasks'
  if ($null -ne (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue)) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
    [Console]::Out.WriteLine("task $TaskName unregistered")
  } else {
    [Console]::Out.WriteLine("task $TaskName is not registered")
  }
  $account = Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue
  if ($null -eq $account) {
    [Console]::Out.WriteLine("no local account ${VaultUser}: no user right to remove")
  } elseif (@(Invoke-AccountRights 'list' $account.SID.Value '') -contains $BatchLogonRight) {
    Invoke-AccountRights 'remove' $account.SID.Value $BatchLogonRight
    [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job) removed from $principalName")
  } else {
    [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job) is not held by $principalName")
  }
  exit 0
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
$settingsLine = 'ExecutionTimeLimit=PT0S RestartCount=2 RestartInterval=PT1M MultipleInstances=IgnoreNew StartWhenAvailable AllowStartIfOnBatteries DontStopIfGoingOnBatteries'

if ($DryRun) {
  [Console]::Out.WriteLine("task $TaskName")
  [Console]::Out.WriteLine("principal $principalName (logon type Password, run level Limited)")
  [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job), granted to the principal unless held")
  [Console]::Out.WriteLine("execute $Node")
  [Console]::Out.WriteLine("argument $argumentLine")
  [Console]::Out.WriteLine("working directory $base")
  [Console]::Out.WriteLine('trigger at startup')
  [Console]::Out.WriteLine("settings $settingsLine")
  [Console]::Out.WriteLine('dry run: nothing registered')
  exit 0
}

if (-not (Test-Elevated)) { Stop-WithError 'must run elevated (an Administrator PowerShell)' 1 }
Import-InBoxModule 'Microsoft.PowerShell.LocalAccounts'
Import-InBoxModule 'ScheduledTasks'
$account = Get-LocalUser -Name $VaultUser -ErrorAction SilentlyContinue
if ($null -eq $account) {
  Stop-WithError "no such local account: $VaultUser (install-two-identity.ps1 creates it)" 2
}
$held = @(Invoke-AccountRights 'list' $account.SID.Value '')
if ($held -contains $DenyBatchLogonRight) {
  Stop-WithError "$principalName is denied Log on as a batch job ($DenyBatchLogonRight): the task could not start; remove the denial" 1
}
if ($held -contains $BatchLogonRight) {
  [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job) already held by $principalName")
} else {
  Invoke-AccountRights 'add' $account.SID.Value $BatchLogonRight
  if (@(Invoke-AccountRights 'list' $account.SID.Value '') -notcontains $BatchLogonRight) {
    Stop-WithError "the grant of $BatchLogonRight to $principalName did not take: the task could not start" 1
  }
  [Console]::Out.WriteLine("right $BatchLogonRight (Log on as a batch job) granted to $principalName")
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
