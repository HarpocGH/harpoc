import { spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import { system32Path } from "../win32-paths.js";
import { runKeystoreHelper } from "./keystore-helper.js";

/**
 * Reduce a file's Windows ACL to the current user — the counterpart of a POSIX
 * owner-only mode, shared by the session file and the unlock key file.
 *
 * `icacls` is invoked through the pinned System32 path with `shell:false` and
 * the path as an *argument* — the session manager's earlier `execSync` built a
 * cmd.exe string with the path interpolated into it, against the project's own
 * "never a shell; args are data" doctrine (L9). `%USERNAME%` was a cmd.exe
 * expansion and cannot survive the shell's removal, so the account name comes
 * from the process itself. Throws when the step fails: the session file
 * reports it and keeps the file, the unlock key file refuses before a byte of
 * the key is written.
 */
export function restrictWindowsAclToOwner(path: string): void {
  const account = userInfo().username;
  if (!account) throw new Error("could not determine the current account name");
  const res = spawnSync(
    system32Path("icacls.exe"),
    [path, "/inheritance:r", "/grant:r", `${account}:F`],
    { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    const detail = (res.stderr?.toString() || res.stdout?.toString() || "").trim().slice(0, 200);
    throw new Error(`icacls exited ${String(res.status)}${detail ? `: ${detail}` : ""}`);
  }
}

/** One access rule by SID; `allow` is false for a deny rule. */
export interface WindowsAclRule {
  allow: boolean;
  sid: string;
}

/** A file's Windows owner and access rules by SID — the names `icacls` prints are localized. */
export interface WindowsAcl {
  /** The account this process runs as. */
  user: string;
  owner: string;
  /** Every access rule, inherited ones included. */
  rules: WindowsAclRule[];
}

/** A rule as the listing prints it: the access mask and where the rule came from. */
export interface WindowsAclEntry extends WindowsAclRule {
  /** The access mask, unsigned (`FileSystemRights` / `PipeAccessRights`; generic bits kept). */
  rights: number;
  /** Inherited from the parent (`icacls`' `(I)`). */
  inherited: boolean;
  /** `InheritanceFlags`: 1 container inherit `(CI)`, 2 object inherit `(OI)`. */
  inheritance: number;
  /** `PropagationFlags`: 1 no-propagate `(NP)`, 2 inherit-only `(IO)`. */
  propagation: number;
}

/** What the listing reads: a `WindowsAcl` whose rules carry their masks, and the asked account's SID. */
export interface WindowsAclListing extends WindowsAcl {
  rules: WindowsAclEntry[];
  /** The local account `account` names, by SID; null when no local account has that name; absent when none was asked. */
  account?: string | null;
}

/** `FileSystemRights.ReadAndExecute | Synchronize` — `icacls`' `(RX)`, measured 0x001200A9. */
export const WINDOWS_READ_EXECUTE_RIGHTS = 0x001200a9;

/** What the agent pipe grants its consumer: `FILE_GENERIC_READ | FILE_GENERIC_WRITE` without `CreateNewInstance` (0x4) — the `GENERIC_READ | GENERIC_WRITE` Win32-OpenSSH opens the pipe for, measured 0x0012019B. */
export const WINDOWS_PIPE_CONSUMER_RIGHTS = 0x0012019b;

const SID_PATTERN = /^S-1-\d+(-\d+)*$/;
const HEX_MASK = /^[0-9A-F]{8}$/;
const SYSTEM_SID = "S-1-5-18";
const ADMINISTRATORS_SID = "S-1-5-32-544";
const PIPE_FULL_CONTROL_RIGHTS = 0x001f019f;
const MAX_LISTING_BYTES = 64 * 1024;
const LISTING_TIMEOUT_MS = 15_000;

/** One `rule` line: type, SID, the mask as eight hex digits, inherited, inheritance and propagation flags. */
const RULE_LINE =
  "'rule '+[int]$r.AccessControlType+' '+$r.IdentityReference.Value+' '+('{0:X8}' -f [int]$r.%RIGHTS%)+' '+[int]$r.IsInherited+' '+[int]$r.InheritanceFlags+' '+[int]$r.PropagationFlags";

/**
 * Fully-qualified BCL calls only — no cmdlets, no Add-Type — as the DPAPI
 * script (`session-key-protector.ts`). stdin carries one or two lines of
 * base64 over UTF-8 — the path, then an account name to resolve on this
 * machine — since the console's input code page would mangle a non-ASCII
 * path. The account is looked up machine-qualified, so a well-known name
 * (`users`, `everyone`) resolves to no account.
 */
const ACL_SCRIPT =
  "$ErrorActionPreference='Stop';" +
  "$i=[System.Console]::In.ReadToEnd().Split([char]10);" +
  "$p=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($i[0].Trim()));" +
  "$s=[System.Security.Principal.SecurityIdentifier];" +
  "if([System.IO.Directory]::Exists($p)){$a=[System.IO.Directory]::GetAccessControl($p)}else{$a=[System.IO.File]::GetAccessControl($p)};" +
  "[System.Console]::Out.WriteLine('user '+[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value);" +
  "[System.Console]::Out.WriteLine('owner '+$a.GetOwner($s).Value);" +
  "if($i.Length -gt 1 -and $i[1].Trim() -ne ''){" +
  "$n=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($i[1].Trim()));" +
  "try{$v=[System.Security.Principal.NTAccount]::new([System.Environment]::MachineName,$n).Translate($s).Value}catch{$v='-'};" +
  "[System.Console]::Out.WriteLine('account '+$v)};" +
  "foreach($r in $a.GetAccessRules($true,$true,$s)){[System.Console]::Out.WriteLine(" +
  RULE_LINE.replace("%RIGHTS%", "FileSystemRights") +
  ")}";

/**
 * Replace a named pipe's DACL through a client handle opened with
 * `ChangePermissions` (Node creates the pipe with the default DACL and has no
 * call to change it; `icacls` refuses a pipe path, exit 87): protected, this
 * account, SYSTEM and Administrators full control, the consumer's account
 * `WINDOWS_PIPE_CONSUMER_RIGHTS`, nothing else — then print the pipe's DACL as
 * the file listing does. stdin: the pipe's name after `\\.\pipe\` as base64,
 * then the consumer's SID.
 */
const PIPE_DACL_SCRIPT =
  "$ErrorActionPreference='Stop';" +
  "$i=[System.Console]::In.ReadToEnd().Split([char]10);" +
  "$n=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($i[0].Trim()));" +
  "$s=[System.Security.Principal.SecurityIdentifier];" +
  "$c=[System.Security.Principal.SecurityIdentifier]::new($i[1].Trim());" +
  "$q=[System.IO.Pipes.NamedPipeClientStream]::new('.',$n,[System.IO.Pipes.PipeAccessRights]'ReadData, WriteData, ReadPermissions, ChangePermissions',[System.IO.Pipes.PipeOptions]::None,[System.Security.Principal.TokenImpersonationLevel]::Identification,[System.IO.HandleInheritability]::None);" +
  "$q.Connect(5000);" +
  "try{$a=$q.GetAccessControl();$a.SetAccessRuleProtection($true,$false);" +
  "foreach($r in @($a.GetAccessRules($true,$true,$s))){[void]$a.RemoveAccessRuleSpecific($r)};" +
  "$u=[System.Security.Principal.WindowsIdentity]::GetCurrent().User;" +
  "foreach($o in @($u,[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){$a.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($o,[System.IO.Pipes.PipeAccessRights]::FullControl,'Allow'))};" +
  "$a.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new($c,[System.IO.Pipes.PipeAccessRights]'ReadData, WriteData, ReadExtendedAttributes, WriteExtendedAttributes, ReadAttributes, WriteAttributes, ReadPermissions, Synchronize','Allow'));" +
  "$q.SetAccessControl($a);$a=$q.GetAccessControl();" +
  "[System.Console]::Out.WriteLine('user '+$u.Value);" +
  "[System.Console]::Out.WriteLine('owner '+$a.GetOwner($s).Value);" +
  "foreach($r in $a.GetAccessRules($true,$true,$s)){[System.Console]::Out.WriteLine(" +
  RULE_LINE.replace("%RIGHTS%", "PipeAccessRights") +
  ")}}finally{$q.Dispose()}";

function powershellArgs(script: string): string[] {
  return ["-NoProfile", "-NonInteractive", "-Command", script];
}

function powershellPath(): string {
  return system32Path("WindowsPowerShell", "v1.0", "powershell.exe");
}

function listingInput(path: string, account: string | undefined): string {
  const lines = [Buffer.from(path, "utf8").toString("base64")];
  if (account !== undefined) lines.push(Buffer.from(account, "utf8").toString("base64"));
  return `${lines.join("\n")}\n`;
}

/**
 * List a file's or directory's owner and access rules through the pinned
 * Windows PowerShell host (`runKeystoreHelper`: `shell:false`, the path on
 * stdin, 15 s timeout, output caps). Rejects when the host fails or prints
 * anything unexpected. Typed `WindowsAcl` for its callers and their doubles;
 * the rules it returns carry `WindowsAclEntry`'s fields too.
 */
export async function listWindowsAcl(path: string): Promise<WindowsAcl> {
  const result = await runKeystoreHelper(
    powershellPath(),
    powershellArgs(ACL_SCRIPT),
    listingInput(path, undefined),
    { label: "ACL listing" },
  );
  return parseWindowsAcl(result.stdout);
}

/**
 * `listWindowsAcl` for a synchronous caller (the CLI's directory checks run
 * before the vault opens, in sync code): the same script through `spawnSync`
 * of the same host — `shell:false`, the path (and `account`, a name to
 * resolve to a local account's SID) on stdin, 15 s timeout, 64 KiB of output.
 * Throws a value-free error when the host fails or prints anything unexpected.
 */
export function listWindowsAclSync(
  path: string,
  options: { account?: string } = {},
): WindowsAclListing {
  const res = spawnSync(powershellPath(), powershellArgs(ACL_SCRIPT), {
    input: listingInput(path, options.account),
    encoding: "utf8",
    shell: false,
    windowsHide: true,
    timeout: LISTING_TIMEOUT_MS,
    maxBuffer: MAX_LISTING_BYTES,
  });
  if (res.error) throw new Error("ACL listing failed to run");
  if (res.status !== 0) throw new Error(`ACL listing failed (exit ${String(res.status)})`);
  const listing = parseWindowsAcl(res.stdout);
  if (options.account !== undefined && listing.account === undefined) {
    throw new Error("ACL listing: incomplete output");
  }
  return listing;
}

/**
 * Set a named pipe's DACL to this account, SYSTEM and Administrators (full)
 * and `consumerSid` (`WINDOWS_PIPE_CONSUMER_RIGHTS`), then check what the pipe
 * holds. Rejects — value-free — when the host fails, the pipe cannot be
 * opened, or the DACL read back is not exactly that.
 */
export async function restrictWindowsPipeToAccount(
  pipePath: string,
  consumerSid: string,
): Promise<WindowsAclListing> {
  const prefix = "\\\\.\\pipe\\";
  if (!pipePath.startsWith(prefix) || !SID_PATTERN.test(consumerSid)) {
    throw new Error("pipe access list: not a pipe path or not a SID");
  }
  const result = await runKeystoreHelper(
    powershellPath(),
    powershellArgs(PIPE_DACL_SCRIPT),
    `${Buffer.from(pipePath.slice(prefix.length), "utf8").toString("base64")}\n${consumerSid}\n`,
    { label: "pipe access list" },
  );
  const listing = parseWindowsAcl(result.stdout);
  const expected = new Map(
    [listing.user, SYSTEM_SID, ADMINISTRATORS_SID].map((sid) => [sid, PIPE_FULL_CONTROL_RIGHTS]),
  );
  if (!expected.has(consumerSid)) expected.set(consumerSid, WINDOWS_PIPE_CONSUMER_RIGHTS);
  const exact =
    listing.rules.length === expected.size &&
    new Set(listing.rules.map((rule) => rule.sid)).size === expected.size &&
    listing.rules.every(
      (rule) => rule.allow && !rule.inherited && expected.get(rule.sid) === rule.rights,
    );
  if (!exact) throw new Error("pipe access list: not as set");
  return listing;
}

/**
 * The listing scripts' output: `user <sid>`, `owner <sid>`, `account <sid | ->`
 * when an account was asked, then per rule `rule <0 allow | 1 deny> <sid>
 * <mask, 8 hex digits> <inherited 0 | 1> <inheritance flags> <propagation flags>`.
 */
export function parseWindowsAcl(text: string): WindowsAclListing {
  let user: string | undefined;
  let owner: string | undefined;
  let account: string | null | undefined;
  const rules: WindowsAclEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const [tag, ...fields] = line.trim().split(" ");
    const [first, second, mask, inherited, inheritance, propagation] = fields;
    if (tag === "user" && fields.length === 1 && SID_PATTERN.test(first ?? "")) {
      user = first;
    } else if (tag === "owner" && fields.length === 1 && SID_PATTERN.test(first ?? "")) {
      owner = first;
    } else if (
      tag === "account" &&
      fields.length === 1 &&
      account === undefined &&
      (first === "-" || SID_PATTERN.test(first ?? ""))
    ) {
      account = first === "-" ? null : (first as string);
    } else if (
      tag === "rule" &&
      fields.length === 6 &&
      (first === "0" || first === "1") &&
      SID_PATTERN.test(second ?? "") &&
      HEX_MASK.test(mask ?? "") &&
      (inherited === "0" || inherited === "1") &&
      /^[0-3]$/.test(inheritance ?? "") &&
      /^[0-3]$/.test(propagation ?? "")
    ) {
      rules.push({
        allow: first === "0",
        sid: second as string,
        rights: Number.parseInt(mask as string, 16),
        inherited: inherited === "1",
        inheritance: Number(inheritance),
        propagation: Number(propagation),
      });
    } else {
      throw new Error("ACL listing: unexpected output");
    }
  }
  if (user === undefined || owner === undefined) throw new Error("ACL listing: incomplete output");
  return account === undefined ? { user, owner, rules } : { user, owner, account, rules };
}
