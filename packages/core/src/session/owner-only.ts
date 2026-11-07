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

/** A file's Windows owner and access rules by SID — the names `icacls` prints are localized. */
export interface WindowsAcl {
  /** The account this process runs as. */
  user: string;
  owner: string;
  /** Every access rule, inherited ones included; `allow` is false for a deny rule. */
  rules: { allow: boolean; sid: string }[];
}

/**
 * Fully-qualified BCL calls only — no cmdlets, no Add-Type — as the DPAPI
 * script (`session-key-protector.ts`). The path arrives as base64 of its UTF-8
 * bytes: the console's input code page would mangle a non-ASCII path.
 */
const ACL_SCRIPT =
  "$ErrorActionPreference='Stop';" +
  "$p=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Console]::In.ReadToEnd().Trim()));" +
  "$s=[System.Security.Principal.SecurityIdentifier];" +
  "$a=[System.IO.File]::GetAccessControl($p);" +
  "[System.Console]::Out.WriteLine('user '+[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value);" +
  "[System.Console]::Out.WriteLine('owner '+$a.GetOwner($s).Value);" +
  "foreach($r in $a.GetAccessRules($true,$true,$s)){[System.Console]::Out.WriteLine('rule '+[int]$r.AccessControlType+' '+$r.IdentityReference.Value)}";

/**
 * List a file's owner and access rules through the pinned Windows PowerShell
 * host (`runKeystoreHelper`: `shell:false`, the path on stdin, 15 s timeout,
 * output caps). Rejects when the host fails or prints anything unexpected.
 */
export async function listWindowsAcl(path: string): Promise<WindowsAcl> {
  const result = await runKeystoreHelper(
    system32Path("WindowsPowerShell", "v1.0", "powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-Command", ACL_SCRIPT],
    Buffer.from(path, "utf8").toString("base64"),
    { label: "ACL listing" },
  );
  return parseWindowsAcl(result.stdout);
}

const SID_PATTERN = /^S-1-\d+(-\d+)*$/;

/** The listing script's output: `user <sid>`, `owner <sid>`, then `rule <0 allow | 1 deny> <sid>` per rule. */
export function parseWindowsAcl(text: string): WindowsAcl {
  let user: string | undefined;
  let owner: string | undefined;
  const rules: WindowsAcl["rules"] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const [tag, first, second, ...rest] = line.trim().split(" ");
    if (tag === "user" && first !== undefined && SID_PATTERN.test(first) && second === undefined) {
      user = first;
    } else if (
      tag === "owner" &&
      first !== undefined &&
      SID_PATTERN.test(first) &&
      second === undefined
    ) {
      owner = first;
    } else if (
      tag === "rule" &&
      (first === "0" || first === "1") &&
      second !== undefined &&
      SID_PATTERN.test(second) &&
      rest.length === 0
    ) {
      rules.push({ allow: first === "0", sid: second });
    } else {
      throw new Error("ACL listing: unexpected output");
    }
  }
  if (user === undefined || owner === undefined) throw new Error("ACL listing: incomplete output");
  return { user, owner, rules };
}
