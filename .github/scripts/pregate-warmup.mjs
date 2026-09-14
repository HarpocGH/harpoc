// Probe P (docs/implementation-plan-concurrency-warmup-register-2026-09-14.md,
// D1): one pre-gate warm-up call on the Windows runner, chosen by argv — `bare`
// (a PowerShell host that exits), `dpapi` (the product's DPAPI protect script,
// session-key-protector.ts, on 32 random bytes), `wmi` (the product's exact
// listing spawn, descendant-sweep.ts win32SweepDeps, for this pid) or `all`
// (probe P's set of 2026-09-14: two listings, one protect, a Get-Process count,
// the Defender status). Every call is the product's spawn shape. One stdout
// line, nothing asserted, exit 0 whatever the figures. Diagnostics only;
// removed or reduced to the adopted call by the tranche commit.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

const system32 = join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const powershell = join(system32, "WindowsPowerShell", "v1.0", "powershell.exe");
const CALL_TIMEOUT_MS = 120_000;
const DPAPI_ASSEMBLY =
  "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

function listingScript(pid) {
  return (
    `Get-CimInstance Win32_Process -Filter "ParentProcessId=${String(pid)}" | ` +
    "ForEach-Object { '{0} {1}' -f $_.ProcessId, ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() }"
  );
}

function dpapiScript() {
  return (
    "$ErrorActionPreference='Stop';" +
    `[void][System.Reflection.Assembly]::Load('${DPAPI_ASSEMBLY}');` +
    "$d=[System.Convert]::FromBase64String([System.Console]::In.ReadToEnd().Trim());" +
    "$e=[System.Text.Encoding]::UTF8.GetBytes('harpoc.probe.v1');" +
    "$o=[System.Security.Cryptography.ProtectedData]::Protect($d,$e,[System.Security.Cryptography.DataProtectionScope]::CurrentUser);" +
    "[System.Console]::Out.Write([System.Convert]::ToBase64String($o))"
  );
}

const DEFENDER_SCRIPT =
  "$s = Get-MpComputerStatus; $p = Get-MpPreference; " +
  "$x = if ($p.ExclusionPath) { $p.ExclusionPath -join ';' } else { '-' }; " +
  "'rtp={0} behavior={1} tamper={2} scriptScanOff={3} exclusions={4}' -f " +
  "$s.RealTimeProtectionEnabled, $s.BehaviorMonitorEnabled, $s.IsTamperProtected, $p.DisableScriptScanning, $x";

function run(script, input) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], {
      shell: false,
      windowsHide: true,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "ignore"],
    });
    let stdout = "";
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ms: Date.now() - started, outcome, stdout });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish("timed out");
    }, CALL_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.on("error", (err) => finish(err.message));
    child.on("close", (code) => finish(code === 0 ? "ok" : `exit ${String(code)}`));
    if (input !== undefined) {
      child.stdin.on("error", () => undefined);
      child.stdin.end(input);
    }
  });
}

const rowCount = (stdout) =>
  stdout.split(/\r?\n/).filter((line) => /^\d+ \d+$/.test(line.trim())).length;

const listing = () => ({ label: "wmi", script: listingScript(process.pid) });
const protect = () => ({
  label: "dpapi",
  script: dpapiScript(),
  input: randomBytes(32).toString("base64"),
});
const CALLS = {
  bare: [{ label: "bare", script: "exit 0" }],
  dpapi: [protect()],
  wmi: [listing()],
  all: [
    listing(),
    listing(),
    protect(),
    { label: "get-process", script: "(Get-Process).Count" },
    { label: "defender", script: DEFENDER_SCRIPT },
  ],
};

function detail(label, result) {
  if (label === "wmi") return `${result.outcome}, rows ${String(rowCount(result.stdout))}`;
  if (label === "get-process" || label === "defender") {
    return `${result.outcome}, ${result.stdout.trim() || "-"}`;
  }
  return result.outcome;
}

const arm = process.argv[2];
const calls = CALLS[arm];
if (calls === undefined) {
  console.log(`[pregate] unknown arm ${String(arm)} - nothing run`);
} else {
  const parts = [];
  for (const call of calls) {
    const result = await run(call.script, call.input);
    parts.push(`${call.label}=${String(result.ms)}ms (${detail(call.label, result)})`);
  }
  console.log(
    `[pregate] ${arm}: ${parts.join("; ")}; cpus=${process.env.NUMBER_OF_PROCESSORS ?? "?"}`,
  );
}
