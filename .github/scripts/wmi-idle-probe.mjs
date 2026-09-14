// Probe P (docs/implementation-plan-close-pin-wmi-cause-2026-09-14.md, D2): the
// product's exact WMI listing spawn (descendant-sweep.ts win32SweepDeps), the
// product's DPAPI protect script (session-key-protector.ts), a Get-Process
// count and the Defender status, each timed on the runner before the test gate
// starts. One stdout line, nothing asserted, exit 0 whatever the figures.
// Diagnostics only; removed by the tranche commit either way.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

const system32 = join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const powershell = join(system32, "WindowsPowerShell", "v1.0", "powershell.exe");
const HELPER_TIMEOUT_MS = 120_000;
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
    }, HELPER_TIMEOUT_MS);
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

const cold = await run(listingScript(process.pid));
const warm = await run(listingScript(process.pid));
const dpapi = await run(dpapiScript(), randomBytes(32).toString("base64"));
const procs = await run("(Get-Process).Count");
const defender = await run(DEFENDER_SCRIPT);

console.log(
  `[probe idle] wmi cold=${String(cold.ms)}ms (${cold.outcome}, rows ${String(rowCount(cold.stdout))}); ` +
    `wmi warm=${String(warm.ms)}ms (${warm.outcome}, rows ${String(rowCount(warm.stdout))}); ` +
    `dpapi protect=${String(dpapi.ms)}ms (${dpapi.outcome}); ` +
    `get-process=${String(procs.ms)}ms (count ${procs.stdout.trim() || "?"}); ` +
    `cpus=${process.env.NUMBER_OF_PROCESSORS ?? "?"}; ` +
    `defender ${defender.stdout.trim() || defender.outcome}`,
);
