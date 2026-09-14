// The pre-gate warm-up on the Windows legs (ci.yml "Warm-up before the gate";
// docs/implementation-plan-concurrency-warmup-register-2026-09-14.md, D3): the
// call probe P isolated on 2026-09-14 — a PowerShell host that exits.
// The product's spawn shape; one stdout line, nothing asserted, exit 0
// whatever the figures.
import { spawn } from "node:child_process";
import { join } from "node:path";

const system32 = join(process.env.SystemRoot ?? "C:\\Windows", "System32");
const powershell = join(system32, "WindowsPowerShell", "v1.0", "powershell.exe");
const CALL_TIMEOUT_MS = 120_000;

function run(script) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ms: Date.now() - started, outcome });
    };
    const timer = setTimeout(() => {
      child.kill();
      finish("timed out");
    }, CALL_TIMEOUT_MS);
    child.stdout.resume();
    child.on("error", (err) => finish(err.message));
    child.on("close", (code) => finish(code === 0 ? "ok" : `exit ${String(code)}`));
  });
}

const CALLS = {
  bare: [{ label: "bare", script: "exit 0" }],
};

const arm = "bare";
const calls = CALLS[arm];
const parts = [];
for (const call of calls) {
  const result = await run(call.script);
  parts.push(`${call.label}=${String(result.ms)}ms (${result.outcome})`);
}
console.log(
  `[pregate] ${arm}: ${parts.join("; ")}; cpus=${process.env.NUMBER_OF_PROCESSORS ?? "?"}`,
);
