import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";
import { assertTierAvailable } from "./helpers/platform-tiers.js";

/**
 * The systemd unit of deployment model B (tranche B4): `deploy/systemd/harpoc.service`
 * runs the daemon as `harpoc` and unlocks it at boot from the unlock key sealed by
 * `deploy/linux/enroll-unlock-key.sh` — no human, no password. Its text is pinned here;
 * `systemd-analyze verify` judges it where systemd is installed (the ubuntu legs and the
 * dev container), on a copy whose `ExecStart=` names an executable that exists, since
 * the operator's install path (`/usr/local/bin/harpoc`) does not exist on a test host.
 */

const deployRoot = resolve(getPkgRoot(import.meta.url), "..", "..", "deploy");
const UNIT = resolve(deployRoot, "systemd", "harpoc.service");
const INSTALL_PATH = "/usr/local/bin/harpoc";

function unitText(): string {
  return readFileSync(UNIT, "utf8");
}

/** Every `Key=value` line of the unit, comments and section headers dropped, in order. */
function directives(text: string): [string, string][] {
  return text
    .split("\n")
    .filter((l) => /^[A-Za-z]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]);
}

function values(text: string, key: string): string[] {
  return directives(text)
    .filter(([k]) => k === key)
    .map(([, v]) => v);
}

describe("the systemd unit (deployment model B)", () => {
  it("deploy/systemd holds exactly harpoc.service", () => {
    expect(readdirSync(resolve(deployRoot, "systemd")).sort()).toEqual(["harpoc.service"]);
  });

  it("harpoc.service is LF-only and carries [Unit], [Service] and [Install] in that order", () => {
    const text = unitText();
    expect(text.includes("\r")).toBe(false);
    expect(text.endsWith("\n")).toBe(true);
    expect(text.split("\n").filter((l) => /^\[.+\]$/.test(l))).toEqual([
      "[Unit]",
      "[Service]",
      "[Install]",
    ]);
  });

  it("the daemon runs as harpoc and unlocks from the sealed credential: one LoadCredentialEncrypted=, and --unlock-credential names its ID", () => {
    const text = unitText();
    expect(values(text, "User")).toEqual(["harpoc"]);
    expect(values(text, "Group")).toEqual(["harpoc"]);
    expect(values(text, "LoadCredentialEncrypted")).toEqual([
      "harpoc-unlock:/etc/credstore.encrypted/harpoc-unlock.cred",
    ]);
    const [execStart, ...more] = values(text, "ExecStart");
    expect(more).toEqual([]);
    expect(execStart?.split(" ")).toEqual([
      INSTALL_PATH,
      "--vault-dir",
      "/var/lib/harpoc",
      "server",
      "start",
      "--rest",
      "--unlock-credential",
      "harpoc-unlock",
      "--runtime-dir",
      "/run/harpoc",
    ]);
    expect(values(text, "WantedBy")).toEqual(["multi-user.target"]);
  });

  it("the daemon writes its file session with the keystore off, as the administrator's sudo commands do, so both read one session (file session mode, until the memory session)", () => {
    expect(values(unitText(), "Environment")).toEqual(["HARPOC_SESSION_KEYSTORE=off"]);
  });

  it("/run/harpoc stays tmpfiles.d's (no RuntimeDirectory=), V8's JIT keeps its executable memory (no MemoryDenyWriteExecute=) and the user is static (no DynamicUser=)", () => {
    const keys = directives(unitText()).map(([k]) => k);
    expect(keys.filter((k) => k.startsWith("RuntimeDirectory"))).toEqual([]);
    expect(keys).not.toContain("MemoryDenyWriteExecute");
    expect(keys).not.toContain("DynamicUser");
    expect(values(unitText(), "StateDirectoryMode")).toEqual(["0700"]);
  });

  it("a key the vault refuses stops the restarts after three starts, before the fifth failure would lock the password out", () => {
    const text = unitText();
    expect(values(text, "Restart")).toEqual(["on-failure"]);
    expect(values(text, "StartLimitBurst")).toEqual(["3"]);
    expect(Number(values(text, "StartLimitIntervalSec")[0])).toBeGreaterThanOrEqual(
      3 * Number(values(text, "RestartSec")[0]) + 30,
    );
  });

  it("the unit loads the credential deploy/linux/enroll-unlock-key.sh writes, under the name it embeds", () => {
    const script = readFileSync(resolve(deployRoot, "linux", "enroll-unlock-key.sh"), "utf8");
    const assigned = (name: string): string | undefined =>
      new RegExp(`^${name}="([^"$]*)"$`, "m").exec(script)?.[1];
    const credName = assigned("CRED_NAME");
    const credDir = assigned("CRED_DIR");
    expect(credName).toBe("harpoc-unlock");
    expect(script).toContain('CRED_PATH="$CRED_DIR/$CRED_NAME.cred"');
    expect(values(unitText(), "LoadCredentialEncrypted")).toEqual([
      `${String(credName)}:${String(credDir)}/${String(credName)}.cred`,
    ]);
  });
});

// systemd exists on Linux only; the `systemd-creds` tier makes a required leg (the ubuntu
// legs) fail rather than skip when systemd-analyze is missing.
describe.skipIf(process.platform !== "linux")("the systemd unit under systemd-analyze", () => {
  it("systemd-analyze verify --recursive-errors=no reports nothing about harpoc.service (ExecStart= pointed at an executable that exists)", (ctx) => {
    const probe = spawnSync("systemd-analyze", ["--version"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    const available = probe.status === 0;
    assertTierAvailable(
      "systemd-creds",
      available,
      probe.error ?? `systemd-analyze --version exited ${String(probe.status)}`,
    );
    if (!available) return ctx.skip();

    const text = unitText();
    expect(text.split(`ExecStart=${INSTALL_PATH} `)).toHaveLength(2);
    const dir = mkdtempSync(join(tmpdir(), "harpoc-unit-"));
    try {
      const copy = join(dir, "harpoc.service");
      writeFileSync(
        copy,
        text.replace(`ExecStart=${INSTALL_PATH} `, `ExecStart=${process.execPath} `),
      );
      const run = spawnSync(
        "systemd-analyze",
        ["verify", "--recursive-errors=no", "--man=no", copy],
        { encoding: "utf8", timeout: 60_000 },
      );
      expect(run.error).toBeUndefined();
      expect(
        run.stderr.split("\n").filter((l) => l.includes("harpoc.service")),
        run.stderr,
      ).toEqual([]);
      expect(run.status, run.stderr).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});
