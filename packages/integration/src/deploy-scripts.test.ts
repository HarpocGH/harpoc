import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";
import { describe, expect, it } from "vitest";
import { getPkgRoot } from "@harpoc/test-utils";

const deployRoot = resolve(getPkgRoot(import.meta.url), "..", "..", "deploy");

/** Every shell script under deploy/, relative to it with `/` separators, sorted. */
const SCRIPTS = readdirSync(deployRoot, { recursive: true, encoding: "utf8" })
  .filter((p) => p.endsWith(".sh"))
  .map((p) => p.split(sep).join("/"))
  .sort();

const ENROLL = resolve(deployRoot, "linux", "enroll-unlock-key.sh");

describe("deploy scripts (deployment model B)", () => {
  it("finds exactly the scripts the deployment ships", () => {
    expect(SCRIPTS).toEqual([
      "dev-container/run.sh",
      "linux/enroll-unlock-key.sh",
      "linux/install-two-identity.sh",
    ]);
  });

  it.each(SCRIPTS)("%s starts with the bash shebang and set -eu", (script) => {
    const lines = readFileSync(resolve(deployRoot, script), "utf8").split("\n");
    expect(lines.slice(0, 2)).toEqual(["#!/usr/bin/env bash", "set -eu"]);
  });

  it("linux/enroll-unlock-key.sh never prints, copies or encodes the key file (no cat, od, base64, cp … on it; no xtrace)", () => {
    const lines = readFileSync(ENROLL, "utf8").split("\n");
    const touching = lines.filter((l) => !/^\s*#/.test(l) && l.includes('"$key_file"'));
    expect(touching.length).toBeGreaterThan(0);
    const sink =
      /\b(cat|xxd|od|hexdump|base64|base32|head|tail|dd|tee|cp|install|less|more|strings|sed|awk|grep|read|xargs|sha256sum|openssl)\b/;
    expect(touching.filter((l) => sink.test(l))).toEqual([]);
    expect(lines.some((l) => /\bset -[a-z]*x|xtrace/.test(l))).toBe(false);
  });

  it("linux/enroll-unlock-key.sh defaults to systemd-creds' own auto mode, never to the host key", () => {
    const text = readFileSync(ENROLL, "utf8");
    expect(text).toContain('mode="${2:-auto}"');
    expect(text).toContain('--with-key="$mode"');
  });
});

describe.skipIf(process.platform === "win32")(
  "deploy scripts on POSIX (the recipes target Linux; on win32 `bash` may resolve to Git Bash or the WSL launcher, and git there tracks no mode)",
  () => {
    it.each(SCRIPTS)("%s parses under bash -n", (script) => {
      const run = spawnSync("bash", ["-n", resolve(deployRoot, script)], {
        encoding: "utf8",
        timeout: 10_000,
      });
      expect(run.error).toBeUndefined();
      expect(run.stderr).toBe("");
      expect(run.status).toBe(0);
    });

    it.each(SCRIPTS)("%s is executable (the index mode git checks out)", (script) => {
      expect(statSync(resolve(deployRoot, script)).mode & 0o111).toBe(0o111);
    });

    it.each([
      { args: [], says: "expected <key-file> [mode]" },
      { args: ["-k"], says: "the key file must be a path" },
      { args: ["", "auto"], says: "the key file must be a path" },
      { args: ["/nonexistent/unlock.key", "null"], says: "unknown mode: null" },
      { args: ["/nonexistent/unlock.key", "auto", "extra"], says: "expected <key-file> [mode]" },
    ])(
      "linux/enroll-unlock-key.sh $args refuses with exit 2 before its root check",
      ({ args, says }) => {
        const run = spawnSync("bash", [ENROLL, ...args], { encoding: "utf8", timeout: 10_000 });
        expect(run.error).toBeUndefined();
        expect(run.status).toBe(2);
        expect(run.stderr).toContain(`enroll-unlock-key.sh: ${says}`);
        expect(run.stderr).not.toContain("must run as root");
      },
    );

    it("linux/enroll-unlock-key.sh --help prints the usage and exits 0", () => {
      const run = spawnSync("bash", [ENROLL, "--help"], { encoding: "utf8", timeout: 10_000 });
      expect(run.status).toBe(0);
      expect(run.stdout).toContain(
        "Usage: enroll-unlock-key.sh <key-file> [auto|tpm2|host+tpm2|host]",
      );
      expect(run.stderr).toBe("");
    });

    // As root the script passes its root check and would read the system; the runners run as a user.
    it.skipIf(process.getuid?.() === 0)(
      "linux/enroll-unlock-key.sh with valid arguments stops at its root check for a non-root user (exit 1, nothing read)",
      () => {
        const run = spawnSync("bash", [ENROLL, "/nonexistent/unlock.key", "host"], {
          encoding: "utf8",
          timeout: 10_000,
        });
        expect(run.status).toBe(1);
        expect(run.stderr).toBe("enroll-unlock-key.sh: must run as root\n");
      },
    );
  },
);
