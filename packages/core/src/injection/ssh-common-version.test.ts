import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { resolveExecutable } from "./allowlist.js";
import { resolveNativeSshClient } from "./__fixtures__/native-ssh-client.js";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { baseSshEnv } from "./ssh-common.js";
import {
  formatSshVersion,
  parseSshVersion,
  readSshVersion,
  refuseUnsupportedSshClient,
  SSH_PASSWORD_LOGIN_MIN_VERSION,
  sshVersionAtLeast,
} from "./ssh-common-version.js";

// A Git-Bash PATH resolves Git's MSYS ssh first, which reads as absent: on win32 the
// native client is taken by its path, as ssh-live-auth.test.ts takes it.
const SSH =
  process.platform === "win32"
    ? (resolveExecutable(
        join(process.env.SystemRoot ?? "C:\\Windows", "System32", "OpenSSH", "ssh.exe"),
        [],
      ) ?? resolveNativeSshClient("ssh"))
    : resolveNativeSshClient("ssh");

const BELOW_FLOOR = "OpenSSH_8.0p1, OpenSSL 1.1.1k";
const AT_FLOOR = "OpenSSH_8.4p1 Debian-5+deb11u7, OpenSSL 1.1.1w  11 Sep 2023";
const ABOVE_FLOOR = "OpenSSH_9.6p1, OpenSSL 3.0.13 30 Jan 2024";

// A CI leg that provisions an ssh client exports HARPOC_REQUIRE_PLATFORM_TESTS
// including "ssh-live": the client going missing is then a failure, not a skip.
it("ssh-live tier: required legs fail instead of skipping when ssh is unresolvable", () => {
  if (SSH === null && tierRequired("ssh-live")) {
    throw new Error(
      'HARPOC_REQUIRE_PLATFORM_TESTS demands the "ssh-live" tier but no ssh client resolves',
    );
  }
});

describe("parseSshVersion", () => {
  it.each<[string, number, number]>([
    ["OpenSSH_8.4p1 Debian-5+deb11u7, OpenSSL 1.1.1w  11 Sep 2023", 8, 4],
    ["OpenSSH_9.2p1 Debian-2+deb12u10, OpenSSL 3.0.22 25 Aug 2026", 9, 2],
    ["OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026", 10, 0],
    ["OpenSSH_10.0p2, OpenSSL 3.5.3 16 Sep 2025", 10, 0],
    ["OpenSSH_10.3p1, OpenSSL 3.5.8 25 Aug 2026", 10, 3],
    ["OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2\r\n", 9, 5],
    ["OpenSSH_for_Windows_10.4p1 Win32-OpenSSH-GitHub, x", 10, 4],
  ])("reads %j as %d.%d", (line, major, minor) => {
    expect(parseSshVersion(line)).toEqual({ major, minor });
  });

  it.each(["", "OpenSSH", "OpenSSH_x.y", "Dropbear v2022.83", "x OpenSSH_9.6p1", "openssh_9.6p1"])(
    "reads %j as null",
    (line) => {
      expect(parseSshVersion(line)).toBeNull();
    },
  );
});

describe("sshVersionAtLeast", () => {
  it("is the floor 8.4", () => {
    expect(SSH_PASSWORD_LOGIN_MIN_VERSION).toEqual([8, 4]);
  });

  it.each<[number, number, boolean]>([
    [8, 3, false],
    [8, 4, true],
    [8, 10, true],
    [7, 9, false],
    [9, 0, true],
    [10, 0, true],
  ])("judges %d.%d against [8, 4] as %s", (major, minor, atLeast) => {
    expect(sshVersionAtLeast({ major, minor }, SSH_PASSWORD_LOGIN_MIN_VERSION)).toBe(atLeast);
  });
});

describe("formatSshVersion", () => {
  it("prints a version as <major>.<minor>", () => {
    expect(formatSshVersion({ major: 8, minor: 0 })).toBe("8.0");
    expect(formatSshVersion({ major: 10, minor: 3 })).toBe("10.3");
  });
});

describe("readSshVersion on the host's own client", () => {
  it.skipIf(SSH === null)(
    "reads the host's own client from standard error, not as null (skipped where no native ssh client resolves)",
    async () => {
      const read = await readSshVersion(SSH as string, baseSshEnv([]));
      expect(read).not.toBeNull();
      const direct = spawnSync(SSH as string, ["-V"], {
        encoding: "utf8",
        env: baseSshEnv([]),
        timeout: 20_000,
        windowsHide: true,
      });
      expect(read).toEqual(parseSshVersion(direct.stderr));
    },
  );
});

describe("a path that cannot be spawned", () => {
  it("readSshVersion resolves a path holding a NUL byte as null and does not reject", async () => {
    await expect(readSshVersion("ssh\u0000", baseSshEnv([]))).resolves.toBeNull();
  });

  it("refuseUnsupportedSshClient refuses it as a version that could not be read", async () => {
    const err = await expectVaultError(
      () => refuseUnsupportedSshClient("ssh\u0000", []),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(
      "Unsupported ssh client: its version could not be read; an ssh bootstrap needs OpenSSH 8.4 or later",
    );
  });
});

describe.skipIf(process.platform === "win32")(
  "on a stand-in ssh (POSIX only: a #!/bin/sh script cannot be spawned shell-free on win32)",
  () => {
    let dir: string;

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-ssh-version-")));
    });

    afterEach(() => {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function standIn(body: string): string {
      const ssh = join(dir, "ssh");
      writeFileSync(ssh, `#!/bin/sh\n${body}\n`);
      chmodSync(ssh, 0o755);
      return ssh;
    }

    describe("readSshVersion", () => {
      it("reads a stand-in that writes OpenSSH_8.0p1 to standard error as major 8, minor 0", async () => {
        expect(await readSshVersion(standIn(`echo '${BELOW_FLOOR}' >&2`), baseSshEnv([]))).toEqual({
          major: 8,
          minor: 0,
        });
      });

      it("reads a stand-in that writes the same line to standard output as null", async () => {
        expect(await readSshVersion(standIn(`echo '${BELOW_FLOOR}'`), baseSshEnv([]))).toBeNull();
      });

      it("reads a stand-in that writes garbage as null", async () => {
        expect(await readSshVersion(standIn("echo 'garbage' >&2"), baseSshEnv([]))).toBeNull();
      });

      it("reads a stand-in that writes OpenSSH_9.6p1 and exits 1 as null", async () => {
        expect(
          await readSshVersion(standIn(`echo '${ABOVE_FLOOR}' >&2\nexit 1`), baseSshEnv([])),
        ).toBeNull();
      });

      it("reads a stand-in that writes OpenSSH_9.6p1 and sleeps past a 1 s bound as null", async () => {
        expect(
          await readSshVersion(
            standIn(`echo '${ABOVE_FLOOR}' >&2\nexec sleep 15`),
            baseSshEnv([]),
            1_000,
          ),
        ).toBeNull();
      });
    });

    describe("refuseUnsupportedSshClient", () => {
      it("refuses OpenSSH 8.0, naming it", async () => {
        const err = await expectVaultError(
          () => refuseUnsupportedSshClient(standIn(`echo '${BELOW_FLOOR}' >&2`), []),
          ErrorCode.SSH_CLIENT_UNSUPPORTED,
        );
        expect(err.message).toBe(
          "Unsupported ssh client: OpenSSH 8.0 is older than 8.4, which an ssh bootstrap needs",
        );
      });

      it("refuses a client whose version reads as garbage", async () => {
        const err = await expectVaultError(
          () => refuseUnsupportedSshClient(standIn("echo 'garbage' >&2"), []),
          ErrorCode.SSH_CLIENT_UNSUPPORTED,
        );
        expect(err.message).toBe(
          "Unsupported ssh client: its version could not be read; an ssh bootstrap needs OpenSSH 8.4 or later",
        );
      });

      it("admits OpenSSH 8.4", async () => {
        await expect(
          refuseUnsupportedSshClient(standIn(`echo '${AT_FLOOR}' >&2`), []),
        ).resolves.toBeUndefined();
      });
    });
  },
);
