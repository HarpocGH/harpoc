import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InjectionPolicy } from "@harpoc/shared";
import { ErrorCode } from "@harpoc/shared";
import { expectVaultError } from "@harpoc/test-utils";
import { resolveRenderClient } from "./sftp-render.js";
import { refuseUnsupportedSshClient } from "./ssh-common-version.js";

const BELOW_FLOOR = "OpenSSH_8.0p1, OpenSSL 1.1.1k";
const AT_FLOOR = "OpenSSH_8.4p1 Debian-5+deb11u7, OpenSSL 1.1.1w  11 Sep 2023";
const UNREAD =
  "Unsupported ssh client: its version could not be read; an sftp render needs OpenSSH 8.4 or later";

function policy(overrides: Partial<InjectionPolicy> = {}): InjectionPolicy {
  return {
    url_allowlist: [],
    command_allowlist: [],
    env_allowlist: [],
    host_allowlist: [],
    response_mode: "filtered",
    response_header_allowlist: [],
    network_isolation: false,
    fs_isolation: false,
    smtp_recipient_allowlist: [],
    imap_read_only: false,
    strict_tree_exit: false,
    proxy: false,
    ssh_agent_socket: false,
    local_dirs: [],
    ssh_bootstrap: null,
    render: { entries: [], approvals: [] },
    ...overrides,
  };
}

describe("resolveRenderClient", () => {
  it.each([
    ["an empty command_allowlist", [] as string[]],
    ["a command_allowlist without ssh", ["harpoc-t9-not-ssh"]],
  ])("ssh not on command_allowlist is COMMAND_NOT_ALLOWED: %s", async (_name, allowlist) => {
    await expectVaultError(
      () => resolveRenderClient(policy({ command_allowlist: allowlist })),
      ErrorCode.COMMAND_NOT_ALLOWED,
    );
  });
});

describe("refuseUnsupportedSshClient for a render", () => {
  it("a client that cannot be run is refused with the render's text", async () => {
    const err = await expectVaultError(
      () => refuseUnsupportedSshClient("ssh\u0000", [], "render"),
      ErrorCode.SSH_CLIENT_UNSUPPORTED,
    );
    expect(err.message).toBe(UNREAD);
  });
});

describe.skipIf(process.platform === "win32")(
  "on a stand-in ssh (POSIX only: a #!/bin/sh script cannot be spawned shell-free on win32)",
  () => {
    let dir: string;
    const savedPath = process.env.PATH;

    beforeEach(() => {
      dir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-render-ssh-")));
      process.env.PATH = [dir, savedPath ?? ""].join(delimiter);
    });

    afterEach(() => {
      process.env.PATH = savedPath;
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    function standIn(body: string): string {
      const ssh = join(dir, "ssh");
      writeFileSync(ssh, `#!/bin/sh\n${body}\n`);
      chmodSync(ssh, 0o755);
      return ssh;
    }

    async function resolved(body: string): Promise<string> {
      const ssh = standIn(body);
      const sshPath = await resolveRenderClient(policy({ command_allowlist: [ssh] }));
      expect(sshPath).toBe(ssh);
      return sshPath;
    }

    it("OpenSSH 8.0 is refused with the render's text, naming it", async () => {
      const sshPath = await resolved(`echo '${BELOW_FLOOR}' >&2`);
      const err = await expectVaultError(
        () => refuseUnsupportedSshClient(sshPath, [], "render"),
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );
      expect(err.message).toBe(
        "Unsupported ssh client: OpenSSH 8.0 is older than 8.4, which an sftp render needs",
      );
    });

    it("a version that reads as garbage is refused with the render's first text", async () => {
      const sshPath = await resolved("echo 'garbage' >&2");
      const err = await expectVaultError(
        () => refuseUnsupportedSshClient(sshPath, [], "render"),
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );
      expect(err.message).toBe(UNREAD);
    });

    it("OpenSSH 8.4 resolves to the stand-in's path and passes", async () => {
      const sshPath = await resolved(`echo '${AT_FLOOR}' >&2`);
      await expect(refuseUnsupportedSshClient(sshPath, [], "render")).resolves.toBeUndefined();
    });
  },
);

describe.runIf(process.platform === "win32")(
  "resolveRenderClient refuses an MSYS build (win32 only: the check is a no-op off Windows, where no such build runs)",
  () => {
    let fixtureDir: string;
    let stub: string;
    const savedPath = process.env.PATH;

    beforeEach(() => {
      fixtureDir = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-msys-ssh-")));
      stub = join(fixtureDir, "ssh.exe");
      writeFileSync(stub, "");
      writeFileSync(join(fixtureDir, "msys-2.0.dll"), "");
      process.env.PATH = fixtureDir;
    });

    afterEach(() => {
      process.env.PATH = savedPath;
      rmSync(fixtureDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });

    it("refuses it SSH_CLIENT_UNSUPPORTED with the existing MSYS text", async () => {
      const err = await expectVaultError(
        () => resolveRenderClient(policy({ command_allowlist: [stub] })),
        ErrorCode.SSH_CLIENT_UNSUPPORTED,
      );
      expect(err.message).toBe(
        `Unsupported ssh client: the binary resolved under ${fixtureDir} is an MSYS/Cygwin build (msys-2.0.dll or cygwin1.dll beside it), which cannot reach the vault's named-pipe ssh-agent; allowlist the native Win32-OpenSSH client (C:\\Windows\\System32\\OpenSSH\\ssh.exe) and put its directory ahead of Git's usr\\bin on PATH`,
      );
    });

    it("guard-flip: without the DLL the same stub resolves", async () => {
      rmSync(join(fixtureDir, "msys-2.0.dll"));
      const sshPath = await resolveRenderClient(policy({ command_allowlist: [stub] }));
      expect(sshPath.toLowerCase()).toBe(stub.toLowerCase());
    });
  },
);
