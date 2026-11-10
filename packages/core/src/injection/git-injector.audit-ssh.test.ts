/**
 * Hard rule 7 (RX-B9-12), the SSH transport's own pre-spawn refusal: when no
 * ssh resolves on the controlled PATH, `runSsh` refuses with one failed
 * `secret.use` row in its neighbours' form (`{ context, operation, host,
 * error }`). The allowlist module is mocked so that `ssh` alone does not
 * resolve — git still does, through the real resolver — which is why this
 * row lives apart from `git-injector.audit.test.ts`, whose rows need the real
 * ssh.
 */
import { describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import type { AuditAttribution } from "../audit/attribution.js";
import type { AuditLogger, AuditLogOptions } from "../audit/audit-logger.js";
import { controlledPathDirs, resolveExecutable } from "./allowlist.js";
import { GitInjector } from "./git-injector.js";
import { spawnCaptured } from "./spawn-captured.js";
import { expectVaultError } from "@harpoc/test-utils";

vi.mock("./allowlist.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./allowlist.js")>();
  return {
    ...actual,
    resolveExecutable: (command: string, pathDirs: string[]) =>
      command === "ssh" ? null : actual.resolveExecutable(command, pathDirs),
  };
});

vi.mock("./spawn-captured.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./spawn-captured.js")>();
  return { ...actual, spawnCaptured: vi.fn() };
});

const GIT = resolveExecutable("git", controlledPathDirs());
// Skipped where git does not resolve: the command allowlist resolves it before ssh.
const describeGit = describe.skipIf(GIT === null);

const ATTRIBUTION: AuditAttribution = {
  principal_type: "agent",
  principal_id: "alice",
  session_id: "sess-attr-1",
  interface: "rest",
};

function expectOneFailedUse(log: Mock, code: string): AuditLogOptions {
  const all = log.mock.calls.map((c) => c[0] as AuditLogOptions);
  expect(all).toHaveLength(1);
  const [row] = all;
  expect(row?.eventType).toBe("secret.use");
  expect(row?.success).toBe(false);
  expect(row?.detail?.error).toBe(code);
  return row as AuditLogOptions;
}

function expectAttributed(row: AuditLogOptions): void {
  expect(row.principalType).toBe("agent");
  expect(row.principalId).toBe("alice");
  expect(row.sessionId).toBe("sess-attr-1");
  expect(row.detail?.interface).toBe("rest");
}

describeGit("RX-B9-12: no ssh on the controlled PATH writes one failed row", () => {
  it("push over SSH: { host, error }, nothing spawned", async () => {
    const log = vi.fn();
    const injector = new GitInjector({ log } as unknown as AuditLogger);
    const err = await expectVaultError(
      () =>
        injector.executeWithSecret(
          {
            type: "git",
            operation: "push",
            repository: "git@github.com:org/repo.git",
            working_directory: "./wd",
          },
          new Uint8Array(Buffer.from("not-a-key")),
          {
            url_allowlist: [],
            command_allowlist: [GIT as string],
            env_allowlist: [],
            host_allowlist: ["github.com"],
            response_mode: "filtered",
            response_header_allowlist: [],
            network_isolation: false,
            fs_isolation: false,
            smtp_recipient_allowlist: [],
            imap_read_only: false,
            strict_tree_exit: false,
            proxy: false,
            ssh_agent_socket: false,
          },
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
          "secret-1",
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expect(err.message).toBe("ssh binary not found on the controlled PATH");
    expect(log.mock.calls).toEqual([
      [
        {
          eventType: "secret.use",
          secretId: "secret-1",
          detail: {
            context: "git",
            operation: "push",
            host: "github.com",
            error: "INVALID_GIT_CONFIG",
          },
          success: false,
        },
      ],
    ]);
    expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
  });

  it("the row carries the caller's attribution", async () => {
    const log = vi.fn();
    const injector = new GitInjector({ log } as unknown as AuditLogger);
    await expectVaultError(
      () =>
        injector.executeWithSecret(
          {
            type: "git",
            operation: "push",
            repository: "git@github.com:org/repo.git",
            working_directory: "./wd",
          },
          new Uint8Array(Buffer.from("not-a-key")),
          {
            url_allowlist: [],
            command_allowlist: [GIT as string],
            env_allowlist: [],
            host_allowlist: ["github.com"],
            response_mode: "filtered",
            response_header_allowlist: [],
            network_isolation: false,
            fs_isolation: false,
            smtp_recipient_allowlist: [],
            imap_read_only: false,
            strict_tree_exit: false,
            proxy: false,
            ssh_agent_socket: false,
          },
          { ssh: { known_hosts: ["github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"] } },
          "secret-1",
          ATTRIBUTION,
        ),
      ErrorCode.INVALID_GIT_CONFIG,
    );
    expectAttributed(expectOneFailedUse(log, "INVALID_GIT_CONFIG"));
    expect(vi.mocked(spawnCaptured)).not.toHaveBeenCalled();
  });
});
