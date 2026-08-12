import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Permission } from "@harpoc/shared";
import { assertOpaque } from "./assert/opacity.js";
import { emit } from "./evidence/record.js";
import { loadExpectations, expectationFor } from "./evidence/preregistration.js";
import {
  createHarnessVault,
  storeSecret,
  EVIDENCE_FILE,
  PREREGISTRATION_FILE,
} from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { preferNativeSsh, resolveGit } from "./harness/fixtures.js";
import { clientKeyPem, knownHostPin } from "./harness/ssh.js";
import { GIT_HTTP, SSHD_PINNED, assertFleetUp } from "./harness/backends.js";

const PASSWORD = "e2e-git-pw";
const GIT_HTTP_SECRET = `${GIT_HTTP.user}:${GIT_HTTP.password}`;
const BASE = `http://${GIT_HTTP.host}:${GIT_HTTP.port}`;

interface AuditRow {
  success: boolean;
  detail: Record<string, unknown> | null;
}

function detailString(row: AuditRow, key: string): string | undefined {
  const value = (row.detail ?? {})[key];
  return typeof value === "string" ? value : undefined;
}

/** The GitResult carried inside the MCP tool response's text content. */
function gitResult(result: unknown): { exit_code?: number; stderr?: string } {
  const content = (result as { content?: Array<{ text?: string }> }).content ?? [];
  try {
    return JSON.parse(content.map((c) => c.text ?? "").join("\n")) as {
      exit_code?: number;
      stderr?: string;
    };
  } catch {
    return {};
  }
}

/**
 * The `git` context over both transports it derives — HTTP and SSH — through the
 * real MCP Streamable-HTTP wire with a scoped token. The first completed `git`
 * executions in the repository, plus the two targeted arms the 2026-07-25 review
 * proved do not transfer from the deep-tested HTTP path: the H6a redirect refusal
 * and the H6b submodule-recursion denial.
 *
 * git-http runs over loopback http with basic auth (D2: no TLS on the git path —
 * criterion 3's handshake is the database arms' job). The ambient credential
 * helpers are neutralized (GIT_CONFIG_NOSYSTEM + an empty GIT_CONFIG_GLOBAL,
 * forwarded through env_allowlist) so the vault's askpass is the sole credential
 * source and the arm behaves identically on Linux CI and a Windows dev host,
 * where Git-for-Windows would otherwise inject credential.helper=manager.
 */
describe("git context — live clones over http and ssh", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let httpHandle: string;
  let sshHandle: string;
  let sshKey: string;
  let emptyGitConfig: string;
  const cloneDirs: string[] = [];
  const savedEnv: Record<string, string | undefined> = {};

  function freshCloneDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "harpoc-e2e-clone-"));
    cloneDirs.push(dir);
    return dir;
  }

  beforeAll(async () => {
    assertFleetUp("git-http");
    assertFleetUp("sshd-pinned");
    preferNativeSsh();
    const gitBin = resolveGit();

    // Make git ignore ambient system/global config so no credential.helper
    // intercepts the request ahead of the vault's askpass helper.
    emptyGitConfig = join(mkdtempSync(join(tmpdir(), "harpoc-e2e-gitcfg-")), "gitconfig");
    writeFileSync(emptyGitConfig, "");
    for (const key of ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"]) {
      savedEnv[key] = process.env[key];
    }
    process.env.GIT_CONFIG_NOSYSTEM = "1";
    process.env.GIT_CONFIG_GLOBAL = emptyGitConfig;

    sshKey = clientKeyPem();
    vault = await createHarnessVault(PASSWORD);

    httpHandle = await storeSecret(vault, "git-http-cred", GIT_HTTP_SECRET);
    await vault.engine.setInjectionPolicy(httpHandle, {
      url_allowlist: [`${BASE}/*`],
      command_allowlist: [gitBin],
      env_allowlist: ["GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"],
      host_allowlist: [],
    });

    sshHandle = await storeSecret(vault, "git-ssh-key", sshKey);
    await vault.engine.setInjectionPolicy(sshHandle, {
      url_allowlist: [],
      command_allowlist: [gitBin],
      env_allowlist: [],
      host_allowlist: [SSHD_PINNED.host],
    });
    await vault.engine.setConnectionConfig(sshHandle, {
      ssh: { known_hosts: [knownHostPin(SSHD_PINNED.host, "pinned")] },
    });

    surface = await startMcpHttpSurface(vault, "e2e-git-agent", [Permission.USE]);
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
    for (const dir of cloneDirs) rmSync(dir, { recursive: true, force: true });
    if (emptyGitConfig) rmSync(join(emptyGitConfig, ".."), { recursive: true, force: true });
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("clones over http with an injected credential that never leaks", async () => {
    const dest = freshCloneDir();
    const outcome = await surface.callUseSecret(httpHandle, {
      type: "git",
      operation: "clone",
      repository: `${BASE}/git/clean.git`,
      working_directory: dest,
    });

    expect(outcome.ok).toBe(true);
    expect(gitResult(outcome.result).exit_code).toBe(0);
    // The clone really completed — the working tree carries the repo's file.
    expect(existsSync(join(dest, "README.md"))).toBe(true);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, auditRows, parentEnv: process.env };
    assertOpaque(GIT_HTTP_SECRET, observation);
    assertOpaque(GIT_HTTP.password, observation);

    const expected = expectationFor(loadExpectations(PREREGISTRATION_FILE), {
      scenario: "git-http-happy-path",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
    });
    const record = emit(EVIDENCE_FILE, {
      scenario: "git-http-happy-path",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
      expected,
      observed: "SUCCEEDED",
    });
    expect(record.match).toBe(true);
  });

  it("writes a successful git audit row attributed to the mcp-http interface", () => {
    const rows = vault.engine.queryAudit({ eventType: "secret.use" }) as unknown as AuditRow[];
    const success = rows.find((r) => r.success === true && detailString(r, "context") === "git");
    expect(success).toBeDefined();
    expect(success && detailString(success, "interface")).toBe("mcp-http");
    expect(vault.engine.verifyAuditChain().valid).toBe(true);
  });

  it("clones over ssh with the pinned host key, leaking no key material", async () => {
    const dest = freshCloneDir();
    const outcome = await surface.callUseSecret(sshHandle, {
      type: "git",
      operation: "clone",
      repository: `ssh://${SSHD_PINNED.user}@${SSHD_PINNED.host}${SSHD_PINNED.repoPath}`,
      working_directory: dest,
    });

    expect(outcome.ok).toBe(true);
    expect(gitResult(outcome.result).exit_code).toBe(0);
    expect(existsSync(join(dest, "README.md"))).toBe(true);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(sshKey, { result: outcome.result, auditRows, parentEnv: process.env });

    const expected = expectationFor(loadExpectations(PREREGISTRATION_FILE), {
      scenario: "git-ssh-happy-path",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
    });
    const record = emit(EVIDENCE_FILE, {
      scenario: "git-ssh-happy-path",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
      expected,
      observed: "SUCCEEDED",
    });
    expect(record.match).toBe(true);
  });

  it("refuses to follow a redirect off-box, withholding the credential (H6a)", async () => {
    const dest = freshCloneDir();
    const outcome = await surface.callUseSecret(httpHandle, {
      type: "git",
      operation: "clone",
      repository: `${BASE}/redirect/clean.git`,
      working_directory: dest,
    });

    // The git process runs (no VaultError), but http.followRedirects=false stops
    // it before the redirect target is reached: a non-zero exit, no working tree.
    expect(outcome.ok).toBe(true);
    expect(gitResult(outcome.result).exit_code).not.toBe(0);
    expect(existsSync(join(dest, "README.md"))).toBe(false);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    const observation = { result: outcome.result, auditRows, parentEnv: process.env };
    assertOpaque(GIT_HTTP_SECRET, observation);
    assertOpaque(GIT_HTTP.password, observation);

    const expected = expectationFor(loadExpectations(PREREGISTRATION_FILE), {
      scenario: "git-http-redirect-refused",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
    });
    const record = emit(EVIDENCE_FILE, {
      scenario: "git-http-redirect-refused",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
      expected,
      observed: "BLOCKED",
    });
    expect(record.match).toBe(true);
  });

  it("denies submodule recursion before any spawn (H6b)", async () => {
    const dest = freshCloneDir();
    const outcome = await surface.callUseSecret(httpHandle, {
      type: "git",
      operation: "clone",
      repository: `${BASE}/git/submodule.git`,
      args: ["--recurse-submodules"],
      working_directory: dest,
    });

    // The denied argument is rejected as a VaultError before git is spawned, so
    // the hostile submodule URL is never contacted and nothing is cloned.
    expect(outcome.ok).toBe(false);
    expect(existsSync(join(dest, "README.md"))).toBe(false);

    const auditRows = vault.engine.queryAudit({ eventType: "secret.use" });
    assertOpaque(GIT_HTTP_SECRET, {
      result: outcome.result,
      error: outcome.errorText,
      auditRows,
    });
    assertOpaque(GIT_HTTP.password, {
      result: outcome.result,
      error: outcome.errorText,
      auditRows,
    });

    const expected = expectationFor(loadExpectations(PREREGISTRATION_FILE), {
      scenario: "git-http-submodule-denied",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
    });
    const record = emit(EVIDENCE_FILE, {
      scenario: "git-http-submodule-denied",
      context: "git",
      surface: "mcp-http",
      arm: "harpoc",
      expected,
      observed: "REJECTED",
    });
    expect(record.match).toBe(true);
  });
});
