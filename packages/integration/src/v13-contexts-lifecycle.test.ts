import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode } from "@harpoc/shared";
import type { UseSecretAction } from "@harpoc/shared";
import { createTestVault, destroyTestVault } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";
import { startFakeSmtp, FIXTURE_CA_PEM } from "./helpers/fake-smtp-server.js";
import { startFakeImap } from "./helpers/fake-imap-server.js";
import { startFakeWsServer } from "./helpers/fake-ws-server.js";
import { LOOPBACK_HOST } from "./helpers/loopback-cert.js";

/**
 * v1.3 Extended Injection Contexts — the cross-package lifecycle proof (Task
 * 17). Each of the five new contexts runs through the REAL `VaultEngine`
 * (real KEK-encrypted policy + connection-config round-trip, real Argon2id
 * vault, no injector stubbing) and the per-context `secret.use` audit-detail
 * shape Tasks 12–14 wrote is asserted from the decrypted audit row.
 *
 * smtp, imap and websocket are exercised end to end against in-process fakes
 * on loopback (the SSRF floor permits loopback; the mail fakes present the
 * loopback certificate so TLS identity verifies). sftp and docker have no
 * in-process backend on this host — a full success would need a live SFTP
 * server and a live Docker daemon + registry — so they are pinned at the
 * engine→injector→audit boundary through their refusal paths, which write the
 * same per-context audit-detail shape on a FAILED `secret.use` row and need no
 * backend. The two thesis-mandated end-to-end refusals (SMTP recipient
 * coupling, docker × isolation) run through the real engine here too.
 */

const PASSWORD = "v13-lifecycle-pw";

let vault: TestVault;
const cleanups: Array<() => Promise<void>> = [];

beforeAll(async () => {
  vault = createTestVault();
  await vault.engine.initVault(PASSWORD);
});

afterAll(async () => {
  await destroyTestVault(vault).catch(() => undefined);
});

afterEach(async () => {
  while (cleanups.length > 0) {
    const close = cleanups.pop();
    if (close) await close().catch(() => undefined);
  }
});

interface UseRow {
  detail: Record<string, unknown> | null;
  success: boolean;
}

/**
 * The single `secret.use` row a fresh secret's one `useSecret` produced —
 * read back from the real (decrypted) audit trail, filtered to that secret.
 */
async function useRow(handle: string): Promise<UseRow> {
  const secretId = await vault.engine.resolveSecretId(handle);
  const rows = vault.engine.queryAudit({ secretId, eventType: AuditEventType.SECRET_USE });
  expect(rows.length).toBe(1);
  const row = rows[0] as UseRow;
  return row;
}

async function makeSecret(name: string, value: string): Promise<string> {
  const created = await vault.engine.createSecret({
    name,
    type: "api_key",
    value: new Uint8Array(Buffer.from(value, "utf8")),
  });
  return created.handle;
}

describe("v1.3 contexts — lifecycle through the real engine", () => {
  it("smtp: sends over implicit TLS and writes the §7.2 audit detail", async () => {
    const fake = await startFakeSmtp({
      starttls: false,
      implicitTls: true,
      authMechanisms: ["PLAIN"],
      auth: "ok",
      rcpt: "ok",
    });
    cleanups.push(fake.close);

    const handle = await makeSecret("v13-smtp-ok", "smtp-user:smtp-pass-lifecycle");
    await vault.engine.setInjectionPolicy(handle, {
      host_allowlist: [`${LOOPBACK_HOST}:${fake.port}`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });

    const action: UseSecretAction = {
      type: "smtp",
      host: LOOPBACK_HOST,
      port: fake.port,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: "lifecycle",
      text: "hello",
    };
    const res = await vault.engine.useSecret(handle, action);
    if (res.type !== "smtp") throw new Error("expected smtp result");
    expect(res.accepted).toBe(1);
    expect(typeof res.message_id).toBe("string");

    const row = await useRow(handle);
    expect(row.success).toBe(true);
    expect(row.detail).toEqual({
      context: "smtp",
      host: LOOPBACK_HOST,
      from: "agent@harpoc.local",
      recipients: ["ops@example.com"],
      attachment_paths: [],
      attachment_total_bytes: 0,
    });
  });

  it("smtp: an attachment send records attachment_paths and total bytes", async () => {
    const fake = await startFakeSmtp({
      starttls: false,
      implicitTls: true,
      authMechanisms: ["PLAIN"],
      auth: "ok",
      rcpt: "ok",
    });
    cleanups.push(fake.close);

    const dir = mkdtempSync(join(tmpdir(), "v13-smtp-att-"));
    cleanups.push(() => Promise.resolve(rmSync(dir, { recursive: true, force: true })));
    const attachmentPath = join(dir, "report.txt");
    const attachmentBytes = Buffer.from("quarterly report body", "utf8");
    writeFileSync(attachmentPath, attachmentBytes);

    const handle = await makeSecret("v13-smtp-attach", "smtp-user:smtp-pass-attach");
    await vault.engine.setInjectionPolicy(handle, {
      smtp_recipient_allowlist: ["*@example.com"],
      host_allowlist: [`${LOOPBACK_HOST}:${fake.port}`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });

    const action: UseSecretAction = {
      type: "smtp",
      host: LOOPBACK_HOST,
      port: fake.port,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: "with attachment",
      text: "see attached",
      attachments: [{ path: attachmentPath }],
    };
    const res = await vault.engine.useSecret(handle, action);
    if (res.type !== "smtp") throw new Error("expected smtp result");
    expect(res.accepted).toBe(1);

    const row = await useRow(handle);
    expect(row.success).toBe(true);
    expect(row.detail).toEqual({
      context: "smtp",
      host: LOOPBACK_HOST,
      from: "agent@harpoc.local",
      recipients: ["ops@example.com"],
      attachment_paths: [attachmentPath],
      attachment_total_bytes: attachmentBytes.length,
    });
  });

  it("imap: searches over implicit TLS and writes the §7.2 audit detail", async () => {
    const fake = await startFakeImap({ auth: "ok", searchResults: [101, 102] });
    cleanups.push(fake.close);

    const handle = await makeSecret("v13-imap-ok", "imap-user:imap-pass-lifecycle");
    await vault.engine.setInjectionPolicy(handle, {
      host_allowlist: [`${LOOPBACK_HOST}:${fake.port}`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });

    const action: UseSecretAction = {
      type: "imap",
      host: LOOPBACK_HOST,
      port: fake.port,
      mailbox: "INBOX",
      operation: { kind: "search", subject: "report" },
    };
    const res = await vault.engine.useSecret(handle, action);
    if (res.type !== "imap") throw new Error("expected imap result");
    expect(res.operation).toBe("search");
    expect(res.uids).toEqual([101, 102]);

    const row = await useRow(handle);
    expect(row.success).toBe(true);
    expect(row.detail).toEqual({
      context: "imap",
      host: LOOPBACK_HOST,
      mailbox: "INBOX",
      operation: "search",
      uid_count: 2,
    });
  });

  it("imap: refuses a mutation under imap_read_only, writing a failed §7.2 row", async () => {
    const handle = await makeSecret("v13-imap-ro", "imap-user:imap-pass-ro");
    await vault.engine.setInjectionPolicy(handle, { imap_read_only: true });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });

    const action: UseSecretAction = {
      type: "imap",
      host: LOOPBACK_HOST,
      port: 993,
      mailbox: "INBOX",
      operation: { kind: "expunge" },
    };
    await expect(vault.engine.useSecret(handle, action)).rejects.toMatchObject({
      code: ErrorCode.IMAP_MUTATION_NOT_ALLOWED,
    });

    const row = await useRow(handle);
    expect(row.success).toBe(false);
    expect(row.detail).toEqual({
      context: "imap",
      host: LOOPBACK_HOST,
      mailbox: "INBOX",
      operation: "expunge",
      uid_count: 0,
      error: ErrorCode.IMAP_MUTATION_NOT_ALLOWED,
    });
  });

  it("websocket: exchanges a message and writes the §7.2 audit detail", async () => {
    const fake = await startFakeWsServer({ messages: ["pong"] });
    cleanups.push(fake.close);

    const handle = await makeSecret("v13-ws-ok", "ws-token-do-not-log");
    await vault.engine.setInjectionPolicy(handle, {
      url_allowlist: [`ws://127.0.0.1:${fake.port}/*`],
    });

    const url = `ws://127.0.0.1:${fake.port}/feed`;
    const action: UseSecretAction = {
      type: "websocket",
      url,
      injection: { type: "bearer" },
      message: "ping",
      collect: { max_messages: 1, window_ms: 2000 },
    };
    const res = await vault.engine.useSecret(handle, action);
    if (res.type !== "websocket") throw new Error("expected websocket result");
    expect(res.messages).toEqual(["pong"]);
    expect(res.close_code).toBe(1000);

    // The credential rode the handshake — proof the injection actually happened
    // (this is the injection channel, not an observable leak channel).
    const auth = fake.requests()[0]?.headers.authorization;
    expect(auth).toBe("Bearer ws-token-do-not-log");

    const row = await useRow(handle);
    expect(row.success).toBe(true);
    expect(row.detail).toEqual({ context: "websocket", url, sent: 1, received: 1 });
  });

  it("sftp: reaches the injector and writes the §7.2 shape on a fail-safe deny", async () => {
    // No in-process SFTP backend on this host: pin the engine→injector→audit
    // wiring through the injector's fail-safe host deny (empty host_allowlist),
    // which reaches `executeSftpAction` before any binary or socket and still
    // produces the full sftp audit shape on the failed row.
    const handle = await makeSecret("v13-sftp", "sftp-private-key-placeholder");
    await vault.engine.setInjectionPolicy(handle, {});

    const action: UseSecretAction = {
      type: "sftp",
      host: "deploy.example.com",
      user: "deploy",
      operation: "upload",
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
    };
    await expect(vault.engine.useSecret(handle, action)).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });

    const row = await useRow(handle);
    expect(row.success).toBe(false);
    expect(row.detail).toEqual({
      context: "sftp",
      host: "deploy.example.com",
      operation: "upload",
      port: null,
      remote_path: "/srv/report.pdf",
      local_path: "/tmp/report.pdf",
      error: ErrorCode.HOST_NOT_ALLOWED,
    });
  });

  it("docker: reaches the injector and writes the §7.2 shape on a fail-safe deny", async () => {
    // No in-process Docker daemon/registry: pin engine→injector→audit through
    // the injector's fail-safe registry deny (empty host_allowlist). The
    // isolation refusal below is the other docker pin (engine-level).
    const handle = await makeSecret("v13-docker", "docker-user:docker-pass");
    await vault.engine.setInjectionPolicy(handle, {});

    const action: UseSecretAction = {
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/team/app:1.0",
      timeout_ms: 300_000,
    };
    await expect(vault.engine.useSecret(handle, action)).rejects.toMatchObject({
      code: ErrorCode.HOST_NOT_ALLOWED,
    });

    const row = await useRow(handle);
    expect(row.success).toBe(false);
    expect(row.detail).toEqual({
      context: "docker_registry",
      registry: "registry.example.com",
      image: "registry.example.com/team/app:1.0",
      operation: "pull",
      error: ErrorCode.HOST_NOT_ALLOWED,
    });
  });
});

describe("v1.3 contexts — the two thesis-mandated end-to-end refusals", () => {
  it("smtp recipient coupling: attachments without a recipient allowlist are refused", async () => {
    const handle = await makeSecret("v13-refuse-attach", "smtp-user:smtp-pass-refuse");
    // No smtp_recipient_allowlist configured.
    await vault.engine.setInjectionPolicy(handle, {
      host_allowlist: [`${LOOPBACK_HOST}:465`],
    });
    await vault.engine.setConnectionConfig(handle, { mail: { tls: { ca: FIXTURE_CA_PEM } } });

    const action: UseSecretAction = {
      type: "smtp",
      host: LOOPBACK_HOST,
      port: 465,
      security: "tls",
      from: "agent@harpoc.local",
      to: ["ops@example.com"],
      subject: "exfil attempt",
      text: "body",
      attachments: [{ path: "/tmp/secret-data.pdf" }],
    };
    await expect(vault.engine.useSecret(handle, action)).rejects.toMatchObject({
      code: ErrorCode.ATTACHMENT_POLICY_REQUIRED,
    });

    const row = await useRow(handle);
    expect(row.success).toBe(false);
    expect(row.detail).toMatchObject({
      context: "smtp",
      host: LOOPBACK_HOST,
      from: "agent@harpoc.local",
      recipients: ["ops@example.com"],
      attachment_paths: ["/tmp/secret-data.pdf"],
      attachment_total_bytes: 0,
      error: ErrorCode.ATTACHMENT_POLICY_REQUIRED,
    });
  });

  it("docker × isolation: network_isolation refuses a docker_registry action pre-dispatch", async () => {
    const handle = await makeSecret("v13-refuse-docker", "docker-user:docker-pass-iso");
    await vault.engine.setInjectionPolicy(handle, { network_isolation: true });

    const action: UseSecretAction = {
      type: "docker_registry",
      operation: "pull",
      image: "registry.example.com/team/app:1.0",
      timeout_ms: 300_000,
    };
    await expect(vault.engine.useSecret(handle, action)).rejects.toMatchObject({
      code: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
    });

    const row = await useRow(handle);
    expect(row.success).toBe(false);
    expect(row.detail).toMatchObject({
      context: "docker_registry",
      image: "registry.example.com/team/app:1.0",
      operation: "pull",
      network_isolation: true,
      error: ErrorCode.NETWORK_ISOLATION_UNAVAILABLE,
    });
  });
});
