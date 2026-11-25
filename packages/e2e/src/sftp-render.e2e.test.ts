import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { renderEntryDigest } from "@harpoc/core";
import {
  AuditEventType,
  ErrorCode,
  Permission,
  VAULT_DB_NAME,
  VaultError,
  isRenderTempName,
} from "@harpoc/shared";
import type { RenderEntry } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { assertOpaque } from "./assert/opacity.js";
import { assertFleetUp } from "./harness/backends.js";
import { resolveSsh } from "./harness/fixtures.js";
import {
  PLANTED,
  RENDER_TARGET,
  plant,
  remoteEntry,
  removeRenderDir,
  renderAddress,
  renderDirNames,
  resetRenderDir,
} from "./harness/render.js";
import { clientKeyPem, hostKeyLine } from "./harness/ssh.js";
import { startMcpHttpSurface } from "./harness/surfaces/mcp-http.js";
import type { CallOutcome, McpHttpSurface } from "./harness/surfaces/mcp-http.js";
import { createHarnessVault, grantOn, storeSecret } from "./harness/vault.js";
import type { HarnessVault } from "./harness/vault.js";

const NO_ROUTE = process.platform !== "linux";
const AGENT = "e2e-render-agent";
const KEY = "secret://deploy-key";
const BOT = "secret://bot-token";
const API = "secret://api-key";
const DB = "secret://db-password";
const SLOTS = [BOT, API, DB];
const TEMPLATE = [
  "# app.env, rendered by harpoc",
  "BOT_TOKEN={{secret://bot-token}}",
  "API_KEY={{secret://api-key}}",
  "DATABASE_URL=postgres://app:{{secret://db-password}}@db.internal:5432/app",
  "BOT_TOKEN_AGAIN={{secret://bot-token}}",
  "",
].join("\n");
const WRITTEN = { type: "sftp_render", status: "written" };
const ISO = { network_isolation: false, fs_isolation: false };

function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface UseRow {
  secret: string | null;
  success: boolean;
  principal: [string | null, string | null];
  detail: Record<string, unknown> | null;
}

// The render reaches sshd-pinned at its address on the compose network, since an entry's host may
// not be loopback, and only a Linux host has a route to that network: neither the Windows nor
// the macOS host of a Docker Desktop has one (harness/backends.ts), so the rows run on Linux alone.
describe.skipIf(NO_ROUTE)("the sftp render against sshd-pinned's real sftp-server", () => {
  let vault: HarnessVault;
  let surface: McpHttpSurface;
  let fleetReached = false;
  let address: string;
  let keyPem: string;
  let keyId: string;
  let ids: Record<string, string>;
  let values: Record<string, string>;
  let appEnv: RenderEntry;
  let occupied: RenderEntry;

  beforeAll(async () => {
    assertFleetUp(RENDER_TARGET.service);
    fleetReached = true;
    address = renderAddress();
    vault = await createHarnessVault(randomBytes(18).toString("base64url"));
    keyPem = clientKeyPem();
    const entry = (name: string, file: string): RenderEntry => ({
      name,
      host: address,
      port: RENDER_TARGET.port,
      user: RENDER_TARGET.user,
      path: `${RENDER_TARGET.dir}/${file}`,
      host_keys: [hostKeyLine("pinned")],
      template: TEMPLATE,
    });
    appEnv = entry("app-env", "app.env");
    occupied = entry("occupied", "occupied");

    expect(await storeSecret(vault, "deploy-key", keyPem)).toBe(KEY);
    await vault.engine.setInjectionPolicy(KEY, {
      url_allowlist: [],
      command_allowlist: [resolveSsh()],
      env_allowlist: [],
      host_allowlist: [address],
      render: { entries: [appEnv, occupied], approvals: [] },
    });
    keyId = await vault.engine.resolveSecretId(KEY);
    ids = { [KEY]: keyId };
    values = {};
    for (const handle of SLOTS) {
      values[handle] = randomBytes(18).toString("base64url");
      expect(await storeSecret(vault, handle.slice("secret://".length), values[handle])).toBe(
        handle,
      );
      await vault.engine.setInjectionPolicy(handle, {
        url_allowlist: [],
        command_allowlist: [],
        env_allowlist: [],
        host_allowlist: [],
        render: {
          entries: [],
          approvals: [appEnv, occupied].map((approved) => ({
            key: keyId,
            entry: approved.name,
            digest: renderEntryDigest(approved),
          })),
        },
      });
      ids[handle] = await vault.engine.resolveSecretId(handle);
    }
    for (const handle of [KEY, ...SLOTS]) {
      await grantOn(vault, handle, AGENT, [Permission.USE]);
    }
    surface = await startMcpHttpSurface(vault, AGENT, [Permission.USE]);
  });

  beforeEach(() => {
    resetRenderDir();
  });

  afterAll(async () => {
    await surface?.close();
    await vault?.destroy();
    if (fleetReached) removeRenderDir();
  });

  function content(): Buffer {
    return Buffer.from(
      TEMPLATE.replaceAll("{{secret://bot-token}}", values[BOT] as string)
        .replaceAll("{{secret://api-key}}", values[API] as string)
        .replaceAll("{{secret://db-password}}", values[DB] as string),
      "utf8",
    );
  }

  /** Every regular file under the vault's directory, read as latin1; one that vanished is skipped. */
  function vaultFiles(): { name: string; text: string }[] {
    return readdirSync(vault.tmpDir, { recursive: true, encoding: "utf8" }).flatMap((name) => {
      const path = join(vault.tmpDir, name);
      try {
        return lstatSync(path).isFile() ? [{ name, text: readFileSync(path, "latin1") }] : [];
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
        throw err;
      }
    });
  }

  function lastUseId(): number {
    return Math.max(
      0,
      ...vault.engine.queryAudit({ eventType: AuditEventType.SECRET_USE }).map((row) => row.id),
    );
  }

  function useRowsAfter(mark: number): UseRow[] {
    return vault.engine
      .queryAudit({ eventType: AuditEventType.SECRET_USE })
      .filter((row) => row.id > mark)
      .sort((a, b) => a.id - b.id)
      .map((row) => ({
        secret: row.secret_id,
        success: row.success,
        principal: [row.principal_type ?? null, row.principal_id ?? null],
        detail: row.detail,
      }));
  }

  function callRows(entry: RenderEntry, success: boolean, key: Record<string, unknown>): UseRow[] {
    const where = {
      host: address,
      port: RENDER_TARGET.port,
      user: RENDER_TARGET.user,
      remote_path: entry.path,
    };
    const principal: [string, string] = ["agent", AGENT];
    return [
      {
        secret: keyId,
        success,
        principal,
        detail: {
          context: "sftp",
          ...where,
          operation: "render",
          entry: entry.name,
          slots: SLOTS,
          ...ISO,
          interface: surface.auditInterface,
          ...key,
        },
      },
      ...SLOTS.map((handle) => ({
        secret: ids[handle] as string,
        success,
        principal,
        detail: {
          context: "sftp",
          operation: "render",
          entry: entry.name,
          key: KEY,
          ...where,
          ...ISO,
          interface: surface.auditInterface,
        },
      })),
    ];
  }

  /**
   * One render through the MCP surface; no slot's value and not the key's PEM text, each searched
   * whole, in any channel or in a file of the vault's directory, the database among them.
   */
  async function render(entry: RenderEntry): Promise<CallOutcome> {
    const outcome = await surface.callUseSecret(KEY, {
      type: "sftp",
      operation: "render",
      entry: entry.name,
    });
    const auditRows = vault.engine.queryAudit();
    const files = vaultFiles();
    expect(files.some((file) => file.name === VAULT_DB_NAME)).toBe(true);
    for (const [label, value] of [
      [KEY, keyPem],
      ...SLOTS.map((handle) => [handle, values[handle] as string]),
    ] as [string, string][]) {
      assertOpaque(value, {
        result: outcome.result,
        error: outcome.errorText,
        auditRows,
        parentEnv: process.env,
      });
      for (const file of files) {
        expectAbsent(file.text, value, `${file.name} of the vault, for ${label}`);
      }
    }
    return outcome;
  }

  it("the closing row against a real sftp-server: the file's bytes, mode 0600 and owner by stat", async () => {
    const mark = lastUseId();
    const outcome = await render(appEnv);

    expect(outcome.ok, outcome.text).toBe(true);
    expect(JSON.parse(outcome.text)).toStrictEqual(WRITTEN);
    const expected = content();
    expect(remoteEntry("app.env")).toStrictEqual({
      kind: "file",
      mode: "600",
      owner: "harpoc",
      size: expected.length,
      sha256: sha256(expected),
    });
    expect(renderDirNames()).toStrictEqual(["app.env"]);
    expect(useRowsAfter(mark)).toStrictEqual(callRows(appEnv, true, { written: "yes" }));
  });

  it("a file at the path is replaced by one of mode 0600", async () => {
    plant("file", "app.env");
    expect(remoteEntry("app.env")).toStrictEqual({
      kind: "file",
      mode: "644",
      owner: "harpoc",
      size: PLANTED.length,
      sha256: sha256(PLANTED),
    });

    const outcome = await render(appEnv);

    expect(outcome.ok, outcome.text).toBe(true);
    expect(JSON.parse(outcome.text)).toStrictEqual(WRITTEN);
    const expected = content();
    expect(remoteEntry("app.env")).toStrictEqual({
      kind: "file",
      mode: "600",
      owner: "harpoc",
      size: expected.length,
      sha256: sha256(expected),
    });
    expect(renderDirNames()).toStrictEqual(["app.env"]);
  });

  it("a link at the path is replaced, not followed", async () => {
    plant("file", "target.env");
    plant("link", "app.env", `${RENDER_TARGET.dir}/target.env`);
    expect(remoteEntry("app.env").kind).toBe("link");

    const outcome = await render(appEnv);

    expect(outcome.ok, outcome.text).toBe(true);
    expect(JSON.parse(outcome.text)).toStrictEqual(WRITTEN);
    const expected = content();
    expect(remoteEntry("app.env")).toStrictEqual({
      kind: "file",
      mode: "600",
      owner: "harpoc",
      size: expected.length,
      sha256: sha256(expected),
    });
    expect(remoteEntry("target.env")).toStrictEqual({
      kind: "file",
      mode: "644",
      owner: "harpoc",
      size: PLANTED.length,
      sha256: sha256(PLANTED),
    });
    expect(renderDirNames().sort()).toStrictEqual(["app.env", "target.env"]);
  });

  it("a directory at the path fails the rename, and the temporary file is gone", async () => {
    plant("directory", "occupied");
    const mark = lastUseId();

    const outcome = await render(occupied);

    expect(outcome.ok, outcome.text).toBe(false);
    expect(outcome.errorText ?? "").toContain(VaultError.renderFailed().message);
    expect(useRowsAfter(mark)).toStrictEqual(
      callRows(occupied, false, {
        written: "no",
        error: ErrorCode.RENDER_FAILED,
        reason: "rename",
      }),
    );
    expect(remoteEntry("occupied").kind).toBe("directory");
    expect(renderDirNames("occupied")).toStrictEqual([]);
    const names = renderDirNames();
    expect(names.filter((name) => isRenderTempName(name, "occupied"))).toStrictEqual([]);
    expect(names).toStrictEqual(["occupied"]);
  });
});
