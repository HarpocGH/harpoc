import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { VaultEngine } from "@harpoc/core";
import { createMcpServer } from "@harpoc/mcp-server";
import { AuditEventType, SecretType } from "@harpoc/shared";
import type { Permission, TokenPrincipalType } from "@harpoc/shared";
import { connectInMemoryClient, connectModernInMemoryClient } from "@harpoc/test-utils";
import type { InMemoryMcpClient, InMemoryToolResult } from "@harpoc/test-utils";
import { createTestVault, destroyTestVault, registerAgents } from "./helpers/engine-factory.js";
import type { TestVault } from "./helpers/engine-factory.js";

const VALUE = "m1-typed-into-the-one-time-form";
const FORM_HEADERS = { "content-type": "application/x-www-form-urlencoded" };
const CLIENT_INFO = { name: "m1-client", version: "1.0.0" };
const URL_CHANNEL = { capabilities: { elicitation: { url: {} } } };

type Leg = "legacy" | "modern";
const LEGS: Leg[] = ["legacy", "modern"];

type CappedField = "name" | "project";
const CAPPED_FIELDS: CappedField[] = ["name", "project"];

interface LaunchToken {
  label: string;
  subject: string;
  principalType: TokenPrincipalType;
  scope: Permission[];
}

const LAUNCH_TOKENS: LaunchToken[] = [
  {
    label: "an agent token [create]",
    subject: "m1-agent",
    principalType: "agent",
    scope: ["create"],
  },
  { label: "a tool token [create]", subject: "m1-tool", principalType: "tool", scope: ["create"] },
  { label: "a user token [create]", subject: "m1-user", principalType: "user", scope: ["create"] },
  {
    label: "an agent token [admin]",
    subject: "m1-admin-agent",
    principalType: "agent",
    scope: ["admin"],
  },
];

interface FormLog {
  opened: number;
}

/** Connect a launch-token session on one protocol era, the client declaring the URL channel. */
function connect(engine: VaultEngine, leg: Leg, launchToken: string): Promise<InMemoryMcpClient> {
  return leg === "legacy"
    ? connectInMemoryClient(createMcpServer({ engine, launchToken }), CLIENT_INFO, URL_CHANNEL)
    : connectModernInMemoryClient(
        () => createMcpServer({ engine, launchToken }),
        CLIENT_INFO,
        URL_CHANNEL,
      );
}

/** Decline every value form the session opens, or post the typed value after `beforePost`. */
function answerForms(
  session: InMemoryMcpClient,
  answer: "post" | "decline",
  beforePost?: () => Promise<unknown>,
): FormLog {
  const log: FormLog = { opened: 0 };
  session.client.setRequestHandler("elicitation/create", async (request) => {
    log.opened++;
    const params = request.params as { url?: string };
    if (answer === "decline" || typeof params.url !== "string") return { action: "decline" };
    await beforePost?.();
    await fetch(params.url, {
      method: "POST",
      headers: FORM_HEADERS,
      body: `value=${encodeURIComponent(VALUE)}`,
    });
    return { action: "accept" };
  });
  return log;
}

/** Return the newest audit row's id, so a test reads only the rows its own call wrote. */
function lastAuditId(engine: VaultEngine): number {
  return Math.max(0, ...engine.queryAudit({}).map((row) => row.id));
}

describe("create_secret collects the value, then creates the secret (C-4)", () => {
  let vault: TestVault;

  beforeAll(async () => {
    vault = createTestVault();
    await vault.engine.initVault("m1-create-secret-value-pw");
    registerAgents(vault.engine, "m1-agent", "m1-admin-agent");
  });

  afterAll(async () => {
    await destroyTestVault(vault);
  });

  const rowsSince = (mark: number) => vault.engine.queryAudit({}).filter((row) => row.id > mark);
  const statusesOf = (secretName: string) =>
    vault.engine
      .listSecrets()
      .filter((info) => info.name === secretName)
      .map((info) => info.status);

  it.each(LEGS.flatMap((leg) => LAUNCH_TOKENS.map((launch) => ({ leg, ...launch }))))(
    "$leg leg, $label: the typed value is stored by the one create — created, active, one row, no failed row",
    async ({ leg, subject, principalType, scope }) => {
      const secretName = `${leg}-${subject}`;
      const handle = `secret://${secretName}`;
      const token = vault.engine.createToken(subject, scope, 3_600_000, { principalType });
      const mark = lastAuditId(vault.engine);
      const session = await connect(vault.engine, leg, token);
      let result: InMemoryToolResult;
      try {
        answerForms(session, "post");
        result = await session.callTool("create_secret", { name: secretName, type: "api_key" });
      } finally {
        await session.close();
      }

      const text = result.content[0]?.text ?? "";
      expect(result.isError ?? false).toBe(false);
      expect(text.includes(VALUE)).toBe(false);
      const payload = JSON.parse(text) as { handle: string; status: string };
      expect(payload.handle).toBe(handle);
      expect(payload.status).toBe("created");
      expect(statusesOf(secretName)).toEqual(["active"]);

      const rows = rowsSince(mark);
      expect(JSON.stringify(rows).includes(VALUE)).toBe(false);
      expect(rows.filter((row) => !row.success)).toEqual([]);
      const creates = rows.filter((row) => row.event_type === AuditEventType.SECRET_CREATE);
      expect(creates).toHaveLength(1);
      expect(creates[0]).toMatchObject({
        success: true,
        principal_type: principalType,
        principal_id: subject,
      });
      expect(creates[0]?.detail).toEqual({ handle, status: "created", interface: "mcp" });

      expect(
        Buffer.from(await vault.engine.getSecretValue(handle)).equals(Buffer.from(VALUE)),
      ).toBe(true);
    },
  );

  it.each(LEGS)(
    "%s leg: a declined form leaves one pending secret, the hint and one row",
    async (leg) => {
      const secretName = `${leg}-declined`;
      const handle = `secret://${secretName}`;
      const token = vault.engine.createToken("m1-agent", ["create"]);
      const mark = lastAuditId(vault.engine);
      const session = await connect(vault.engine, leg, token);
      let forms: FormLog;
      let result: InMemoryToolResult;
      try {
        forms = answerForms(session, "decline");
        result = await session.callTool("create_secret", { name: secretName, type: "api_key" });
      } finally {
        await session.close();
      }

      expect(forms.opened).toBe(1);
      expect(result.isError ?? false).toBe(false);
      expect(JSON.parse(result.content[0]?.text ?? "")).toEqual({
        handle,
        status: "pending",
        message: `Secret created. Set the value with: harpoc secret set ${secretName}`,
      });
      expect(statusesOf(secretName)).toEqual(["pending"]);

      const rows = rowsSince(mark);
      expect(rows.filter((row) => !row.success)).toEqual([]);
      const creates = rows.filter((row) => row.event_type === AuditEventType.SECRET_CREATE);
      expect(creates).toHaveLength(1);
      expect(creates[0]).toMatchObject({
        success: true,
        principal_type: "agent",
        principal_id: "m1-agent",
      });
      expect(creates[0]?.detail).toEqual({ handle, status: "pending", interface: "mcp" });
    },
  );

  it.each(LEGS)(
    "%s leg: a taken name is refused DUPLICATE_SECRET before any form opens",
    async (leg) => {
      const secretName = `${leg}-taken`;
      await vault.engine.createSecret({ name: secretName, type: SecretType.API_KEY });
      const token = vault.engine.createToken("m1-agent", ["create"]);
      const session = await connect(vault.engine, leg, token);
      let forms: FormLog;
      let result: InMemoryToolResult;
      try {
        forms = answerForms(session, "post");
        result = await session.callTool("create_secret", { name: secretName, type: "api_key" });
      } finally {
        await session.close();
      }

      expect(forms.opened).toBe(0);
      expect(result.isError).toBe(true);
      const text = result.content[0]?.text ?? "";
      expect(text.includes(`Secret already exists: ${secretName}`)).toBe(true);
      expect(statusesOf(secretName)).toEqual(["pending"]);
    },
  );

  it.each(LEGS)(
    "%s leg: a name taken while the form is open ends DUPLICATE_SECRET after it, the typed bytes zeroed",
    async (leg) => {
      const secretName = `${leg}-taken-while-open`;
      const token = vault.engine.createToken("m1-agent", ["create"]);
      const create = vi.spyOn(vault.engine, "createSecret");
      let session: InMemoryMcpClient | undefined;
      let forms: FormLog;
      let result: InMemoryToolResult;
      let typed: Uint8Array | undefined;
      try {
        session = await connect(vault.engine, leg, token);
        forms = answerForms(session, "post", () =>
          vault.engine.createSecret({ name: secretName, type: SecretType.API_KEY }),
        );
        result = await session.callTool("create_secret", { name: secretName, type: "api_key" });
        typed = create.mock.calls
          .map(([input]) => input.value)
          .find((bytes) => bytes !== undefined);
      } finally {
        create.mockRestore();
        await session?.close();
      }

      expect(forms.opened).toBe(1);
      expect(result.isError).toBe(true);
      const text = result.content[0]?.text ?? "";
      expect(text.includes(`Secret already exists: ${secretName}`)).toBe(true);
      expect(text.includes(VALUE)).toBe(false);
      expect(typed?.length).toBe(Buffer.byteLength(VALUE));
      expect(typed?.every((byte) => byte === 0)).toBe(true);
      expect(statusesOf(secretName)).toEqual(["pending"]);
    },
  );

  it.each(LEGS.flatMap((leg) => CAPPED_FIELDS.map((field): [Leg, CappedField] => [leg, field])))(
    "%s leg: a 256-character %s is refused at the tool's boundary before any form opens",
    async (leg, field) => {
      const tooLong = "a".repeat(256);
      const secretName = field === "name" ? tooLong : `${leg}-long-project`;
      const token = vault.engine.createToken("m1-agent", ["create"]);
      const mark = lastAuditId(vault.engine);
      const session = await connect(vault.engine, leg, token);
      let forms: FormLog;
      let result: InMemoryToolResult;
      try {
        forms = answerForms(session, "post");
        result = await session.callTool("create_secret", {
          name: secretName,
          type: "api_key",
          ...(field === "project" ? { project: tooLong } : {}),
        });
      } finally {
        await session.close();
      }

      expect(forms.opened).toBe(0);
      expect(result.isError).toBe(true);
      expect((result.content[0]?.text ?? "").includes("Input validation error")).toBe(true);
      expect(statusesOf(secretName)).toEqual([]);
      expect(
        rowsSince(mark).filter((row) => row.event_type === AuditEventType.SECRET_CREATE),
      ).toEqual([]);
    },
  );
});
