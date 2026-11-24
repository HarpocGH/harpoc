import { describe, it, expect, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SSHD_BOOTSTRAP,
  agentPrivateKeyPem,
  agentPublicKey,
  bootstrapHostKey,
  bootstrapPassword,
  parseHostState,
} from "./bootstrap.js";

const RECOVERY = "run: pnpm --filter @harpoc/e2e bootstrap";
const KEY_BODY = randomBytes(51).toString("base64");

describe("the sshd-bootstrap fixture's readers", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-e2e-bootstrap-")));
  const empty = join(root, "empty");
  const full = join(root, "full");
  mkdirSync(empty);
  mkdirSync(full);
  const password = randomBytes(18).toString("base64url");
  writeFileSync(join(full, "password"), password);
  writeFileSync(join(full, "hostkey_ed25519.pub"), `ssh-ed25519 ${KEY_BODY} harpoc-e2e-hostkey\n`);
  writeFileSync(join(full, "agent_ed25519.pub"), `ssh-ed25519 ${KEY_BODY}\tharpoc-e2e-agent\n`);
  writeFileSync(join(full, "agent_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\n");

  afterAll(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it.each([
    ["bootstrapPassword", bootstrapPassword],
    ["bootstrapHostKey", bootstrapHostKey],
    ["agentPublicKey", agentPublicKey],
    ["agentPrivateKeyPem", agentPrivateKeyPem],
  ])("%s throws the fixture's recovery where out/ is empty", (_name, read) => {
    expect(() => read(empty)).toThrow(RECOVERY);
  });

  it("reads the password as the file holds it", () => {
    expect(Object.is(bootstrapPassword(full), password)).toBe(true);
  });

  it("reads a public key as `<type> <base64>`, its comment dropped", () => {
    expect(bootstrapHostKey(full)).toBe(`ssh-ed25519 ${KEY_BODY}`);
    expect(agentPublicKey(full)).toBe(`ssh-ed25519 ${KEY_BODY}`);
    expect(agentPrivateKeyPem(full)).toBe("-----BEGIN OPENSSH PRIVATE KEY-----\n");
  });

  it("names the two services on 127.0.0.1 at their own 55xxx ports", () => {
    expect(SSHD_BOOTSTRAP.sudo).toEqual({
      service: "sshd-bootstrap-sudo",
      host: "127.0.0.1",
      port: 55122,
    });
    expect(SSHD_BOOTSTRAP["sudo-rs"]).toEqual({
      service: "sshd-bootstrap-sudo-rs",
      host: "127.0.0.1",
      port: 55123,
    });
  });
});

describe("parseHostState", () => {
  it("reads the key lines, the drop-in's mode and owner, and whether sudo waits", () => {
    expect(parseHostState("1\n440:root\nwaiting\n")).toEqual({
      keyLines: 1,
      dropIn: "440:root",
      sudoWaiting: true,
    });
    expect(parseHostState("0\n-\nidle\n")).toEqual({
      keyLines: 0,
      dropIn: null,
      sudoWaiting: false,
    });
    expect(parseHostState("2\r\n440:root\r\nidle\r\n")).toEqual({
      keyLines: 2,
      dropIn: "440:root",
      sudoWaiting: false,
    });
  });

  it.each([
    ["no text", ""],
    ["two lines", "1\n-\n"],
    ["four lines", "1\n-\nidle\nidle\n"],
    ["a count that is no number", "one\n-\nidle\n"],
    ["an empty drop-in line", "1\n\nidle\n"],
    ["a third word of neither kind", "1\n-\nbusy\n"],
  ])("refuses %s", (_name, text) => {
    expect(() => parseHostState(text)).toThrow("unexpected host state");
  });
});
