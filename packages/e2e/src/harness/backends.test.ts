import { describe, it, expect } from "vitest";
import { connect as netConnect } from "node:net";
import {
  PG,
  MYSQL,
  SSHD_PINNED,
  SSHD_ROGUE,
  GIT_HTTP,
  ECHO_HTTPS,
  MCP_DOWNSTREAM,
  assertFleetUp,
} from "./backends.js";

/**
 * Plain TCP, deliberately NOT a TLS handshake: PostgreSQL 16 only starts TLS
 * after an in-protocol SSLRequest (TLS-first is a PostgreSQL 17 feature) and
 * MySQL greets in plaintext before negotiating, so a raw TLS client is
 * answered with non-TLS bytes and would read a healthy server as down. These
 * probes claim reachability only; the verified TLS handshakes belong to the
 * database arms, which drive the real driver stacks.
 */
function canOpenTcp(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.setTimeout(5_000, () => {
      socket.destroy();
      resolve(false);
    });
  });
}

describe("backend fleet", () => {
  it("fails with an actionable message when the service is unknown", () => {
    expect(() => assertFleetUp("does-not-exist" as never)).toThrow(/docker compose|pnpm/i);
  });

  it("exposes the offset loopback ports, never the defaults", () => {
    // 5432/3306 would let a developer's own database answer and turn a green
    // run into evidence about the wrong server.
    expect(PG.port).toBe(55432);
    expect(PG.plainPort).toBe(55433);
    expect(MYSQL.port).toBe(55306);
    expect(PG.host).toBe("localhost");
  });

  it("addresses the two sshd servers at distinct loopback aliases on port 22", () => {
    // The ssh context cannot speak any port but 22 (F-1), so the pinned and
    // rogue servers must live at different addresses, not different ports.
    expect(SSHD_PINNED.host).toBe("127.0.0.2");
    expect(SSHD_ROGUE.host).toBe("127.0.0.3");
    expect(SSHD_PINNED.port).toBe(22);
    expect(SSHD_ROGUE.port).toBe(22);
    expect(SSHD_PINNED.host).not.toBe(SSHD_ROGUE.host);
  });

  it("keeps the git-http credential distinct from the database password", () => {
    expect(GIT_HTTP.port).toBe(55080);
    expect(GIT_HTTP.password).not.toBe(PG.password);
  });

  it("reaches the postgres container", async () => {
    assertFleetUp("postgres-tls");
    expect(await canOpenTcp(PG.ip, PG.port)).toBe(true);
  });

  it("reaches the mysql container", async () => {
    assertFleetUp("mysql-tls");
    expect(await canOpenTcp(MYSQL.ip, MYSQL.port)).toBe(true);
  });

  it("reaches the pinned and rogue sshd containers on their aliases", async () => {
    assertFleetUp("sshd-pinned");
    assertFleetUp("sshd-rogue");
    expect(await canOpenTcp(SSHD_PINNED.host, SSHD_PINNED.port)).toBe(true);
    expect(await canOpenTcp(SSHD_ROGUE.host, SSHD_ROGUE.port)).toBe(true);
  });

  it("reaches the git-http container", async () => {
    assertFleetUp("git-http");
    expect(await canOpenTcp(GIT_HTTP.host, GIT_HTTP.port)).toBe(true);
  });

  it("reaches the echo-https container on its own offset port", async () => {
    expect(ECHO_HTTPS.port).toBe(55443);
    assertFleetUp("echo-https");
    expect(await canOpenTcp(ECHO_HTTPS.ip, ECHO_HTTPS.port)).toBe(true);
  });

  it("reaches the mcp-downstream container on its own offset port", async () => {
    expect(MCP_DOWNSTREAM.port).toBe(55090);
    expect(MCP_DOWNSTREAM.endpoint).toContain(String(MCP_DOWNSTREAM.port));
    assertFleetUp("mcp-downstream");
    expect(await canOpenTcp(MCP_DOWNSTREAM.host, MCP_DOWNSTREAM.port)).toBe(true);
  });
});
