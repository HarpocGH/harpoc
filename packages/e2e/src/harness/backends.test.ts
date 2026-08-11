import { describe, it, expect } from "vitest";
import { connect as netConnect } from "node:net";
import { PG, MYSQL, assertFleetUp } from "./backends.js";

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

  it("reaches the postgres container", async () => {
    assertFleetUp("postgres-tls");
    expect(await canOpenTcp(PG.ip, PG.port)).toBe(true);
  });

  it("reaches the mysql container", async () => {
    assertFleetUp("mysql-tls");
    expect(await canOpenTcp(MYSQL.ip, MYSQL.port)).toBe(true);
  });
});
