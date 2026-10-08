import { describe, expect, it } from "vitest";

import { mcpProtocolRevisionSchema, mcpServerConfigSchema, mcpTransportSchema } from "./schemas.js";
import { renderSchemaIssues } from "./schema-issues.js";

// ---------------------------------------------------------------------------
// mcpServerConfigSchema
// ---------------------------------------------------------------------------

describe("mcpTransportSchema", () => {
  it("accepts stdio and http", () => {
    expect(mcpTransportSchema.parse("stdio")).toBe("stdio");
    expect(mcpTransportSchema.parse("http")).toBe("http");
  });

  it("rejects unknown transports", () => {
    expect(() => mcpTransportSchema.parse("sse")).toThrow();
  });
});

describe("mcpProtocolRevisionSchema", () => {
  it("accepts the two revisions and refuses another value-free", () => {
    expect(mcpProtocolRevisionSchema.parse("2025-11-25")).toBe("2025-11-25");
    expect(mcpProtocolRevisionSchema.parse("2026-07-28")).toBe("2026-07-28");
    const refused = mcpProtocolRevisionSchema.safeParse("2025-03-26");
    expect(refused.success).toBe(false);
    if (refused.success) return;
    expect(renderSchemaIssues(refused.error)).toBe("<root>: must be one of 2025-11-25, 2026-07-28");
  });
});

describe("mcpServerConfigSchema", () => {
  const validStdio = {
    server_name: "github-mcp",
    transport: "stdio",
    command: "node",
    args: ["server.js"],
    env_var: "GITHUB_TOKEN",
  };

  const validHttp = {
    server_name: "remote-mcp",
    transport: "http",
    url: "https://mcp.example.com/mcp",
  };

  it("accepts a valid stdio config", () => {
    const result = mcpServerConfigSchema.parse(validStdio);
    expect(result.transport).toBe("stdio");
    expect(result.command).toBe("node");
  });

  it("accepts a valid http config", () => {
    const result = mcpServerConfigSchema.parse(validHttp);
    expect(result.transport).toBe("http");
    expect(result.url).toBe("https://mcp.example.com/mcp");
  });

  it("rejects stdio without a command", () => {
    expect(() =>
      mcpServerConfigSchema.parse({
        server_name: "x",
        transport: "stdio",
        env_var: "TOKEN",
      }),
    ).toThrow();
  });

  it("rejects stdio without an env_var", () => {
    expect(() =>
      mcpServerConfigSchema.parse({
        server_name: "x",
        transport: "stdio",
        command: "node",
      }),
    ).toThrow();
  });

  it("rejects http without a url", () => {
    expect(() => mcpServerConfigSchema.parse({ server_name: "x", transport: "http" })).toThrow();
  });

  it("rejects an invalid env_var name", () => {
    expect(() => mcpServerConfigSchema.parse({ ...validStdio, env_var: "has-dash" })).toThrow();
  });

  it("rejects an invalid server_name format", () => {
    expect(() => mcpServerConfigSchema.parse({ ...validStdio, server_name: "bad name" })).toThrow();
  });

  it("defaults protocol to 2025-11-25 and keeps an explicit 2026-07-28", () => {
    const legacy = mcpServerConfigSchema.parse({
      server_name: "s",
      transport: "http",
      url: "https://x.example/mcp",
    });
    expect(legacy.protocol).toBe("2025-11-25");
    const modern = mcpServerConfigSchema.parse({
      server_name: "s",
      transport: "http",
      url: "https://x.example/mcp",
      protocol: "2026-07-28",
    });
    expect(modern.protocol).toBe("2026-07-28");
  });
});
