import { ErrorCode } from "@harpoc/shared";
import type { UseSecretResponse } from "@harpoc/shared";
import { expectAbsent, expectVaultError } from "@harpoc/test-utils";
import { describe, expect, it, vi } from "vitest";
import { InjectionGuard } from "./injection-guard.js";
import { sanitizeUseSecretResult } from "./sanitize-result.js";

describe("sanitizeUseSecretResult", () => {
  const guard = new InjectionGuard();

  it("sanitizes credential patterns in a known result shape", () => {
    const result: UseSecretResponse = {
      type: "http",
      status: 200,
      body: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
    };
    sanitizeUseSecretResult(result, guard);
    expect(result.body).toContain("[REDACTED]");
  });

  // H3: a hostile downstream MCP server chooses its own key names, and the
  // boundary guard is the last layer before JSON.stringify hands the result to
  // the model. Key position must be sanitized like value position.
  it("sanitizes a credential-shaped string in an MCP structured_content key", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "mcp",
      content: [{ type: "text", text: "ok" }],
      structured_content: { [bearerish]: 1 },
    };
    sanitizeUseSecretResult(result, guard);
    expectAbsent(JSON.stringify(result), bearerish);
  });

  it("sanitizes a credential-shaped key inside an MCP content block", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "mcp",
      content: [{ type: "text", text: "ok", meta: { [bearerish]: true } }],
    };
    sanitizeUseSecretResult(result, guard);
    expectAbsent(JSON.stringify(result), bearerish);
  });

  it("sanitizes a credential-shaped database column name in a row object", () => {
    const bearerish = "Bearer abcdefghijklmnopqrstuvwxyz012345";
    const result: UseSecretResponse = {
      type: "database",
      rows: [{ [bearerish]: 1 }],
      fields: [],
      row_count: 1,
      truncated: false,
    };
    sanitizeUseSecretResult(result, guard);
    expectAbsent(JSON.stringify(result.rows), bearerish);
  });

  /**
   * T10: three of the six context branches were unpinned — replacing the
   * `database`, `git` and `ssh` cases with a bare `return;` kept the whole
   * suite green, so the boundary layer (the last one before the result is
   * stringified for the model) could silently stop covering half the contexts.
   */
  describe("every context shape is sanitized (T10)", () => {
    const BEARERISH = "Bearer abcdefghijklmnopqrstuvwxyz012345";

    it("database: row values, error text and the echoed command", () => {
      const result: UseSecretResponse = {
        type: "database",
        rows: [{ note: `token=${BEARERISH}` }],
        fields: [{ name: "note" }],
        row_count: 1,
        truncated: false,
        error: `query failed for ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(JSON.stringify(result.rows), BEARERISH, "the rows");
      expectAbsent(result.error, BEARERISH, "the error");
      expect(result.error).toContain("[REDACTED]");
    });

    it("git: stdout, stderr and error", () => {
      const result: UseSecretResponse = {
        type: "git",
        operation: "clone",
        stdout: `remote: ${BEARERISH}`,
        stderr: `fatal: could not read ${BEARERISH}`,
        exit_code: 1,
        error: `auth failed: ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.stdout, BEARERISH, "stdout");
      expectAbsent(result.stderr, BEARERISH, "stderr");
      expectAbsent(result.error, BEARERISH, "the error");
      expect(result.stdout).toContain("[REDACTED]");
    });

    it("ssh: stdout, stderr and error", () => {
      const result: UseSecretResponse = {
        type: "ssh",
        stdout: `printed ${BEARERISH}`,
        stderr: `warning about ${BEARERISH}`,
        exit_code: 0,
        error: `channel error ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.stdout, BEARERISH, "stdout");
      expectAbsent(result.stderr, BEARERISH, "stderr");
      expectAbsent(result.error, BEARERISH, "the error");
      expect(result.stderr).toContain("[REDACTED]");
    });

    it("sftp: stdout, stderr and error", () => {
      const result: UseSecretResponse = {
        type: "sftp",
        stdout: `transferred ${BEARERISH}`,
        stderr: `warning about ${BEARERISH}`,
        exit_code: 0,
        error: `sftp error ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.stdout, BEARERISH, "stdout");
      expectAbsent(result.stderr, BEARERISH, "stderr");
      expectAbsent(result.error, BEARERISH, "the error");
      expect(result.stdout).toContain("[REDACTED]");
    });

    it("process: stdout, stderr and error", () => {
      const result: UseSecretResponse = {
        type: "process",
        stdout: `env dump ${BEARERISH}`,
        stderr: `stderr ${BEARERISH}`,
        exit_code: 0,
        error: `spawn error ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.stdout, BEARERISH, "stdout");
      expectAbsent(result.stderr, BEARERISH, "stderr");
      expectAbsent(result.error, BEARERISH, "the error");
    });

    it("http: body, headers and error", () => {
      const result: UseSecretResponse = {
        type: "http",
        status: 401,
        body: `denied ${BEARERISH}`,
        headers: { "x-echo": BEARERISH },
        error: `HTTP error ${BEARERISH}`,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.body, BEARERISH, "the body");
      expectAbsent(result.headers?.["x-echo"], BEARERISH, "the x-echo header");
      expectAbsent(result.error, BEARERISH, "the error");
    });

    it("imap: fetched message content, at any depth", () => {
      const result: UseSecretResponse = {
        type: "imap",
        operation: "fetch",
        messages: [
          { uid: 1, flags: [], envelope: { subject: `re: ${BEARERISH}` }, text: BEARERISH },
        ],
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(JSON.stringify(result.messages), BEARERISH);
    });

    it("websocket: every collected frame", () => {
      const result: UseSecretResponse = {
        type: "websocket",
        messages: ["hello", `echo ${BEARERISH}`],
        close_code: 1000,
      };
      sanitizeUseSecretResult(result, guard);

      expectAbsent(result.messages[1], BEARERISH);
      expect(result.messages[0]).toBe("hello");
    });

    it("ssh_bootstrap: a status result passes unchanged and is never read as an ssh result", () => {
      const result: UseSecretResponse = {
        type: "ssh_bootstrap",
        key: "installed",
        sudoers: "written",
      };
      const spy = vi.spyOn(guard, "sanitize");
      try {
        sanitizeUseSecretResult(result, guard);
        expect(result).toEqual({ type: "ssh_bootstrap", key: "installed", sudoers: "written" });
        expect(spy).not.toHaveBeenCalled();
      } finally {
        spy.mockRestore();
      }
    });

    it("control: text carrying no credential pattern is left byte-identical", () => {
      const result: UseSecretResponse = {
        type: "ssh",
        stdout: "total 0\ndrwxr-xr-x 2 user user 4096 Jan  1 00:00 .",
        stderr: "",
        exit_code: 0,
      };
      const before = result.stdout;
      sanitizeUseSecretResult(result, guard);
      expect(result.stdout).toBe(before);
    });
  });

  it("rejects an unknown result type instead of passing it through unsanitized", async () => {
    const bogus = { type: "ftp", payload: "x" } as unknown as UseSecretResponse;
    const err = await expectVaultError(
      () => sanitizeUseSecretResult(bogus, guard),
      ErrorCode.INVALID_INPUT,
    );
    expect(err.message).toContain("Unsupported result type: ftp");
  });
});
