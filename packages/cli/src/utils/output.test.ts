import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { printTable, printJson, printRecord, handleError, formatTimestamp } from "./output.js";

let consoleOutput: string[];
let consoleErrorOutput: string[];

beforeEach(() => {
  consoleOutput = [];
  consoleErrorOutput = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    consoleOutput.push(args.map(String).join(" "));
  });
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    consoleErrorOutput.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("printTable", () => {
  it("prints a table with headers and rows", () => {
    printTable([
      { Name: "foo", Type: "api_key" },
      { Name: "bar-baz", Type: "certificate" },
    ]);
    expect(consoleOutput[0]).toContain("Name");
    expect(consoleOutput[0]).toContain("Type");
    // Separator line
    expect(consoleOutput[1]).toMatch(/^-+/);
    // Data rows
    expect(consoleOutput[2]).toContain("foo");
    expect(consoleOutput[3]).toContain("bar-baz");
  });

  it("prints 'No results.' for empty array", () => {
    printTable([]);
    expect(consoleOutput[0]).toBe("No results.");
  });
});

describe("printJson", () => {
  it("prints JSON to stdout", () => {
    printJson({ key: "value" });
    expect(consoleOutput[0]).toBe(JSON.stringify({ key: "value" }, null, 2));
  });
});

describe("printRecord", () => {
  it("prints key-value pairs aligned", () => {
    printRecord({ Name: "test", Status: "active" });
    expect(consoleOutput.length).toBe(2);
    expect(consoleOutput[0]).toContain("Name");
    expect(consoleOutput[0]).toContain("test");
    expect(consoleOutput[1]).toContain("Status");
    expect(consoleOutput[1]).toContain("active");
  });
});

describe("handleError", () => {
  it("formats VAULT_LOCKED error with hint", () => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });

    try {
      handleError(VaultError.vaultLocked());
    } catch {
      // Expected
    }
    expect(consoleErrorOutput[0]).toContain("Run 'harpoc unlock' first");
  });

  it("formats VAULT_NOT_FOUND error with hint", () => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });

    try {
      handleError(VaultError.vaultNotFound());
    } catch {
      // Expected
    }
    expect(consoleErrorOutput[0]).toContain("Run 'harpoc init'");
  });

  it("formats LOCKOUT_ACTIVE with retry time", () => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });

    try {
      handleError(VaultError.lockoutActive(30000));
    } catch {
      // Expected
    }
    expect(consoleErrorOutput[0]).toContain("30s");
  });

  it("outputs JSON error when json flag is set", () => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });

    try {
      handleError(VaultError.vaultLocked(), true);
    } catch {
      // Expected
    }
    const errorStr = consoleErrorOutput[0] ?? "{}";
    const parsed = JSON.parse(errorStr) as { error: string; message: string };
    expect(parsed.error).toBe(ErrorCode.VAULT_LOCKED);
  });

  it("handles generic Error", () => {
    vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit");
    });

    try {
      handleError(new Error("something failed"));
    } catch {
      // Expected
    }
    expect(consoleErrorOutput[0]).toContain("something failed");
  });
});

describe("formatTimestamp", () => {
  it("formats a millisecond timestamp", () => {
    const result = formatTimestamp(1709251200000);
    expect(result).toMatch(/2024-03-01/);
  });

  it("formats a second-based timestamp", () => {
    const result = formatTimestamp(1709251200);
    expect(result).toMatch(/2024-03-01/);
  });

  it("returns '-' for null", () => {
    expect(formatTimestamp(null)).toBe("-");
  });
});
