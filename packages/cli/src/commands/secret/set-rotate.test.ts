import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";
import { ErrorCode, VaultError } from "@harpoc/shared";

const { mockEngine, mockResolveSecretValue } = vi.hoisted(() => ({
  mockEngine: {
    createSecret: vi.fn(),
    rotateSecret: vi.fn(),
    destroy: vi.fn().mockResolvedValue(undefined),
  },
  mockResolveSecretValue: vi.fn(),
}));

vi.mock("../../utils/vault-loader.js", () => ({
  resolveVaultDir: vi.fn().mockReturnValue("/mock/.harpoc"),
  loadUnlockedEngine: vi.fn(),
}));

vi.mock("../../utils/secret-value.js", () => ({
  resolveSecretValue: mockResolveSecretValue,
}));

import { loadUnlockedEngine } from "../../utils/vault-loader.js";
import { registerSecretSetCommand } from "./set.js";
import { registerSecretRotateCommand } from "./rotate.js";

const loadEngineMock = vi.mocked(loadUnlockedEngine);

let errorSpy: ReturnType<typeof vi.spyOn>;
let exitSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  loadEngineMock.mockResolvedValue(mockEngine as never);
  mockEngine.createSecret.mockResolvedValue({ handle: "secret://k", name: "k" });
  mockEngine.rotateSecret.mockResolvedValue(undefined);
  mockResolveSecretValue.mockResolvedValue(Buffer.from("resolved-value", "utf8"));
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  exitSpy = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
});

afterEach(() => {
  errorSpy.mockRestore();
  exitSpy.mockRestore();
});

async function run(args: string[]): Promise<void> {
  const program = new Command();
  program.option("--vault-dir <path>", "Path to vault directory");
  const secret = program.command("secret");
  registerSecretSetCommand(secret);
  registerSecretRotateCommand(secret);
  program.exitOverride();
  program.configureOutput({ writeErr: () => {} });
  await program.parseAsync(["node", "harpoc", "secret", ...args]);
}

describe("secret set/rotate — sealed vault fails before the value is resolved (review fix F4)", () => {
  beforeEach(() => {
    loadEngineMock.mockRejectedValue(VaultError.vaultLocked());
  });

  it("set: a sealed vault never consults the value/passphrase prompt", async () => {
    await run(["set", "k", "--from-file", "/nonexistent/key.pem"]);
    expect(exitSpy).toHaveBeenCalledWith(1);
    // Pre-fix, resolveSecretValue ran (and could prompt for a passphrase,
    // leaving decrypted key material unwiped) before the engine load threw.
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
  });

  it("rotate: a sealed vault never consults the value/passphrase prompt", async () => {
    await run(["rotate", "secret://k", "--from-file", "/nonexistent/key.pem"]);
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
  });

  it("control: an unlocked vault resolves the value and stores it", async () => {
    loadEngineMock.mockResolvedValue(mockEngine as never);
    await run(["set", "k"]);
    expect(mockResolveSecretValue).toHaveBeenCalledTimes(1);
    expect(mockEngine.createSecret).toHaveBeenCalledWith(
      expect.objectContaining({ name: "k", value: expect.any(Buffer) }),
    );
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

describe("secret set/rotate — value wiped even when the engine call throws (review fix F4)", () => {
  it("set: the resolved buffer is zeroed after createSecret rejects", async () => {
    const value = Buffer.from("super-secret-material", "utf8");
    mockResolveSecretValue.mockResolvedValue(value);
    mockEngine.createSecret.mockRejectedValue(
      new VaultError(ErrorCode.DUPLICATE_SECRET, "duplicate"),
    );

    await run(["set", "k"]);

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect([...value].every((b) => b === 0)).toBe(true);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("rotate: the resolved buffer is zeroed after rotateSecret rejects", async () => {
    const value = Buffer.from("rotated-secret-material", "utf8");
    mockResolveSecretValue.mockResolvedValue(value);
    mockEngine.rotateSecret.mockRejectedValue(
      new VaultError(ErrorCode.SECRET_NOT_FOUND, "missing"),
    );

    await run(["rotate", "secret://k"]);

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect([...value].every((b) => b === 0)).toBe(true);
    expect(mockEngine.destroy).toHaveBeenCalledTimes(1);
  });

  it("control: the success path wipes too", async () => {
    const value = Buffer.from("stored-secret-material", "utf8");
    mockResolveSecretValue.mockResolvedValue(value);

    await run(["set", "k"]);

    expect(mockEngine.createSecret).toHaveBeenCalledTimes(1);
    expect([...value].every((b) => b === 0)).toBe(true);
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

describe("secret set — type validation precedes any prompt (review fix F4)", () => {
  it("an invalid --type fails before the value is resolved", async () => {
    await run(["set", "k", "--type", "not-a-type"]);
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(mockResolveSecretValue).not.toHaveBeenCalled();
    expect(loadEngineMock).not.toHaveBeenCalled();
  });
});

describe("secret set/rotate — --no-decrypt and --from-file Commander mapping (review T5)", () => {
  // The classic Commander negation trap: `--no-decrypt` materializes as
  // options.decrypt === false, NOT options.noDecrypt. Reading the wrong
  // property would silently decrypt anyway — pinned against real Commander.
  it("set: --no-decrypt reaches resolveSecretValue as noDecrypt: true", async () => {
    await run(["set", "k", "--no-decrypt"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ noDecrypt: true }),
    );
  });

  it("set: the default decrypts at import (noDecrypt: false)", async () => {
    await run(["set", "k"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ noDecrypt: false }),
    );
  });

  it("rotate: --no-decrypt reaches resolveSecretValue as noDecrypt: true", async () => {
    await run(["rotate", "secret://k", "--no-decrypt"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ noDecrypt: true }),
    );
  });

  it("rotate: the default decrypts at import (noDecrypt: false)", async () => {
    await run(["rotate", "secret://k"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ noDecrypt: false }),
    );
  });

  it("both commands forward the --from-file path verbatim", async () => {
    await run(["set", "k", "--from-file", "C:/keys/id.pem"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ fromFile: "C:/keys/id.pem" }),
    );
    mockResolveSecretValue.mockClear();
    await run(["rotate", "secret://k", "--from-file", "C:/keys/id.pem"]);
    expect(mockResolveSecretValue).toHaveBeenCalledWith(
      expect.objectContaining({ fromFile: "C:/keys/id.pem" }),
    );
  });
});
