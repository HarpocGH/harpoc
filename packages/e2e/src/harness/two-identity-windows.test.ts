import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AGENT_DRIVER_WINDOWS,
  B7_MARKER,
  EXISTS_PROBE,
  LIST_DIRECTORY,
  READ_FILE,
  REMOVE_FILE,
  REMOVE_TREE,
  REPORT_SELF,
  agentDriverArgv,
  agentTools,
  cliArgv,
  consumerPathsWindows,
  curlArgsWindows,
  daemonArgsWindows,
  defaultRuntimeDirWindows,
  forwardSlashes,
  nodeOneLiner,
  removeVaultRoot,
  sshArgsWindows,
  startTwoAccountDeployment,
} from "./two-identity-windows.js";
import {
  AGENT_DRIVER,
  B6_MARKER,
  TOKEN_FILE_REQUEST,
  WRITE_STDIN_TO_FILE,
} from "./two-identity.js";

const SEALED = "C:\\ProgramData\\harpoc\\vault\\harpoc-b7-ab12\\unlock.key.dpapi";

describe("the Windows layout", () => {
  it("derives the consumer's token file and agent pipe from the runtime directory and the consumer's name", () => {
    expect(consumerPathsWindows("C:\\ProgramData\\harpoc\\run", "harpoc-ci-agent")).toEqual({
      dir: "C:\\ProgramData\\harpoc\\run\\harpoc-ci-agent",
      tokenFile: "C:\\ProgramData\\harpoc\\run\\harpoc-ci-agent\\token.jwt",
      agentPipe: "\\\\.\\pipe\\harpoc-harpoc-ci-agent-ssh-agent",
    });
  });

  it("defaults the runtime directory to %ProgramData%\\harpoc\\run and refuses an unset ProgramData", () => {
    expect(defaultRuntimeDirWindows("C:\\ProgramData")).toBe("C:\\ProgramData\\harpoc\\run");
    expect(() => defaultRuntimeDirWindows("")).toThrow(/ProgramData is not set/);
  });
});

describe("daemonArgsWindows", () => {
  const args = daemonArgsWindows(
    "C:\\v\\vault",
    "C:\\ProgramData\\harpoc\\run",
    "agent1",
    { rest: 4001, proxy: 4002 },
    SEALED,
  );

  it("starts the daemon headless from the sealed key, in memory mode, with the proxy, the pipe and the token file", () => {
    expect(args).toEqual([
      "--vault-dir",
      "C:\\v\\vault",
      "server",
      "start",
      "--rest",
      "--port",
      "4001",
      "--runtime-dir",
      "C:\\ProgramData\\harpoc\\run",
      "--session",
      "memory",
      "--unlock-key-dpapi",
      SEALED,
      "--proxy",
      "--proxy-port",
      "4002",
      "--ssh-agent",
      "--issue-token",
      "agent=agent1,file=C:\\ProgramData\\harpoc\\run\\agent1\\token.jwt,scope=use,secrets=api-key+deploy-key,ttl=60",
    ]);
  });

  it("names no plaintext key source and no credential directory", () => {
    expect(args.includes("--unlock-key-file")).toBe(false);
    expect(args.includes("--unlock-credential")).toBe(false);
  });
});

describe("the agent's tools", () => {
  const d = {
    agentFiles: {
      knownHosts: "C:/ProgramData/b7/known_hosts",
      identity: "C:/ProgramData/b7/id.pub",
    },
    sshServer: { port: 2222 },
    placeholders: { apiKey: "harpoc:api-key" },
  };

  it("hardens ssh as the Linux row does, with forward-slash paths and no quoting", () => {
    const args = sshArgsWindows(d);
    expect(args).toContain("UserKnownHostsFile=C:/ProgramData/b7/known_hosts");
    expect(args).toContain("IdentitiesOnly=yes");
    expect(args).toContain("StrictHostKeyChecking=yes");
    expect(args.slice(-3)).toEqual(["--", "127.0.0.1", "true"]);
    expect(args[args.indexOf("-l") + 1]).toBe(B7_MARKER);
    expect(args.some((a) => a.includes('"'))).toBe(false);
  });

  it("gives curl the placeholder as the bearer and the token on stdin only", () => {
    const args = curlArgsWindows(d, "http://127.0.0.1:3128/x", ["-D", "-"]);
    expect(args).toEqual([
      "-sS",
      "--user-agent",
      B7_MARKER,
      "-D",
      "-",
      "-H",
      "@-",
      "-H",
      "Authorization: Bearer harpoc:api-key",
      "http://127.0.0.1:3128/x",
    ]);
  });

  it("runs the native clients by their System32 paths", () => {
    expect(agentTools("C:\\Windows")).toEqual({
      curl: "C:\\Windows\\System32\\curl.exe",
      ssh: "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
    });
  });

  it("is the Linux driver with the Windows marker and nothing else changed", () => {
    expect(AGENT_DRIVER_WINDOWS.includes(B6_MARKER)).toBe(false);
    expect(AGENT_DRIVER_WINDOWS.includes(`// ${B7_MARKER}-driver`)).toBe(true);
    expect(AGENT_DRIVER_WINDOWS.replaceAll(B7_MARKER, B6_MARKER)).toBe(AGENT_DRIVER);
  });

  it("writes a path with forward slashes", () => {
    expect(forwardSlashes("C:\\a\\b c\\d")).toBe("C:/a/b c/d");
  });
});

describe("what either account runs carries the marker, so the teardown's sweep reaches it", () => {
  it("passes every one-liner its own arguments first and the marker last", () => {
    for (const script of [
      LIST_DIRECTORY,
      READ_FILE,
      EXISTS_PROBE,
      REMOVE_FILE,
      REPORT_SELF,
      TOKEN_FILE_REQUEST,
      WRITE_STDIN_TO_FILE,
    ]) {
      expect(nodeOneLiner(script, "C:\\x")).toEqual([
        process.execPath,
        "-e",
        script,
        "C:\\x",
        B7_MARKER,
      ]);
    }
  });

  it("runs the agent's driver from its file in the agent's own directory, the marker last (its text is over the 1024 characters CreateProcessWithLogonW takes)", () => {
    const driverFile = "C:\\ProgramData\\harpoc-b7-public\\harpoc-b7-agent-ab12\\driver.cjs";
    expect(agentDriverArgv(driverFile)).toEqual([process.execPath, driverFile, B7_MARKER]);
  });

  it("removes the run's root as the vault account with one node one-liner — rmSync in the X-1 form on its argument, the marker last", () => {
    const root = "C:\\ProgramData\\harpoc\\vault\\harpoc-b7-ab12";
    expect(nodeOneLiner(REMOVE_TREE, root)).toEqual([
      process.execPath,
      "-e",
      "require('node:fs').rmSync(process.argv[1], { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })",
      root,
      B7_MARKER,
    ]);
  });

  it("runs the built CLI with the marker as node's own --title, which the CLI's parser never sees", () => {
    expect(cliArgv("C:\\cli\\dist\\index.js", ["proxy", "env"])).toEqual([
      process.execPath,
      `--title=${B7_MARKER}`,
      "C:\\cli\\dist\\index.js",
      "proxy",
      "env",
    ]);
  });
});

/**
 * The root's removal with the vault account's run stubbed: a scratch directory
 * this process owns stands in for the vault-owned root, so whether the
 * runner's `rmSync` ran is read from whether the directory is gone.
 */
describe("removeVaultRoot (the vault account's run stubbed)", () => {
  let root = "";

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "harpoc-b7-root-"));
    writeFileSync(join(root, "unlock.key.dpapi"), "unit-fixture-not-a-blob");
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("a removal as the vault account that fails and leaves the root refuses before the runner's rmSync, naming the vault account and its exit code", async () => {
    let thrown: unknown;
    try {
      await removeVaultRoot(root, "harpoc", async () => ({ code: 1, stdout: "", stderr: "" }));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe(
      `${root}: removing it as harpoc exited 1, and the runner cannot remove what the vault account's access list keeps (the sealed key)`,
    );
    expect(existsSync(join(root, "unlock.key.dpapi"))).toBe(true);
  });

  it("after a removal as the vault account that succeeded, the runner removes what is left and nothing is thrown", async () => {
    await removeVaultRoot(root, "harpoc", async () => ({ code: 0, stdout: "", stderr: "" }));
    expect(existsSync(root)).toBe(false);
  });
});

describe("startTwoAccountDeployment's preconditions", () => {
  const absent = join(tmpdir(), `harpoc-b7-absent-${String(process.pid)}`);

  afterAll(() => {
    rmSync(absent, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("refuses a vault root the recipe did not make, naming it and the recipe, before it starts or creates anything", async () => {
    await expect(
      startTwoAccountDeployment({
        vault: { user: "harpoc-b7-no-such-account", password: "unit-fixture-pw-1" },
        agent: { user: "harpoc-b7-no-such-account", password: "unit-fixture-pw-2" },
        runtimeDir: join(absent, "run"),
        vaultRoot: join(absent, "vault"),
        publicRoot: join(absent, "public"),
        password: "unit-fixture-master-1",
        apiKeyValue: "unit-fixture-api-key-1",
      }),
    ).rejects.toThrow(
      /vault root .* does not exist: run deploy\/windows\/install-two-identity\.ps1/,
    );
    expect(existsSync(absent)).toBe(false);
  });
});
