import { spawnSync } from "node:child_process";
import type { SpawnSyncReturns } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expectAbsent } from "@harpoc/test-utils";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { tierRequired } from "./__fixtures__/platform-tier.js";
import { requireFsIsolation } from "./fs-isolation.js";
import { writeHelperFiles } from "./spawn-captured-helpers.js";
import type { HelperFiles, HelperFilesSpec } from "./spawn-captured-helpers.js";
import { SSH_ASKPASS_FILES, SSH_PASSWORD_HELPER_SRC } from "./ssh-injector-bootstrap.js";

const PROMPT = "deploy@host.example's password: ";
const HOST_LINE = "line-for-the-host\n";
const READ_BACK = `${SSH_PASSWORD_HELPER_SRC}import { readFileSync } from "node:fs";
writeSync(1, "read:" + readFileSync(0, "utf8"));
`;

const REFUSED_ARGUMENTS: Array<[string, string[]]> = [
  ["the old-password prompt", ["Enter deploy@host.example's old password: "]],
  ["the new-password prompt", ["Enter deploy@host.example's new password: "]],
  ["another user", ["root@host.example's password: "]],
  ["another host", ["deploy@other.example's password: "]],
  ["keyboard-interactive's prompt", ["(deploy@host.example) Password: "]],
  ["a bare prompt", ["Password: "]],
  ["the empty argument", [""]],
  ["the prompt with one more blank", [`${PROMPT} `]],
  ["the prompt with a final line feed", [`${PROMPT}\n`]],
  ["the prompt without its final blank", [PROMPT.slice(0, -1)]],
  ["the user in upper case", ["DEPLOY@host.example's password: "]],
  ["no argument", []],
  ["two arguments", [PROMPT, PROMPT]],
];

function identity(err: unknown): unknown {
  return err;
}

function helperEnv(password: string, word: string): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HARPOC_SSH_PROMPT: PROMPT,
    HARPOC_SSH_WORD: word,
    HARPOC_SSH_PASSWORD: password,
  };
}

function askAs(
  command: string,
  args: string[],
  env: Record<string, string>,
): SpawnSyncReturns<string> {
  return spawnSync(command, args, { env, input: HOST_LINE, encoding: "utf8", timeout: 20_000 });
}

function freshSecret(): string {
  return randomBytes(18).toString("base64url");
}

function expectRefusedSilently(r: SpawnSyncReturns<string>, password: string): void {
  expectAbsent(r.stdout, password, "standard output");
  expectAbsent(r.stderr, password, "standard error");
  expect(r.status).toBe(1);
  expect(r.stdout).toBe("");
  expect(r.stderr).toBe("");
}

let tempRoot: string;
let savedTmpdir: string | undefined;

beforeEach(() => {
  tempRoot = realpathSync(mkdtempSync(join(tmpdir(), "harpoc-askpass-t-")));
  savedTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = tempRoot;
});

afterEach(() => {
  if (savedTmpdir === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = savedTmpdir;
  rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

// POSIX only: the engine refuses the bootstrap on a Windows vault host, and node refuses to
// spawn the .cmd launcher without a shell.
describe.skipIf(process.platform === "win32")("the ssh bootstrap's password helper", () => {
  let files: HelperFiles;

  beforeEach(() => {
    files = writeHelperFiles(SSH_ASKPASS_FILES, identity);
  });

  it("the expected prompt", () => {
    const password = freshSecret();
    const word = freshSecret();
    const r = askAs(files.launcher, [PROMPT], helperEnv(password, word));
    expect(r.status).toBe(0);
    expect(r.stderr).toBe(`\n${word}\n`);
    expect(r.stdout === `${password}\n`).toBe(true);
  });

  it.each(REFUSED_ARGUMENTS)("refuses %s, writing nothing", (_name, args) => {
    const password = freshSecret();
    const r = askAs(files.launcher, args, helperEnv(password, freshSecret()));
    expectRefusedSilently(r, password);
  });

  it.each(["HARPOC_SSH_PROMPT", "HARPOC_SSH_WORD", "HARPOC_SSH_PASSWORD"])(
    "refuses without %s in its environment, writing nothing",
    (name) => {
      const password = freshSecret();
      const env = Object.fromEntries(
        Object.entries(helperEnv(password, freshSecret())).filter(([key]) => key !== name),
      );
      expectRefusedSilently(askAs(files.launcher, [PROMPT], env), password);
      expectRefusedSilently(askAs(files.launcher, [""], env), password);
    },
  );

  it("does not read the input meant for the host", () => {
    const password = freshSecret();
    const env = helperEnv(password, freshSecret());
    const quiet = writeHelperFiles({ ...SSH_ASKPASS_FILES, source: READ_BACK }, identity);
    const control: HelperFilesSpec = {
      prefix: SSH_ASKPASS_FILES.prefix,
      script: SSH_ASKPASS_FILES.script,
      launcher: SSH_ASKPASS_FILES.launcher,
      source: READ_BACK,
    };
    const open = writeHelperFiles(control, identity);
    const fromQuiet = askAs(quiet.launcher, [PROMPT], env);
    const fromOpen = askAs(open.launcher, [PROMPT], env);
    expect(fromQuiet.status).toBe(0);
    expect(fromQuiet.stdout === `${password}\nread:`).toBe(true);
    expect(fromOpen.status).toBe(0);
    expect(fromOpen.stdout === `${password}\nread:${HOST_LINE}`).toBe(true);
  });

  describe("under filesystem isolation", () => {
    let fsAvailable = false;

    beforeAll(async () => {
      let probeError: unknown;
      try {
        await requireFsIsolation("/bin/true", []);
        fsAvailable = true;
      } catch (err) {
        probeError = err;
      }
      if (!fsAvailable && tierRequired("fs-isolation")) {
        throw new Error(
          `HARPOC_REQUIRE_PLATFORM_TESTS demands the "fs-isolation" tier but its probe failed: ${String(probeError)}`,
        );
      }
    });

    it("the expected prompt, through the wrapper", async (ctx) => {
      if (!fsAvailable) {
        return ctx.skip("filesystem isolation is unavailable and not required here");
      }
      const password = freshSecret();
      const word = freshSecret();
      const wrapped = await requireFsIsolation(files.launcher, [PROMPT]);
      const r = askAs(wrapped.command, wrapped.args, helperEnv(password, word));
      expect(r.status).toBe(0);
      expect(r.stderr).toBe(`\n${word}\n`);
      expect(r.stdout === `${password}\n`).toBe(true);
    });
  });
});
