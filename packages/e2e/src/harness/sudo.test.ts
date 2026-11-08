import type { ChildProcess } from "node:child_process";
import { describe, expect, it } from "vitest";
import { runCommand, sudoArgv } from "./sudo.js";

describe("sudoArgv", () => {
  it("runs the command as the user with -n and --, and no env when none is given", () => {
    expect(sudoArgv("harpoc", ["/usr/bin/node", "cli.js", "--version"])).toEqual([
      "-n",
      "-u",
      "harpoc",
      "--",
      "/usr/bin/node",
      "cli.js",
      "--version",
    ]);
  });

  it("hands each variable to /usr/bin/env as a NAME=value argument, in order, before the command", () => {
    expect(
      sudoArgv("harpoc", ["node", "server"], {
        HARPOC_SESSION_KEYSTORE: "off",
        CREDENTIALS_DIRECTORY: "/tmp/creds dir",
      }),
    ).toEqual([
      "-n",
      "-u",
      "harpoc",
      "--",
      "/usr/bin/env",
      "HARPOC_SESSION_KEYSTORE=off",
      "CREDENTIALS_DIRECTORY=/tmp/creds dir",
      "node",
      "server",
    ]);
  });

  it("refuses a variable name env would misread, naming the name and never the value", () => {
    expect(() => sudoArgv("agent", ["curl"], { "BAD=NAME": "value-1" })).toThrow(
      /^sudoArgv: "BAD=NAME" is not a variable name$/,
    );
    expect(() => sudoArgv("agent", ["curl"], { "": "value-2" })).toThrow(/is not a variable name/);
  });

  it("refuses a command env would take for one more assignment, and only where env runs", () => {
    expect(() => sudoArgv("agent", ["A=b"], { HOME: "/home/agent" })).toThrow(/assignment/);
    expect(sudoArgv("agent", ["A=b"])).toEqual(["-n", "-u", "agent", "--", "A=b"]);
  });
});

describe("runCommand", () => {
  it("writes stdin to the child and settles with its exit code and both streams", async () => {
    const run = await runCommand(
      process.execPath,
      [
        "-e",
        "process.stdin.on('data', (c) => process.stdout.write(c));" +
          "process.stdin.on('end', () => { process.stderr.write('e'); process.exitCode = 4; });",
      ],
      { stdin: "from stdin", label: "echo" },
    );
    expect(run).toEqual({ code: 4, stdout: "from stdin", stderr: "e" });
  });

  it("rejects naming a hung child once it is gone, and never with the child's output", async () => {
    const err = await runCommand(
      process.execPath,
      ["-e", "process.stdout.write('child-output-1'); setInterval(() => {}, 1000)"],
      { label: "hung", timeoutMs: 300 },
    ).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/^hung pid \d+ timed out after 300 ms/);
    expect(err?.message.includes("child-output-1")).toBe(false);
    const pid = Number(/pid (\d+)/.exec(err?.message ?? "")?.[1]);
    expect(() => process.kill(pid, 0)).toThrow();
  }, 1_500);

  it("delivers the deadline's signal through the hook it is given, then rejects naming the label", async () => {
    const delivered: string[] = [];
    const err = await runCommand(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], {
      timeoutMs: 100,
      label: "sleeper",
      deliver: (signal, child) => {
        delivered.push(signal);
        child.kill(signal);
      },
    }).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/^sleeper pid \d+ timed out after 100 ms and was killed$/);
    expect(delivered).toEqual(["SIGTERM"]);
  });

  it("rejects naming the label and the undelivered signal when the hook fails, never with the hook's own error", async () => {
    const held: { child?: ChildProcess } = {};
    try {
      const err = await runCommand(process.execPath, ["-e", "setTimeout(() => {}, 10000)"], {
        timeoutMs: 100,
        label: "sleeper",
        deliver: (_signal, child) => {
          held.child = child;
          throw new Error("kill EPERM");
        },
      }).then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      expect(err?.message.startsWith("sleeper pid ")).toBe(true);
      expect(err?.message).toContain("could not be delivered");
      expect(err?.message.includes("EPERM")).toBe(false);
    } finally {
      const child = held.child;
      if (child !== undefined && child.exitCode === null && child.signalCode === null) {
        await new Promise<void>((resolve) => {
          child.once("close", () => resolve());
          child.kill();
        });
      }
    }
  });
});
