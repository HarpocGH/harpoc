import { describe, expect, it } from "vitest";
import type { ChildRun } from "../harness/child.js";
import { judgeSweep, parseNulList, sweepRecordText, sweepUserProcesses } from "./proc-sweep.js";
import type { ProcEntry } from "./proc-sweep.js";

const CREDENTIAL = "b6-sweep-credential-9a1f";
const PLACEHOLDER = "harpoc:api-key";
const SOCKET = "/run/harpoc/agent/ssh-agent.sock";
const JUDGED = { credentials: [CREDENTIAL], placeholders: [PLACEHOLDER, SOCKET] };

const entry = (pid: number, environ: string[], cmdline: string[]): ProcEntry => ({
  pid,
  environ,
  cmdline,
});

const driver = entry(
  101,
  [
    "PATH=/usr/bin",
    "HOME=/home/agent",
    `HARPOC_PLACEHOLDER_API_KEY=${PLACEHOLDER}`,
    "HARPOC_PROXY_TOKEN_FILE=/run/harpoc/agent/token.jwt",
    `SSH_AUTH_SOCK=${SOCKET}`,
  ],
  ["/usr/bin/node", "-e", "// harpoc-b6-driver"],
);
const curl = entry(
  102,
  ["PATH=/usr/bin", `HARPOC_PLACEHOLDER_API_KEY=${PLACEHOLDER}`],
  [
    "curl",
    "-sS",
    "-H",
    "@-",
    "-H",
    `Authorization: Bearer ${PLACEHOLDER}`,
    "http://127.0.0.1:3128/",
  ],
);
const ssh = entry(103, [`SSH_AUTH_SOCK=${SOCKET}`], ["ssh", "-p", "2222", "127.0.0.1", "true"]);

describe("parseNulList", () => {
  it("splits a /proc body on NUL, the trailing terminator dropped", () => {
    expect(parseNulList("A=1\0B=2\0")).toEqual(["A=1", "B=2"]);
    expect(parseNulList("curl\0-sS")).toEqual(["curl", "-sS"]);
    expect(parseNulList("")).toEqual([]);
  });
});

describe("judgeSweep", () => {
  it("holds when the agent's processes carry the placeholder and the socket path and none the credential", () => {
    expect(judgeSweep([driver, curl, ssh], JUDGED)).toEqual({
      credentialSeen: false,
      placeholderSeen: true,
      leakingPids: [],
      placeholderPids: [101, 102, 103],
      commands: ["node", "curl", "ssh"],
    });
  });

  it("sees the credential in an environment variable", () => {
    const leaking = entry(104, ["PATH=/usr/bin", `API_KEY=${CREDENTIAL}`], ["sleep", "60"]);
    const judged = judgeSweep([driver, leaking], JUDGED);
    expect(judged.credentialSeen).toBe(true);
    expect(judged.leakingPids).toEqual([104]);
  });

  it("sees the credential base64-encoded on a command line", () => {
    const encoded = Buffer.from(CREDENTIAL, "utf8").toString("base64");
    const leaking = entry(105, [], ["curl", `--oauth2-bearer=${encoded}`]);
    expect(judgeSweep([leaking], JUDGED)).toMatchObject({
      credentialSeen: true,
      leakingPids: [105],
    });
  });

  it("reports no placeholder where the sweep caught none of the agent's tools — the anti-vacuity half", () => {
    expect(judgeSweep([entry(7, ["PATH=/usr/bin"], ["/bin/bash"])], JUDGED)).toMatchObject({
      credentialSeen: false,
      placeholderSeen: false,
      commands: ["bash"],
    });
    expect(judgeSweep([], JUDGED)).toMatchObject({
      credentialSeen: false,
      placeholderSeen: false,
      commands: [],
    });
  });
});

describe("sweepRecordText", () => {
  it("keeps the command line and the variables the row is about, and drops the host's", () => {
    expect(sweepRecordText(driver, JUDGED)).toBe(
      [
        "pid 101: /usr/bin/node -e // harpoc-b6-driver",
        `  HARPOC_PLACEHOLDER_API_KEY=${PLACEHOLDER}`,
        "  HARPOC_PROXY_TOKEN_FILE=/run/harpoc/agent/token.jwt",
        `  SSH_AUTH_SOCK=${SOCKET}`,
      ].join("\n"),
    );
  });

  it("keeps any variable that carries a credential, whatever its name, so the record shows the leak", () => {
    const leaking = entry(9, ["PATH=/usr/bin", `DEPLOY_TOKEN=${CREDENTIAL}`], ["sleep", "60"]);
    // Boolean-shaped: a failing comparison never echoes the credential.
    expect(
      sweepRecordText(leaking, JUDGED) === `pid 9: sleep 60\n  DEPLOY_TOKEN=${CREDENTIAL}`,
    ).toBe(true);
  });
});

describe("sweepUserProcesses", () => {
  function fakeProc(
    pgrep: ChildRun,
    files: Record<string, string>,
  ): { read: (argv: string[]) => Promise<ChildRun>; calls: string[][] } {
    const calls: string[][] = [];
    return {
      calls,
      read: async (argv) => {
        calls.push(argv);
        if (argv[0] === "pgrep") return pgrep;
        const path = argv[1] ?? "";
        const body = files[path];
        return body === undefined
          ? { code: 1, stdout: "", stderr: `cat: ${path}: No such file or directory\n` }
          : { code: 0, stdout: body, stderr: "" };
      },
    };
  }

  it("lists the user's processes and reads each one's environ and cmdline through the reader", async () => {
    const proc = fakeProc(
      { code: 0, stdout: "12\n34\n", stderr: "" },
      {
        "/proc/12/environ": "A=1\0",
        "/proc/12/cmdline": "curl\0-sS\0",
        "/proc/34/environ": "B=2\0",
        "/proc/34/cmdline": "ssh\0",
      },
    );
    expect(await sweepUserProcesses("agent", proc.read)).toEqual([
      { pid: 12, environ: ["A=1"], cmdline: ["curl", "-sS"] },
      { pid: 34, environ: ["B=2"], cmdline: ["ssh"] },
    ]);
    expect(proc.calls).toEqual([
      ["pgrep", "-u", "agent"],
      ["cat", "/proc/12/environ"],
      ["cat", "/proc/12/cmdline"],
      ["cat", "/proc/34/environ"],
      ["cat", "/proc/34/cmdline"],
    ]);
  });

  it("skips a process that exited between the listing and the read", async () => {
    const proc = fakeProc(
      { code: 0, stdout: "12\n56\n", stderr: "" },
      { "/proc/12/environ": "A=1\0", "/proc/12/cmdline": "curl\0" },
    );
    expect((await sweepUserProcesses("agent", proc.read)).map((e) => e.pid)).toEqual([12]);
  });

  it("returns nothing where the user runs no process (pgrep exits 1)", async () => {
    const proc = fakeProc({ code: 1, stdout: "", stderr: "" }, {});
    expect(await sweepUserProcesses("agent", proc.read)).toEqual([]);
  });

  it("refuses a process it cannot read rather than sweeping past it", async () => {
    const read = async (argv: string[]): Promise<ChildRun> =>
      argv[0] === "pgrep"
        ? { code: 0, stdout: "77\n", stderr: "" }
        : { code: 1, stdout: "", stderr: `cat: ${argv[1] ?? ""}: Permission denied\n` };
    await expect(sweepUserProcesses("agent", read)).rejects.toThrow(/pid 77 could not be read/);
  });

  it("refuses a failed listing", async () => {
    const proc = fakeProc({ code: 2, stdout: "", stderr: "pgrep: bad option\n" }, {});
    await expect(sweepUserProcesses("agent", proc.read)).rejects.toThrow(/pgrep -u agent exited 2/);
  });
});
