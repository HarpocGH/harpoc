import { spawn } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import { CHILD_TIMEOUT_MS } from "../harness/child.js";
import { windowsCommandLine } from "../harness/runas-windows.js";
import { runCommand } from "../harness/sudo.js";
import {
  B7_MARKER,
  INVENTORY_COMMAND,
  inventoryArgv,
  inventoryRecordText,
  judgeInventory,
  listAccountProcesses,
  parseInventory,
} from "./process-inventory-windows.js";
import type { InventoryEntry } from "./process-inventory-windows.js";

const CREDENTIAL = "b7-inventory-credential-value-5d1e";
const PLACEHOLDER = "harpoc:api-key";

/** `Get-CimInstance Win32_Process` as measured on the dev host (Windows 11 26200, standard token), trimmed to three processes. */
const MEASURED =
  '[{"ProcessId":1192,"Name":"winlogon.exe","CommandLine":null},{"ProcessId":2052,"Name":"lsass.exe","CommandLine":null},{"ProcessId":130748,"Name":"node.exe","CommandLine":"\\"C:\\\\Program Files\\\\nodejs\\\\node.exe\\" -e \\"setTimeout(()=\\u003e{},20000)\\" harpoc-b7-marker "}]';

const entry = (pid: number, name: string, commandLine: string | null): InventoryEntry => ({
  pid,
  name,
  commandLine,
});

describe("parseInventory", () => {
  it("reads the listing as measured, PowerShell's \\u003e escape and null command lines included", () => {
    expect(parseInventory(MEASURED)).toEqual([
      entry(1192, "winlogon.exe", null),
      entry(2052, "lsass.exe", null),
      entry(
        130748,
        "node.exe",
        '"C:\\Program Files\\nodejs\\node.exe" -e "setTimeout(()=>{},20000)" harpoc-b7-marker ',
      ),
    ]);
  });

  it("refuses a listing that does not parse with its own message, quoting none of the listing", () => {
    const fragment = "pw-4ac1e";
    const listing = `[{"ProcessId":1,"Name":"x.exe","CommandLine":"x"}, ${fragment}-tail]`;
    let thrown: unknown;
    try {
      parseInventory(listing);
    } catch (err) {
      thrown = err;
    }
    expect(thrown instanceof SyntaxError).toBe(true);
    expect(thrown instanceof Error && thrown.message.includes(fragment)).toBe(false);
    expect(thrown instanceof Error && thrown.cause === undefined).toBe(true);
    expect(thrown instanceof Error ? thrown.message : undefined).toBe(
      `process inventory: the listing (${String(listing.length)} characters) is not valid JSON`,
    );
  });

  it("refuses a listing that is not an array of entries", () => {
    expect(() => parseInventory('{"ProcessId":1}')).toThrow(/not an array/);
    expect(() => parseInventory('[{"ProcessId":"1","Name":"x","CommandLine":null}]')).toThrow(
      /malformed entry at index 0/,
    );
  });
});

describe("judgeInventory", () => {
  const opts = { credentials: [CREDENTIAL], placeholders: [PLACEHOLDER], foreignPids: [4242] };

  it("finds the account's own marked tools and its placeholder, and a foreign pid listed without its command line", () => {
    const judged = judgeInventory(
      [
        entry(
          10,
          "curl.exe",
          `curl.exe --user-agent ${B7_MARKER} -H "Authorization: Bearer ${PLACEHOLDER}"`,
        ),
        entry(11, "ssh.exe", `ssh.exe -v -l ${B7_MARKER}`),
        entry(4242, "node.exe", null),
        entry(1, "System", null),
      ],
      opts,
    );
    expect(judged).toEqual({
      credentialSeen: false,
      placeholderSeen: true,
      leakingPids: [],
      placeholderPids: [10],
      markedPids: [10, 11],
      foreignListed: [4242],
      foreignReadable: [],
      commands: ["curl.exe", "ssh.exe"],
    });
  });

  it("sights a credential in any encoding in any command line, and a foreign command line it can read", () => {
    const encoded = Buffer.from(CREDENTIAL).toString("base64");
    const judged = judgeInventory(
      [entry(10, "x.exe", `x.exe ${encoded}`), entry(4242, "node.exe", "node.exe server start")],
      opts,
    );
    expect(judged.credentialSeen).toBe(true);
    expect(judged.leakingPids).toEqual([10]);
    expect(judged.foreignReadable).toEqual([4242]);
  });

  it("reports a foreign pid the listing does not hold as not listed", () => {
    expect(judgeInventory([entry(1, "System", null)], opts).foreignListed).toEqual([]);
  });
});

describe("inventoryRecordText", () => {
  const opts = { credentials: [CREDENTIAL], placeholders: [PLACEHOLDER], foreignPids: [4242] };

  it("keeps the marked processes, the carriers and the foreign pids — stating the absence of a line", () => {
    expect(inventoryRecordText(entry(4242, "node.exe", null), opts)).toBe(
      "pid 4242: node.exe [command line not carried]",
    );
    expect(inventoryRecordText(entry(10, "curl.exe", `curl.exe ${B7_MARKER}`), opts)).toBe(
      `pid 10: curl.exe curl.exe ${B7_MARKER}`,
    );
    expect(inventoryRecordText(entry(11, "x.exe", `x.exe ${PLACEHOLDER}`), opts)).toContain(
      PLACEHOLDER,
    );
  });

  it("leaves out every other process of the host", () => {
    expect(
      inventoryRecordText(entry(1, "svchost.exe", "svchost.exe -k netsvcs"), opts),
    ).toBeUndefined();
    expect(inventoryRecordText(entry(2, "lsass.exe", null), opts)).toBeUndefined();
  });
});

describe("the inventory command", () => {
  it("is the standard cmdlet through the pinned Windows PowerShell, with no shell and no P/Invoke", () => {
    const argv = inventoryArgv("C:\\Windows");
    expect(argv[0]).toBe("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    expect(argv.at(-1)).toBe(INVENTORY_COMMAND);
    expect(INVENTORY_COMMAND).toContain("Get-CimInstance Win32_Process");
    expect(/Add-Type|DllImport|OpenProcess|ReadProcessMemory/.test(INVENTORY_COMMAND)).toBe(false);
  });

  it("refuses to read past a listing that failed", async () => {
    vi.stubEnv("SystemRoot", "");
    try {
      await expect(
        listAccountProcesses(async () => ({ code: 1, stdout: "", stderr: "boom" }), "C:\\Windows"),
      ).rejects.toThrow(/the listing exited 1/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

const READY_SCRIPT = "process.stdout.write('ready'); setInterval(() => {}, 1000)";
const NON_ASCII_ARGUMENT = "unit-fixture-\u2192-\u00fc";

/** Runs `body` with the pid of a marked child that has written its readiness, then kills the child and awaits its exit. */
async function whileMarkedChildRuns(
  argument: string,
  body: (pid: number) => Promise<void>,
): Promise<void> {
  const child = spawn(process.execPath, ["-e", READY_SCRIPT, `${B7_MARKER}-unit`, argument], {
    shell: false,
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  try {
    await new Promise<void>((resolve, reject) => {
      const bound = setTimeout(() => {
        reject(new Error(`the marked child wrote nothing within ${String(CHILD_TIMEOUT_MS)} ms`));
      }, CHILD_TIMEOUT_MS);
      child.stdout.once("data", () => {
        clearTimeout(bound);
        resolve();
      });
      child.once("exit", (code) => {
        clearTimeout(bound);
        reject(new Error(`the marked child exited before it was listed (code ${String(code)})`));
      });
    });
    await body(child.pid as number);
  } finally {
    child.kill();
    await exited;
  }
}

/**
 * Windows only (`Win32_Process`, `powershell.exe`). The same-account listing is
 * the account switch's seam, as in `runas-windows.test.ts`: the harness's own
 * child, marked, is listed with its command line — the control's channel — and
 * a system service process (`lsass.exe`, another account's) is listed without.
 */
describe.skipIf(process.platform !== "win32")("the inventory on this host", () => {
  const read = (argv: string[]) =>
    runCommand(argv[0] ?? "", argv.slice(1), { label: "process inventory" });

  it(
    "carries a marked child's command line and not a system service process's",
    async () => {
      await whileMarkedChildRuns("unit-fixture-argument", async (pid) => {
        const entries = await listAccountProcesses(read);
        const own = entries.find((e) => e.pid === pid);
        expect(own?.commandLine?.includes("unit-fixture-argument")).toBe(true);
        const system = entries.filter((e) => e.name.toLowerCase() === "lsass.exe");
        expect(system.length).toBe(1);
        expect(system[0]?.commandLine === null).toBe(true);
      });
    },
    CHILD_TIMEOUT_MS + 10_000,
  );

  it(
    "carries a marked child's non-ASCII command line exactly, whatever the console code page",
    async () => {
      await whileMarkedChildRuns(NON_ASCII_ARGUMENT, async (pid) => {
        const entries = await listAccountProcesses(read);
        expect(entries.find((e) => e.pid === pid)?.commandLine).toBe(
          windowsCommandLine([
            process.execPath,
            "-e",
            READY_SCRIPT,
            `${B7_MARKER}-unit`,
            NON_ASCII_ARGUMENT,
          ]),
        );
      });
    },
    CHILD_TIMEOUT_MS + 10_000,
  );
});
