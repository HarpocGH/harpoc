import { spawn } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
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

/**
 * Windows only (`Win32_Process`, `powershell.exe`). The same-account listing is
 * the account switch's seam, as in `runas-windows.test.ts`: the harness's own
 * child, marked, is listed with its command line — the control's channel — and
 * a system service process (`lsass.exe`, another account's) is listed without.
 */
describe.skipIf(process.platform !== "win32")("the inventory on this host", () => {
  const read = (argv: string[]) =>
    runCommand(argv[0] ?? "", argv.slice(1), { label: "process inventory" });

  it("carries a marked child's command line and not a system service process's", async () => {
    const child = spawn(
      process.execPath,
      ["-e", "setTimeout(() => {}, 30000)", `${B7_MARKER}-unit`, "unit-fixture-argument"],
      { shell: false, stdio: "ignore", windowsHide: true },
    );
    try {
      const pid = child.pid as number;
      const entries = await listAccountProcesses(read);
      const own = entries.find((e) => e.pid === pid);
      expect(own?.commandLine?.includes("unit-fixture-argument")).toBe(true);
      const system = entries.filter((e) => e.name.toLowerCase() === "lsass.exe");
      expect(system.length).toBe(1);
      expect(system[0]?.commandLine).toBeNull();
    } finally {
      child.kill();
    }
  }, 60_000);
});
