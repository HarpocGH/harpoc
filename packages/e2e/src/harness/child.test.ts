import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";
import { runNodeChild, stopChild } from "./child.js";

describe("e2e child deadlines", () => {
  it("settles with the exit code, stdout and stderr of a child that ends", async () => {
    const run = await runNodeChild(
      ["-e", "process.stdout.write('o');process.stderr.write('e');process.exit(3)"],
      { label: "quick" },
    );
    expect(run).toEqual({ code: 3, stdout: "o", stderr: "e" });
  });

  it("rejects naming a hung child, and only once it is gone", async () => {
    const err = await runNodeChild(["-e", "setInterval(()=>{},1000)"], {
      label: "hung",
      timeoutMs: 300,
    }).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/^hung pid \d+ timed out after 300 ms/);
    const pid = Number(/pid (\d+)/.exec(err?.message ?? "")?.[1]);
    expect(() => process.kill(pid, 0)).toThrow();
  }, 1_500);

  it.skipIf(process.platform === "win32")(
    "stopChild escalates to SIGKILL on a child that ignores SIGTERM (POSIX; win32 kill() is already TerminateProcess)",
    async () => {
      const child = spawn(process.execPath, [
        "-e",
        "process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)",
      ]);
      try {
        await new Promise((r) => child.stdout.once("data", r));
        await stopChild(child, "stubborn", 200);
        expect(child.signalCode).toBe("SIGKILL");
      } finally {
        child.kill("SIGKILL");
      }
    },
  );
});
