import { describe, expect, it } from "vitest";
import { openControllingTerminal } from "./tty-prompt.js";

/**
 * The real terminal opener — every other tty-prompt test injects a fake
 * terminal, so the actual CONIN$/CONOUT$ (Windows) / /dev/tty (POSIX) open
 * path was exercised by no test on any platform. Attempt-and-skip (the
 * symlink-test pattern): hosts without a controlling terminal (headless CI,
 * GUI-spawned processes) skip; console hosts run it for real.
 */
describe("openControllingTerminal (real opener)", () => {
  it("opens and closes the real controlling terminal where one exists", (ctx) => {
    const terminal = openControllingTerminal();
    if (!terminal) {
      ctx.skip();
      return;
    }
    try {
      expect(terminal.input).toBeTruthy();
      expect(terminal.output).toBeTruthy();
    } finally {
      terminal.close();
    }
  });
});
