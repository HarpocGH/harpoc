import { EventEmitter } from "node:events";
import { describe, it, expect, vi } from "vitest";
import { collectValueFromTty, promptForValueMasked } from "./tty-prompt.js";
import type { ControllingTerminal } from "./tty-prompt.js";

interface FakeTerminal {
  terminal: ControllingTerminal;
  emit: (data: string) => void;
  written: () => string;
  setRawMode: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
}

function fakeTerminal(): FakeTerminal {
  const emitter = new EventEmitter();
  const chunks: string[] = [];
  const setRawMode = vi.fn();
  const close = vi.fn();
  const terminal: ControllingTerminal = {
    input: {
      setRawMode,
      on: (event, listener) => emitter.on(event, listener),
      removeListener: (event, listener) => emitter.removeListener(event, listener),
    },
    output: {
      write: (text: string) => {
        chunks.push(text);
      },
    },
    close,
  };
  return {
    terminal,
    emit: (data: string) => emitter.emit("data", Buffer.from(data, "utf8")),
    written: () => chunks.join(""),
    setRawMode,
    close,
  };
}

describe("promptForValueMasked", () => {
  it("collects the typed value on Enter without echoing it", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "Enter value: ", 1000);

    fake.emit("s3c");
    fake.emit("ret");
    fake.emit("\r");

    const value = await promise;
    expect(Buffer.from(value as Uint8Array).toString("utf8")).toBe("s3cret");
    expect(fake.written()).toContain("Enter value: ");
    expect(fake.written()).not.toContain("s3c");
    expect(fake.setRawMode).toHaveBeenNthCalledWith(1, true);
    expect(fake.setRawMode).toHaveBeenLastCalledWith(false);
  });

  it("supports backspace editing", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);

    fake.emit("ab");
    fake.emit("\x7f");
    fake.emit("c\n");

    const value = await promise;
    expect(Buffer.from(value as Uint8Array).toString("utf8")).toBe("ac");
  });

  it("cancels on Ctrl+C", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    fake.emit("partial");
    fake.emit("\x03");
    expect(await promise).toBe(null);
  });

  it("cancels on Ctrl+D", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    fake.emit("\x04");
    expect(await promise).toBe(null);
  });

  it("treats empty input as cancelled", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    fake.emit("\r");
    expect(await promise).toBe(null);
  });

  it.each<{ keys: string; chunks: string[]; expected: string }>([
    { keys: "an arrow key (CSI)", chunks: ["\x1b[D", "p", "w", "\r"], expected: "pw" },
    {
      keys: "a CSI with parameters (Ctrl+Left)",
      chunks: ["\x1b[1;5D", "pw", "\r"],
      expected: "pw",
    },
    { keys: "an application-mode arrow (SS3)", chunks: ["\x1bOD", "pw\r"], expected: "pw" },
    { keys: "F1 (SS3)", chunks: ["p", "\x1bOP", "w\r"], expected: "pw" },
    { keys: "a CSI split across two chunks", chunks: ["\x1b[", "Dpw\r"], expected: "pw" },
    {
      keys: "bracketed-paste markers around pasted text",
      chunks: ["\x1b[200~pw\x1b[201~", "\r"],
      expected: "pw",
    },
    { keys: "an Alt chord (ESC and one printable)", chunks: ["\x1bx", "pw\r"], expected: "pw" },
    {
      keys: "a second ESC that re-opens the sequence (ESC ESC [ D consumed whole)",
      chunks: ["\x1b\x1b[D", "pw\r"],
      expected: "pw",
    },
    {
      keys: "a bare ESC keypress, the next key kept",
      chunks: ["\x1b", "p", "w\r"],
      expected: "pw",
    },
    { keys: "a sequence cut short by Enter", chunks: ["pw\x1b[1;", "\r"], expected: "pw" },
    {
      keys: "an arrow before a backspace",
      chunks: ["pwx", "\x1b[D", "\x7f", "\r"],
      expected: "pw",
    },
    {
      keys: "C0 control bytes (Ctrl+A, Ctrl+Z, NUL)",
      chunks: ["\x01p\x1aw\x00", "\r"],
      expected: "pw",
    },
    { keys: "a tab", chunks: ["p\tw\r"], expected: "pw" },
    {
      keys: "multibyte text beside an arrow key",
      chunks: ["\u00fc", "\x1b[C", "\u20ac\ud83d\udd11\r"],
      expected: "\u00fc\u20ac\ud83d\udd11",
    },
  ])("drops $keys and keeps the typed text (Q5)", async ({ chunks, expected }) => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    for (const chunk of chunks) {
      fake.emit(chunk);
    }
    expect(await promise).toEqual(new TextEncoder().encode(expected));
  });

  it("treats input of arrow keys alone as empty and cancelled (Q5)", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    fake.emit("\x1b[A");
    fake.emit("\x1bOB");
    fake.emit("\r");
    expect(await promise).toBe(null);
  });

  it("cancels on Ctrl+D inside a pending sequence (Q5)", async () => {
    const fake = fakeTerminal();
    const promise = promptForValueMasked(fake.terminal, "> ", 1000);
    fake.emit("pw\x1b[1;");
    fake.emit("\x04");
    expect(await promise).toBe(null);
  });

  it("times out to null", async () => {
    const fake = fakeTerminal();
    const value = await promptForValueMasked(fake.terminal, "> ", 20);
    expect(value).toBe(null);
    expect(fake.setRawMode).toHaveBeenLastCalledWith(false);
  });
});

describe("collectValueFromTty", () => {
  it("returns null when no controlling terminal is available", async () => {
    const value = await collectValueFromTty({ subject: "k", operation: "create" }, () => null);
    expect(value).toBe(null);
  });

  it("prompts on the opened terminal and closes it afterwards", async () => {
    const fake = fakeTerminal();
    const promise = collectValueFromTty(
      { subject: "my-key", operation: "rotate" },
      () => fake.terminal,
    );

    fake.emit("new-value\r");

    const value = await promise;
    expect(Buffer.from(value as Uint8Array).toString("utf8")).toBe("new-value");
    expect(fake.written()).toContain('"my-key"');
    expect(fake.written()).toContain("Enter new value");
    expect(fake.close).toHaveBeenCalled();
  });

  it("closes the terminal even when the prompt is cancelled", async () => {
    const fake = fakeTerminal();
    const promise = collectValueFromTty({ subject: "k", operation: "create" }, () => fake.terminal);
    fake.emit("\x03");
    expect(await promise).toBe(null);
    expect(fake.close).toHaveBeenCalled();
  });
});
