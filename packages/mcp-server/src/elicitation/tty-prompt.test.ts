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
