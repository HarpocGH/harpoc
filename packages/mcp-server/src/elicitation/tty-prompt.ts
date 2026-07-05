import { closeSync, openSync } from "node:fs";
import { ReadStream, WriteStream } from "node:tty";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

export interface TtyPromptOptions {
  /** Secret name shown in the prompt (display only). */
  subject: string;
  operation: "create" | "rotate";
  timeoutMs?: number;
}

export interface MaskedPromptInput {
  setRawMode?(mode: boolean): unknown;
  on(event: "data", listener: (chunk: Buffer) => void): unknown;
  removeListener(event: "data", listener: (chunk: Buffer) => void): unknown;
}

export interface MaskedPromptOutput {
  write(text: string): unknown;
}

export interface ControllingTerminal {
  input: MaskedPromptInput;
  output: MaskedPromptOutput;
  close(): void;
}

/**
 * Open the process's controlling terminal directly — NOT stdin/stdout, which
 * over the stdio MCP transport carry the JSON-RPC stream. Returns null when no
 * controlling terminal is available (GUI-spawned hosts, redirected consoles),
 * which is exactly the thesis's condition for skipping this channel.
 */
export function openControllingTerminal(): ControllingTerminal | null {
  try {
    if (process.platform === "win32") {
      return openTerminalFds("\\\\.\\CONIN$", "\\\\.\\CONOUT$");
    }
    return openTerminalFds("/dev/tty", "/dev/tty");
  } catch {
    return null;
  }
}

function openTerminalFds(inputPath: string, outputPath: string): ControllingTerminal | null {
  const fdIn = openSync(inputPath, "r+");
  let fdOut: number;
  try {
    fdOut = openSync(outputPath, "w");
  } catch (err) {
    closeSync(fdIn);
    throw err;
  }

  let input: ReadStream;
  let output: WriteStream;
  try {
    input = new ReadStream(fdIn);
    output = new WriteStream(fdOut);
  } catch (err) {
    closeSync(fdIn);
    closeSync(fdOut);
    throw err;
  }

  if (!input.isTTY || !output.isTTY) {
    input.destroy();
    output.destroy();
    return null;
  }

  return {
    input,
    output,
    close: () => {
      input.destroy();
      output.destroy();
    },
  };
}

/**
 * Masked line read on an already-open terminal: raw mode, no echo, Enter
 * confirms, Backspace edits, Ctrl+C / Ctrl+D / empty input / timeout cancel
 * (→ null, the caller falls through to the deferred channel). Mirrors the CLI's
 * hidden prompt semantics.
 */
export function promptForValueMasked(
  terminal: ControllingTerminal,
  promptText: string,
  timeoutMs: number,
): Promise<Uint8Array | null> {
  return new Promise((resolve) => {
    const { input, output } = terminal;
    let value = "";
    let done = false;

    const finish = (result: Uint8Array | null): void => {
      if (done) return;
      done = true;
      clearTimeout(timeoutId);
      input.removeListener("data", onData);
      input.setRawMode?.(false);
      output.write("\n");
      resolve(result);
    };

    const timeoutId = setTimeout(() => finish(null), timeoutMs);

    const onData = (chunk: Buffer): void => {
      const text = chunk.toString("utf8");
      for (const char of text) {
        if (char === "\r" || char === "\n") {
          finish(value.length > 0 ? new Uint8Array(Buffer.from(value, "utf8")) : null);
          return;
        }
        if (char === "\x7f" || char === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        if (char === "\x03" || char === "\x04") {
          finish(null);
          return;
        }
        if (char < " ") {
          continue;
        }
        value += char;
      }
    };

    output.write(promptText);
    input.setRawMode?.(true);
    input.on("data", onData);
  });
}

/**
 * The thesis's middle value-collection channel (priority 2, CLI stdin prompt):
 * a masked prompt on the controlling terminal. Returns null when no terminal
 * is available, the user cancels, or the prompt times out — the caller then
 * falls back to deferred/pending creation.
 */
export async function collectValueFromTty(
  options: TtyPromptOptions,
  openTerminal: () => ControllingTerminal | null = openControllingTerminal,
): Promise<Uint8Array | null> {
  const terminal = openTerminal();
  if (!terminal) return null;

  const verb = options.operation === "create" ? "Enter value" : "Enter new value";
  const promptText = `\n[harpoc] ${verb} for secret "${options.subject}" (input hidden, Enter to confirm, Ctrl+C to skip): `;

  try {
    return await promptForValueMasked(
      terminal,
      promptText,
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    );
  } finally {
    terminal.close();
  }
}
