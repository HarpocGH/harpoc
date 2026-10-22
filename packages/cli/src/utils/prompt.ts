import { StringDecoder } from "node:string_decoder";
import type { Readable } from "node:stream";

type HiddenPromptInput = Readable & {
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
};

type ConfirmPromptInput = Readable & {
  isTTY?: boolean;
};

type EscapeState = "ground" | "escape" | "csi" | "ss3";

function nextEscapeState(state: EscapeState, char: string): EscapeState | null {
  const code = char.charCodeAt(0);
  if (state === "escape") {
    if (char === "[") return "csi";
    if (char === "O") return "ss3";
    if (code >= 0x20 && code <= 0x7e) return "ground";
  } else if (state === "csi") {
    if (code >= 0x20 && code <= 0x3f) return "csi";
    if (code >= 0x40 && code <= 0x7e) return "ground";
  } else if (state === "ss3") {
    if (code >= 0x40 && code <= 0x7e) return "ground";
  }
  return char === "\x1b" ? "escape" : null;
}

function dropLastCodePoint(value: string): string {
  const last = value.charCodeAt(value.length - 1);
  const previous = value.charCodeAt(value.length - 2);
  const pair = last >= 0xdc00 && last <= 0xdfff && previous >= 0xd800 && previous <= 0xdbff;
  return value.slice(0, pair ? -2 : -1);
}

/**
 * The bytes of `data` after the Enter at `chunk[enterIndex]` (and its `\n` when
 * the Enter is `\r`). CR and LF are ASCII and never held by the decoder, so the
 * k-th CR/LF character of `chunk` is the k-th CR/LF byte of `data`; a partial
 * character after the Enter is pushed back as raw bytes, not as decoded text.
 */
function rawRemainderAfterEnter(data: Buffer, chunk: string, enterIndex: number): Buffer {
  let k = 0;
  for (let i = 0; i <= enterIndex; i++) {
    const code = chunk.charCodeAt(i);
    if (code === 0x0a || code === 0x0d) k++;
  }
  for (let j = 0; j < data.length; j++) {
    const byte = data[j];
    if (byte !== 0x0a && byte !== 0x0d) continue;
    k--;
    if (k > 0) continue;
    let start = j + 1;
    if (byte === 0x0d && data[start] === 0x0a) start++;
    return data.subarray(start);
  }
  return data.subarray(data.length);
}

/**
 * Prompt for a password with hidden input.
 */
export async function promptPassword(message = "Password: "): Promise<string> {
  return promptHidden(message);
}

/**
 * Prompt for a secret value with hidden input.
 */
export async function promptSecret(message = "Secret value: "): Promise<string> {
  return promptHidden(message);
}

/**
 * Prompt for confirmation (y/N). Reads one line with the same chunk-independent
 * scanning as promptHidden, minus raw mode — confirmation input is not secret,
 * so a TTY's canonical line editing and native echo are fine, and Ctrl+C stays
 * an ordinary SIGINT. EOF acts as the line terminator, so a closed stdin
 * resolves (an empty answer is the default No) instead of leaving the promise
 * dangling and the process exiting 0 without running the guarded command.
 */
export function promptConfirm(
  message: string,
  input: ConfirmPromptInput = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const toAnswer = (value: string): boolean => value.trim().toLowerCase() === "y";

    if (input.readableEnded) {
      output.write(`${message} [y/N] \n`);
      resolve(false);
      return;
    }

    output.write(`${message} [y/N] `);

    let value = "";

    const finish = (remainder: string): void => {
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("error", onError);
      input.pause();
      if (remainder.length > 0) {
        input.unshift(Buffer.from(remainder, "utf8"));
      }
      // A TTY echoes the typed Enter itself; piped input echoes nothing, so
      // terminate the prompt line before the command's next output.
      if (!input.isTTY) {
        output.write("\n");
      }
    };

    const onData = (data: Buffer): void => {
      const chunk = data.toString("utf8");
      for (let i = 0; i < chunk.length; i++) {
        const char = chunk.charAt(i);
        if (char === "\n" || char === "\r") {
          let rest = chunk.slice(i + 1);
          if (char === "\r" && rest.startsWith("\n")) {
            rest = rest.slice(1);
          }
          finish(rest);
          resolve(toAnswer(value));
          return;
        }
        value += char;
      }
    };

    const onEnd = (): void => {
      finish("");
      resolve(toAnswer(value));
    };

    const onError = (err: Error): void => {
      finish("");
      reject(err);
    };

    input.on("data", onData);
    input.once("end", onEnd);
    input.once("error", onError);
    input.resume();
  });
}

/**
 * Read one line with hidden input. On a TTY, raw mode delivers one keystroke
 * per data chunk; on a pipe, a single chunk can carry the whole line — or
 * several. Input is therefore scanned per character, the first line
 * terminator settles the prompt, and anything after it is pushed back onto
 * the stream for the next prompt. EOF terminates the line (callers treat an
 * empty value as an error), so a closed stdin can no longer leave the promise
 * dangling and the process exiting 0 without having run the command.
 *
 * In raw mode a key that is not text is dropped whole: an ESC-led CSI
 * (`ESC [`) or SS3 (`ESC O`) sequence — an arrow, a function key, a bracketed
 * paste marker — even when split across chunks after its introducer, an Alt
 * chord (ESC and one printable), a bare ESC, and every other C0 control byte
 * — Enter, Backspace and Ctrl+C still act. Piped input keeps its bytes.
 *
 * No readline interface may be attached here: with a TTY output, readline
 * runs in terminal mode and echoes every keypress, printing the secret.
 */
export function promptHidden(
  message: string,
  input: HiddenPromptInput = process.stdin,
  output: NodeJS.WritableStream = process.stderr,
): Promise<string> {
  return new Promise((resolve, reject) => {
    if (input.readableEnded) {
      output.write(`${message}\n`);
      resolve("");
      return;
    }

    output.write(message);
    const wasRaw = input.isRaw;
    if (typeof input.setRawMode === "function") {
      input.setRawMode(true);
    }

    const scanKeys = typeof input.setRawMode === "function";
    let escape: EscapeState = "ground";
    let value = "";
    const decoder = new StringDecoder("utf8");

    const finish = (remainder: Buffer): void => {
      if (typeof input.setRawMode === "function") {
        input.setRawMode(wasRaw ?? false);
      }
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("error", onError);
      // Pausing lets the process exit with stdin still open and keeps any
      // pushed-back input buffered until the next prompt resumes the stream.
      input.pause();
      if (remainder.length > 0) {
        input.unshift(remainder);
      }
      output.write("\n");
    };

    const onData = (data: Buffer): void => {
      const chunk = decoder.write(data);
      for (let i = 0; i < chunk.length; i++) {
        const char = chunk.charAt(i);
        if (scanKeys) {
          const next = nextEscapeState(escape, char);
          escape = next ?? "ground";
          if (next !== null) continue;
        }
        // Handle enter
        if (char === "\n" || char === "\r") {
          finish(rawRemainderAfterEnter(data, chunk, i));
          resolve(value);
          return;
        }
        // Handle backspace
        if (char === "\x7f" || char === "\b") {
          value = dropLastCodePoint(value);
          continue;
        }
        // Handle Ctrl+C
        if (char === "\x03") {
          finish(Buffer.alloc(0));
          reject(new Error("User cancelled"));
          return;
        }
        if (scanKeys && char < " ") continue;
        value += char;
      }
      if (escape === "escape") escape = "ground";
    };

    const onEnd = (): void => {
      finish(Buffer.alloc(0));
      resolve(value);
    };

    const onError = (err: Error): void => {
      finish(Buffer.alloc(0));
      reject(err);
    };

    input.on("data", onData);
    input.once("end", onEnd);
    input.once("error", onError);
    input.resume();
  });
}
