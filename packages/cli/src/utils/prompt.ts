import { createInterface } from "node:readline";
import type { Readable } from "node:stream";

type HiddenPromptInput = Readable & {
  isRaw?: boolean;
  setRawMode?: (mode: boolean) => unknown;
};

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
 * Prompt for confirmation (y/N).
 */
export async function promptConfirm(message: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(`${message} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
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

    const rl = createInterface({ input, output });

    output.write(message);
    const wasRaw = input.isRaw;
    if (typeof input.setRawMode === "function") {
      input.setRawMode(true);
    }

    let value = "";

    const finish = (remainder: string): void => {
      if (typeof input.setRawMode === "function") {
        input.setRawMode(wasRaw ?? false);
      }
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.removeListener("error", onError);
      rl.close();
      // Pausing lets the process exit with stdin still open and keeps any
      // pushed-back input buffered until the next prompt resumes the stream.
      input.pause();
      if (remainder.length > 0) {
        input.unshift(Buffer.from(remainder, "utf8"));
      }
      output.write("\n");
    };

    const onData = (data: Buffer): void => {
      const chunk = data.toString("utf8");
      for (let i = 0; i < chunk.length; i++) {
        const char = chunk.charAt(i);
        // Handle enter
        if (char === "\n" || char === "\r") {
          let rest = chunk.slice(i + 1);
          if (char === "\r" && rest.startsWith("\n")) {
            rest = rest.slice(1);
          }
          finish(rest);
          resolve(value);
          return;
        }
        // Handle backspace
        if (char === "\x7f" || char === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        // Handle Ctrl+C
        if (char === "\x03") {
          finish("");
          reject(new Error("User cancelled"));
          return;
        }
        value += char;
      }
    };

    const onEnd = (): void => {
      finish("");
      resolve(value);
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
