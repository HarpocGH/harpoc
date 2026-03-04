import { createInterface } from "node:readline";

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

function promptHidden(message: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });

    // Disable echo by writing ANSI escape to hide input
    process.stderr.write(message);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (typeof stdin.setRawMode === "function") {
      stdin.setRawMode(true);
    }

    let input = "";
    const onData = (data: Buffer): void => {
      const char = data.toString("utf8");
      // Handle enter
      if (char === "\n" || char === "\r" || char === "\r\n") {
        if (typeof stdin.setRawMode === "function") {
          stdin.setRawMode(wasRaw ?? false);
        }
        stdin.removeListener("data", onData);
        rl.close();
        process.stderr.write("\n");
        resolve(input);
        return;
      }
      // Handle backspace
      if (char === "\x7f" || char === "\b") {
        input = input.slice(0, -1);
        return;
      }
      // Handle Ctrl+C
      if (char === "\x03") {
        if (typeof stdin.setRawMode === "function") {
          stdin.setRawMode(wasRaw ?? false);
        }
        stdin.removeListener("data", onData);
        rl.close();
        reject(new Error("User cancelled"));
        return;
      }
      input += char;
    };

    stdin.on("data", onData);
  });
}
