import { join } from "node:path";
import type { Command } from "commander";
import { parseHandle, VaultError } from "@harpoc/shared";
import { handleError, printJson } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { DEFAULT_PROXY_PORT, MAX_PORT, MIN_PORT } from "../../utils/option-bounds.js";
import { assertConsumerName, consumerDir, resolveRuntimeDir } from "../../utils/runtime-dir.js";

interface ProxyEnvOptions {
  runtimeDir?: string;
  proxyPort: string;
  json?: boolean;
}

const NO_RUNTIME_DIR =
  "# no --runtime-dir: the HARPOC_PROXY_TOKEN_FILE and HARPOC_PROXY_SOCKET lines are omitted";

/**
 * The placeholder a consumer's client sends where the credential would go: the handle's own
 * path, `harpoc:<name>` for the project-less `secret://<name>` and `harpoc://<project>/<name>`
 * for `secret://<project>/<name>` (RC-8: no default-project resolution).
 */
export function placeholderFor(handle: string): string {
  const { project, name } = parseHandle(handle);
  return project === undefined ? `harpoc:${name}` : `harpoc://${project}/${name}`;
}

/** The variable a placeholder is printed under: `HARPOC_PLACEHOLDER_[<PROJECT>_]<NAME>`, `-` as `_`. */
export function placeholderVariable(handle: string): string {
  const { project, name } = parseHandle(handle);
  const stem = project === undefined ? name : `${project}_${name}`;
  return `HARPOC_PLACEHOLDER_${stem.toUpperCase().replace(/-/g, "_")}`;
}

/**
 * A consumer's environment block for the egress proxy, in print order: the proxy's address, its
 * base-URL form, the consumer's token-file and socket paths when a runtime directory is named,
 * and one placeholder per handle. Derived from its arguments alone — no vault is opened, and no
 * value or token can appear in it.
 */
export function proxyEnvironment(
  consumer: string,
  handles: string[],
  options: { port: number; runtimeDir?: string },
): Record<string, string> {
  assertConsumerName(consumer);
  const origin = `http://127.0.0.1:${String(options.port)}`;
  const env: Record<string, string> = {
    HARPOC_PROXY_URL: origin,
    HARPOC_PROXY_BASE: `${origin}/`,
  };
  if (options.runtimeDir !== undefined) {
    const dir = consumerDir(options.runtimeDir, consumer);
    env.HARPOC_PROXY_TOKEN_FILE = join(dir, "token.jwt");
    env.HARPOC_PROXY_SOCKET = join(dir, "proxy.sock");
  }
  for (const handle of handles) {
    const variable = placeholderVariable(handle);
    const placeholder = placeholderFor(handle);
    const taken = env[variable];
    if (taken !== undefined && taken !== placeholder) {
      throw VaultError.invalidInput(
        `${variable} would name both ${taken} and ${placeholder}; print the two handles in separate calls`,
      );
    }
    env[variable] = placeholder;
  }
  return env;
}

export function registerProxyEnvCommand(proxy: Command): void {
  proxy
    .command("env <consumer> <handle...>")
    .description(
      "Print a consumer's environment block for the egress proxy: its address and base-URL form, the consumer's token-file and socket paths, and one placeholder per handle — no value and no token; opens no vault",
    )
    .option(
      "--runtime-dir <path>",
      "The daemon's runtime directory, holding <consumer>/token.jwt and <consumer>/proxy.sock (without it those two lines are omitted)",
    )
    .option(
      "--proxy-port <port>",
      "The daemon's --proxy-port (loopback)",
      String(DEFAULT_PROXY_PORT),
    )
    .option("--json", "Output as JSON")
    .action((consumer: string, handles: string[], options: ProxyEnvOptions) => {
      try {
        const port = parseIntOption(options.proxyPort, "proxy port", MIN_PORT, MAX_PORT);
        const runtimeDir = resolveRuntimeDir(options.runtimeDir, {});
        const env = proxyEnvironment(consumer, handles, { port, runtimeDir: runtimeDir?.path });
        if (options.json) {
          printJson(env);
          return;
        }
        const lines = Object.entries(env).map(([key, value]) => `${key}=${value}`);
        if (runtimeDir === undefined) lines.splice(2, 0, NO_RUNTIME_DIR);
        for (const line of lines) console.log(line);
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
