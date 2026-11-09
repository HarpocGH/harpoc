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
 * The five variables a client's TLS stack reads its trust from (B8, RD-B8-14), each pointed at
 * the consumer's `ca.pem` — the Harpoc CA's root, written there by the daemon's start.
 */
export const CLIENT_CA_VARIABLES = [
  "SSL_CERT_FILE",
  "NODE_EXTRA_CA_CERTS",
  "REQUESTS_CA_BUNDLE",
  "CURL_CA_BUNDLE",
  "GIT_SSL_CAINFO",
] as const;

const NO_RUNTIME_DIR_CA =
  "# no --runtime-dir: the HARPOC_PROXY_CA_FILE line and the five client CA variables are omitted (harpoc proxy ca export writes the root)";

/** win32 (DB-14): the proxy is the loopback TCP listener alone — no proxy.sock to name. */
export const NO_SOCKET_ON_WINDOWS =
  "# Windows: the proxy serves no socket — the HARPOC_PROXY_SOCKET line is omitted (the TCP listener with the token file's token)";

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
  options: { port: number; runtimeDir?: string; platform?: NodeJS.Platform },
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
    if ((options.platform ?? process.platform) !== "win32") {
      env.HARPOC_PROXY_SOCKET = join(dir, "proxy.sock");
    }
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
  if (options.runtimeDir !== undefined) {
    const caFile = join(consumerDir(options.runtimeDir, consumer), "ca.pem");
    env.HARPOC_PROXY_CA_FILE = caFile;
    for (const variable of CLIENT_CA_VARIABLES) env[variable] = caFile;
  }
  return env;
}

/**
 * win32 (R-X9): curl on Schannel and git on its default schannel backend take no trust from the
 * five variables — two comment lines name what they take instead (no `GIT_CONFIG_*` variable:
 * it would collide with the consumer's own `GIT_CONFIG_COUNT` list of the token recipe).
 */
export function windowsTrustComments(caFile: string): string[] {
  return [
    `# Windows: curl on Schannel ignores CURL_CA_BUNDLE and SSL_CERT_FILE — pass --cacert ${caFile} --ssl-revoke-best-effort (or both as .curlrc lines)`,
    "# Windows: git's schannel backend reads GIT_SSL_CAINFO only with http.schannelUseSSLCAInfo=true, and checks revocation strictly unless http.sslBackend=schannel is set explicitly (git config --global http.sslBackend schannel and git config --global http.schannelUseSSLCAInfo true, or http.sslBackend=openssl)",
  ];
}

/**
 * The `HTTPS_PROXY` form, as a comment (R-C8, lane C's recommendation): the variable carries
 * the consumer's token as the proxy URL's password, and `proxy env` prints no token — the
 * client's launcher reads the token file.
 */
export function httpsProxyComment(port: number, hasRuntimeDir: boolean): string {
  const token = hasRuntimeDir ? "<the token in HARPOC_PROXY_TOKEN_FILE>" : "<the consumer's token>";
  return `# HTTPS_PROXY=http://harpoc:${token}@127.0.0.1:${String(port)} — the token is not printed: set the variable from the token file when the client starts`;
}

export function registerProxyEnvCommand(proxy: Command): void {
  proxy
    .command("env <consumer> <handle...>")
    .description(
      "Print a consumer's environment block for the egress proxy: its address and base-URL form, the consumer's token-file and socket paths, one placeholder per handle, the Harpoc CA's root file for the clients' trust and the HTTPS_PROXY form — no value and no token; opens no vault",
    )
    .option(
      "--runtime-dir <path>",
      "The daemon's runtime directory, holding <consumer>/token.jwt, <consumer>/proxy.sock and <consumer>/ca.pem (without it those lines are omitted)",
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
        const runtimeDir = resolveRuntimeDir(options.runtimeDir, undefined);
        const env = proxyEnvironment(consumer, handles, { port, runtimeDir: runtimeDir?.path });
        if (options.json) {
          printJson(env);
          return;
        }
        const lines = Object.entries(env).map(([key, value]) => `${key}=${value}`);
        if (runtimeDir === undefined) lines.splice(2, 0, NO_RUNTIME_DIR);
        else if (process.platform === "win32") lines.splice(3, 0, NO_SOCKET_ON_WINDOWS);
        if (runtimeDir === undefined) lines.push(NO_RUNTIME_DIR_CA);
        if (process.platform === "win32") {
          lines.push(...windowsTrustComments(env.HARPOC_PROXY_CA_FILE ?? "<the exported root>"));
        }
        lines.push(httpsProxyComment(port, runtimeDir !== undefined));
        for (const line of lines) console.log(line);
      } catch (err) {
        handleError(err, options.json);
      }
    });
}
