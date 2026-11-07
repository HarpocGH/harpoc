import type { Command } from "commander";
import {
  ErrorCode,
  MAX_DOCKER_TIMEOUT_MS,
  parseHandle,
  parseRestBaseUrl,
  type RestBaseUrlRefusal,
  VaultError,
} from "@harpoc/shared";
import type { RestClient } from "@harpoc/sdk";
import { handleError } from "./output.js";

/**
 * The CLI's REST mode (model B, design M3 § Consumers): `harpoc --url <base> --token-file <path>
 * <command>` sends the command to a running `harpoc server start --rest` through the SDK's
 * RestClient instead of opening a local vault. Both options are read before the command path
 * only: Commander binds a root option wherever it appears, and after the command path `--url` is
 * `secret use` / `allow` / `mcp-server`'s own flag and `--token-file` is `server start`'s.
 */
export interface RestMode {
  client: RestClient;
  /** The --url origin: the one part of the URL a message may name. */
  origin: string;
}

interface RestModeRootOptions {
  restUrl?: string;
  restTokenFile?: string;
  vaultDir?: string;
}

/** The root keys the two options land under — no command declares an option of that name. */
const REST_MODE_FLAGS: ReadonlyMap<string, "restUrl" | "restTokenFile"> = new Map([
  ["--url", "restUrl"],
  ["--token-file", "restTokenFile"],
]);

/** The help text the root prints after its option list (the two options are not Commander's). */
export const REST_MODE_HELP = `
REST mode (both before the command):
  --url <base>         send the command to a running harpoc REST server instead of opening a local
                       vault (https, or http on loopback)
  --token-file <path>  the bearer token for --url, read from this file`;

/**
 * Every command that runs over REST — the route its RestClient member reaches, or, for
 * `oauth providers`, `proxy env` and `ssh-agent status`, no vault at all. Any other command
 * refuses REST_MODE_UNSUPPORTED, so a command registered later never runs in-process under --url
 * by default.
 */
export const REST_MODE_COMMANDS: ReadonlySet<string> = new Set([
  "lock",
  "audit",
  "secret set",
  "secret get",
  "secret list",
  "secret rotate",
  "secret delete",
  "secret use",
  "secret allow",
  "secret mcp-server",
  "secret connection",
  "auth list",
  "auth revoke",
  "policy grant",
  "policy revoke",
  "policy list",
  "agent register",
  "agent list",
  "agent show",
  "agent update",
  "agent deactivate",
  "agent activate",
  "agent delete",
  "agent permissions",
  "oauth status",
  "oauth refresh",
  "oauth providers",
  "cert import",
  "cert status",
  "cert csr",
  "cert renew",
  "cert attach",
  "proxy env",
  "ssh-agent status",
]);

/**
 * The client deadline of `secret use`: the longest action budget the use schema admits (docker,
 * 30 min) plus a minute for the route's own work. Every other command keeps the SDK's 30 s.
 */
export const REST_MODE_USE_TIMEOUT_MS = MAX_DOCKER_TIMEOUT_MS + 60_000;

const restModes = new WeakMap<Command, RestMode>();

function rootOf(command: Command): Command {
  let root = command;
  while (root.parent) root = root.parent;
  return root;
}

/** The command path below the root, e.g. `secret list`. */
export function commandPath(command: Command): string {
  const names: string[] = [];
  for (let current = command; current.parent; current = current.parent) {
    names.unshift(current.name());
  }
  return names.join(" ");
}

/**
 * The root program's option parse calls this first: a leading run of `--url <base>` /
 * `--token-file <path>` (and their `=` forms) before the command path is taken off the argument
 * list and stored on the root; `--vault-dir` in that run stays where it is; the first other
 * token ends the run. With neither option in it the list comes back unchanged, so every model A
 * argument list reaches Commander as it is.
 */
export function extractRestModeOptions(program: Command, args: readonly string[]): string[] {
  const kept: string[] = [];
  let i = 0;
  while (i < args.length) {
    const arg = args[i] as string;
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const flag = eq === -1 ? arg : arg.slice(0, eq);
    const key = REST_MODE_FLAGS.get(flag);
    if (key !== undefined) {
      const value = eq === -1 ? args[i + 1] : arg.slice(eq + 1);
      if (value === undefined) {
        const placeholder = flag === "--url" ? "<base>" : "<path>";
        program.error(`error: option '${flag} ${placeholder}' argument missing`, {
          code: "commander.optionMissingArgument",
        });
      }
      program.setOptionValueWithSource(key, value, "cli");
      i += eq === -1 ? 2 : 1;
    } else if (flag === "--vault-dir") {
      const width = eq === -1 ? 2 : 1;
      kept.push(...args.slice(i, i + width));
      i += width;
    } else {
      break;
    }
  }
  return [...kept, ...args.slice(i)];
}

/** `<what> has no REST mode` — names the command and where it runs, nothing else. */
export function restModeUnsupported(what: string): VaultError {
  return VaultError.restModeUnsupported(what);
}

const REST_URL_REFUSALS: Readonly<Record<RestBaseUrlRefusal, string>> = {
  flag: "--url: a flag, not a URL",
  not_a_url: "--url: not a URL (give the server's base URL, e.g. http://127.0.0.1:3000)",
  scheme: "--url must use HTTPS (plain HTTP is allowed for loopback only)",
  plain_http_off_loopback: "--url must use HTTPS (plain HTTP is allowed for loopback only)",
  credentials: "--url: credentials in the URL are refused; the bearer is read from --token-file",
  query_or_fragment: "--url: a query or fragment is refused; give the server's base URL",
};

/**
 * `--url`: HTTPS anywhere, plain HTTP on loopback only (the bearer must not cross a network in
 * the clear — `oauthEndpointUrlSchema`'s rule), no credentials, no query or fragment; a path
 * prefix is kept. No refusal echoes the value: a URL can carry a password.
 */
export function parseRestUrl(value: string): URL {
  const parsed = parseRestBaseUrl(value);
  if (parsed.ok) return parsed.url;
  throw VaultError.invalidInput(REST_URL_REFUSALS[parsed.reason]);
}

async function resolveRestMode(
  options: RestModeRootOptions,
  actionCommand: Command,
): Promise<RestMode> {
  if (options.restUrl === undefined) {
    throw VaultError.invalidInput(
      "--token-file before the command is the bearer of --url and requires it (server start's own --token-file goes after the command)",
    );
  }
  const url = parseRestUrl(options.restUrl);
  if (options.vaultDir !== undefined) {
    throw VaultError.invalidInput(
      "--url and --vault-dir exclude each other: --url sends the command to a server, --vault-dir opens a local vault",
    );
  }
  const path = commandPath(actionCommand);
  if (!REST_MODE_COMMANDS.has(path)) throw restModeUnsupported(path);
  // RestClient strips an optional `secret://` and the route re-adds it, so a bare name would
  // pass over REST where the engine refuses it: every <handle> argument is parsed here.
  actionCommand.registeredArguments.forEach((argument, index) => {
    const value: unknown = actionCommand.processedArgs[index];
    if (argument.name() === "handle" && typeof value === "string") parseHandle(value);
  });
  if (actionCommand.optsWithGlobals<{ token?: string }>().token !== undefined) {
    throw VaultError.invalidInput(
      "--token is the bearer under --url; pass it through --token-file",
    );
  }
  if (process.env.HARPOC_TOKEN !== undefined) {
    throw VaultError.invalidInput(
      "HARPOC_TOKEN is set: under --url the bearer is read from --token-file only (unset HARPOC_TOKEN)",
    );
  }
  const tokenFile = options.restTokenFile;
  if (tokenFile === undefined) {
    throw VaultError.invalidInput("--url requires --token-file <path> (the bearer token)");
  }
  if (tokenFile.trim() === "") throw VaultError.invalidInput("--token-file: empty path");
  if (tokenFile.startsWith("-")) {
    throw VaultError.invalidInput(
      "--token-file: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  const { readLaunchTokenFile } = await import("@harpoc/mcp-server");
  const read = readLaunchTokenFile(tokenFile);
  if (!read.ok) {
    throw VaultError.invalidInput(read.message.replace(/^Error: /, "").trimEnd());
  }
  const { RestClient } = await import("@harpoc/sdk");
  const baseUrl = `${url.origin}${url.pathname}`;
  const client =
    path === "secret use"
      ? new RestClient({ baseUrl, token: read.token, timeoutMs: REST_MODE_USE_TIMEOUT_MS })
      : new RestClient({ baseUrl, token: read.token });
  return { client, origin: url.origin };
}

/**
 * The root program's second preAction hook (after refuseEmptyVaultDir): with neither REST-mode
 * option given it does nothing; otherwise every refusal — the option checks, a command without a
 * REST mode, the token channel — happens here, before any prompt or vault, through the --json
 * envelope where the command declares --json; then the RestClient is built for restModeOf.
 */
export async function prepareRestMode(program: Command, actionCommand: Command): Promise<void> {
  const options = program.opts<RestModeRootOptions>();
  if (options.restUrl === undefined && options.restTokenFile === undefined) return;
  try {
    restModes.set(program, await resolveRestMode(options, actionCommand));
  } catch (err) {
    handleError(err, actionCommand.optsWithGlobals<{ json?: boolean }>().json === true);
  }
}

/** The REST mode the root hook prepared for this parse, or undefined on the in-process path. */
export function restModeOf(command: Command): RestMode | undefined {
  return restModes.get(rootOf(command));
}

/**
 * A command's REST branch, run inside the command's own `try` so its `catch` renders a refusal
 * as the in-process path does; an unreachable server becomes CONNECTION_REFUSED naming the
 * origin instead of fetch's bare "fetch failed".
 */
export async function runRestMode(
  mode: RestMode,
  body: (client: RestClient) => Promise<void>,
): Promise<void> {
  try {
    await body(mode.client);
  } catch (err) {
    if (err instanceof TypeError && err.message === "fetch failed") {
      throw new VaultError(
        ErrorCode.CONNECTION_REFUSED,
        `Cannot reach the harpoc server at ${mode.origin}`,
      );
    }
    throw err;
  }
}
