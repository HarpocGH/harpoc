import { readFileSync, statSync, type Stats } from "node:fs";
import type { Command } from "commander";
import type {
  CallerContext,
  InjectionPolicy,
  RenderApproval,
  RenderEntry,
  RenderPolicy,
} from "@harpoc/shared";
import {
  AuditEventType,
  injectionPolicyInputSchema,
  isValidName,
  MAX_RENDER_TEMPLATE_BYTES,
  parseHandle,
  renderApprovalSchema,
  renderEntryInputSchema,
  renderSchemaIssues,
  VaultError,
} from "@harpoc/shared";
import { renderEntryDetail, renderEntryDigest } from "@harpoc/core";
import type { VaultEngine } from "@harpoc/core";
import type { RestClient } from "@harpoc/sdk";
import { loadUnlockedEngine, resolveSecretId, resolveVaultDir } from "../../utils/vault-loader.js";
import { handleError, printJson, printSuccess } from "../../utils/output.js";
import { parseIntOption } from "../../utils/options.js";
import { MAX_PORT, MIN_PORT } from "../../utils/option-bounds.js";
import { promptConfirm } from "../../utils/prompt.js";
import { resolveTokenCallerForHandle, TOKEN_OPTION_DESCRIPTION } from "../../utils/token-caller.js";
import { restModeOf, restModeUnsupported, runRestMode } from "../../utils/rest-mode.js";
import { escapeForTerminal } from "../../utils/terminal-escape.js";

interface RenderOptions {
  token?: string;
  json?: boolean;
}

interface RenderSetOptions extends RenderOptions {
  entry: string;
  host?: string;
  user?: string;
  port?: string;
  path?: string;
  hostKey: string[];
  templateFile: string;
}

interface RenderRemoveOptions extends RenderOptions {
  entry: string;
}

interface RenderApprovalOptions extends RenderOptions {
  key?: string;
  keyId?: string;
  entry: string;
  digest?: string;
  confirm?: boolean;
}

interface RenderListOptions extends RenderOptions {
  template?: string;
  key?: string;
}

type ListedApproval = RenderApproval & { stale?: true };

interface PolicyAccess {
  read(handle: string): Promise<InjectionPolicy>;
  write(handle: string, policy: InjectionPolicy): Promise<void>;
}

const WRITE_OPTIONS = { acknowledge_interpreters: false };
const DIGEST_CHANGED = "the entry's digest changed; approvals of the old digest no longer hold";

function collect(value: string, acc: string[]): string[] {
  acc.push(value);
  return acc;
}

function tokenOf(options: RenderOptions): string | undefined {
  return options.token ?? process.env.HARPOC_TOKEN;
}

function engineAccess(engine: VaultEngine, caller: CallerContext | undefined): PolicyAccess {
  return {
    read: (handle) => engine.getInjectionPolicy(handle, caller),
    write: (handle, policy) => engine.setInjectionPolicy(handle, policy, WRITE_OPTIONS, caller),
  };
}

function restAccess(client: RestClient): PolicyAccess {
  return {
    read: (handle) => client.getInjectionPolicy(handle),
    write: (handle, policy) => client.setInjectionPolicy(handle, policy, WRITE_OPTIONS),
  };
}

function readTemplateFile(path: string): string {
  if (path.trim() === "") throw VaultError.invalidInput("--template-file: empty path");
  if (path.startsWith("-")) {
    throw VaultError.invalidInput(
      "--template-file: a flag, not a path (give a path that starts with a dash as ./-name)",
    );
  }
  let stat: Stats | undefined;
  try {
    stat = statSync(path);
  } catch {
    stat = undefined;
  }
  if (stat === undefined || !stat.isFile()) {
    throw VaultError.invalidInput(`Cannot read template file: ${path}`);
  }
  if (stat.size > MAX_RENDER_TEMPLATE_BYTES) {
    throw VaultError.invalidInput(
      `The template file exceeds the ${String(MAX_RENDER_TEMPLATE_BYTES)}-byte limit: ${path}`,
    );
  }
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch {
    throw VaultError.invalidInput(`Cannot read template file: ${path}`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw VaultError.invalidInput(`The template file is not UTF-8 text: ${path}`);
  }
}

function judgeRenderEntryOptions(options: RenderSetOptions): RenderEntry {
  const template = readTemplateFile(options.templateFile);
  const port =
    options.port === undefined
      ? undefined
      : parseIntOption(options.port, "port", MIN_PORT, MAX_PORT);
  const parsed = renderEntryInputSchema.safeParse({
    name: options.entry,
    host: options.host,
    port,
    user: options.user,
    path: options.path,
    host_keys: options.hostKey,
    template,
  });
  if (!parsed.success) throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
  return parsed.data;
}

function judgeApprovalOptions(options: RenderApprovalOptions, command: "approve" | "revoke"): void {
  if (options.key === undefined && options.keyId === undefined) {
    throw VaultError.invalidInput(`secret render ${command} needs --key <handle> or --key-id <id>`);
  }
  if (options.key !== undefined && options.keyId !== undefined) {
    throw VaultError.invalidInput("--key and --key-id exclude each other");
  }
  if (command === "approve" && options.keyId !== undefined && options.digest === undefined) {
    throw VaultError.invalidInput(
      "--key-id needs --digest: the key's policy is read through --key alone",
    );
  }
  if (options.key !== undefined) parseHandle(options.key);
  const parsed = renderApprovalSchema
    .partial()
    .safeParse({ key: options.keyId, entry: options.entry, digest: options.digest });
  if (!parsed.success) throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
}

function judgeRemoveOptions(options: RenderRemoveOptions): void {
  const parsed = renderApprovalSchema.pick({ entry: true }).safeParse({ entry: options.entry });
  if (!parsed.success) throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
}

function judgeListOptions(options: RenderListOptions): void {
  if (options.key !== undefined) {
    if (options.template !== undefined) {
      throw VaultError.invalidInput("--key and --template exclude each other");
    }
    parseHandle(options.key);
  }
  if (options.template !== undefined && !isValidName(options.template)) {
    throw VaultError.invalidInput("--template: Invalid name format");
  }
}

function withRender(current: InjectionPolicy, render: RenderPolicy): InjectionPolicy {
  const parsed = injectionPolicyInputSchema.safeParse({ ...current, render });
  if (!parsed.success) throw VaultError.schemaValidation(renderSchemaIssues(parsed.error));
  return parsed.data;
}

function placeEntry(
  render: RenderPolicy,
  entry: RenderEntry,
): { render: RenderPolicy; replaced: RenderEntry | undefined } {
  const index = render.entries.findIndex((stored) => stored.name === entry.name);
  const entries =
    index < 0
      ? [...render.entries, entry]
      : render.entries.map((stored, i) => (i === index ? entry : stored));
  return { render: { ...render, entries }, replaced: render.entries[index] };
}

function placeApproval(render: RenderPolicy, approval: RenderApproval): RenderPolicy {
  const index = render.approvals.findIndex(
    (stored) => stored.key === approval.key && stored.entry === approval.entry,
  );
  const approvals =
    index < 0
      ? [...render.approvals, approval]
      : render.approvals.map((stored, i) => (i === index ? approval : stored));
  return { ...render, approvals };
}

function reportEntrySet(
  handle: string,
  entry: RenderEntry,
  replaced: RenderEntry | undefined,
  keyId: string | undefined,
): void {
  const digest = renderEntryDigest(entry);
  console.log(digest);
  if (keyId !== undefined) console.error(`key: ${keyId}`);
  if (replaced !== undefined && renderEntryDigest(replaced) !== digest) {
    console.error(DIGEST_CHANGED);
  }
  printSuccess(`Render entry set (${handle})`);
}

async function removeEntry(access: PolicyAccess, handle: string, name: string): Promise<void> {
  const current = await access.read(handle);
  const entries = current.render.entries.filter((entry) => entry.name !== name);
  if (entries.length === current.render.entries.length) {
    throw VaultError.invalidInput(
      "--entry: the secret's policy holds no render entry of that name",
    );
  }
  await access.write(handle, withRender(current, { ...current.render, entries }));
  printSuccess(`Render entry removed (${handle})`);
}

function showField(label: string, value: string): void {
  console.error(`${label}: ${escapeForTerminal(value)}`);
}

function showApproval(approval: RenderApproval): RenderApproval {
  showField("key", approval.key);
  showField("entry", approval.entry);
  showField("digest", approval.digest);
  return approval;
}

function showEntry(keyId: string, entry: RenderEntry): RenderApproval {
  const detail = renderEntryDetail(entry);
  showField("key", keyId);
  showField("entry", detail.name);
  showField("host", detail.host);
  showField("port", String(detail.port));
  showField("user", detail.user);
  showField("path", detail.path);
  showField("host_key_fingerprints", detail.host_key_fingerprints.join(", "));
  showField("slots", detail.slots.join(", "));
  showField("digest", detail.digest);
  console.error("template:");
  console.error(escapeForTerminal(entry.template));
  return { key: keyId, entry: detail.name, digest: detail.digest };
}

/**
 * A delivering key named by its handle: its policy read under the caller's grant, and only then
 * its id, so that a caller who holds nothing on the key learns neither the id nor whether the key
 * exists.
 */
async function readKey(
  engine: VaultEngine,
  handle: string,
  caller: CallerContext | undefined,
  eventType?: AuditEventType,
): Promise<{ id: string; policy: InjectionPolicy }> {
  const policy = await engine.getInjectionPolicy(handle, caller);
  const id =
    eventType === undefined
      ? await resolveSecretId(engine, handle, caller)
      : await resolveSecretId(engine, handle, caller, eventType);
  return { id, policy };
}

async function approvalInProcess(
  engine: VaultEngine,
  options: RenderApprovalOptions,
  token: string | undefined,
): Promise<RenderApproval> {
  if (options.key === undefined) {
    return showApproval({
      key: options.keyId as string,
      entry: options.entry,
      digest: options.digest as string,
    });
  }
  const scoped = resolveTokenCallerForHandle(
    engine,
    "read",
    options.key,
    token,
    "secret render approve",
  );
  const key = await readKey(engine, options.key, scoped?.caller, AuditEventType.POLICY_GRANT);
  if (options.digest !== undefined) {
    return showApproval({ key: key.id, entry: options.entry, digest: options.digest });
  }
  const entry = key.policy.render.entries.find((stored) => stored.name === options.entry);
  if (entry === undefined) {
    throw VaultError.invalidInput("--entry: the key's policy holds no render entry of that name");
  }
  return showEntry(key.id, entry);
}

async function storeApproval(
  access: PolicyAccess,
  handle: string,
  approval: RenderApproval,
  confirm: boolean | undefined,
): Promise<void> {
  if (!confirm && !(await promptConfirm(`Approve this render entry for ${handle}?`))) {
    console.error("Aborted.");
    return;
  }
  const current = await access.read(handle);
  await access.write(handle, withRender(current, placeApproval(current.render, approval)));
  printSuccess(`Render approval stored (${handle})`);
}

async function removeApproval(
  access: PolicyAccess,
  handle: string,
  keyId: string,
  entry: string,
): Promise<void> {
  const current = await access.read(handle);
  const approvals = current.render.approvals.filter(
    (approval) => approval.key !== keyId || approval.entry !== entry,
  );
  if (approvals.length === current.render.approvals.length) {
    throw VaultError.invalidInput("the secret's policy holds no approval of that key's entry");
  }
  await access.write(handle, withRender(current, { ...current.render, approvals }));
  printSuccess(`Render approval removed (${handle})`);
}

function writeTemplate(policy: InjectionPolicy, name: string): void {
  const entry = policy.render.entries.find((stored) => stored.name === name);
  if (entry === undefined) {
    throw VaultError.invalidInput(
      "--template: the secret's policy holds no render entry of that name",
    );
  }
  process.stdout.write(entry.template);
}

function markStale(
  approvals: readonly RenderApproval[],
  keyId: string,
  entries: readonly RenderEntry[],
): ListedApproval[] {
  const digests = new Map(entries.map((entry) => [entry.name, renderEntryDigest(entry)]));
  return approvals.map((approval) =>
    approval.key === keyId && digests.get(approval.entry) !== approval.digest
      ? { ...approval, stale: true }
      : approval,
  );
}

async function runRenderCommand<T>(
  cmd: Command,
  json: boolean | undefined,
  judge: () => T,
  overRest: (client: RestClient, judged: T) => Promise<void>,
  inProcess: (engine: VaultEngine, judged: T) => Promise<void>,
): Promise<void> {
  const vaultDir = resolveVaultDir(cmd.optsWithGlobals<{ vaultDir?: string }>().vaultDir);
  try {
    const judged = judge();
    const rest = restModeOf(cmd);
    if (rest) {
      await runRestMode(rest, (client) => overRest(client, judged));
      return;
    }
    const engine = await loadUnlockedEngine(vaultDir);
    try {
      await inProcess(engine, judged);
    } finally {
      await engine.destroy();
    }
  } catch (err) {
    handleError(err, json);
  }
}

export function registerSecretRenderCommand(secret: Command): void {
  const render = secret
    .command("render")
    .description(
      "Render entries of a delivering key, and the approvals on the secrets its templates read (sftp render)",
    );

  render
    .command("set <handle>")
    .description(
      "Add or replace a render entry of a delivering key and print its digest; a key with an entry serves the sftp render alone",
    )
    .requiredOption("--entry <name>", "Render entry name")
    .option(
      "--host <host>",
      "The host the file is written on: a name, or an IPv4 address in plain dotted form; no loopback",
    )
    .option("--user <user>", "The login account the file is written as")
    .option("--port <port>", "The host's port (default 22)")
    .option("--path <path>", "The remote file's absolute path")
    .option(
      "--host-key <line>",
      "A public key of the host as '<type> <base64>', read at its console (repeatable, 1 to 8)",
      collect,
      [],
    )
    .requiredOption(
      "--template-file <file>",
      "The file's template: text with slots {{secret://name}} or {{secret://project/name}}, at most 16384 bytes",
    )
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action((handle: string, options: RenderSetOptions, cmd: Command) =>
      runRenderCommand(
        cmd,
        options.json,
        () => judgeRenderEntryOptions(options),
        async (client, entry) => {
          const access = restAccess(client);
          const current = await access.read(handle);
          const { render: merged, replaced } = placeEntry(current.render, entry);
          await access.write(handle, withRender(current, merged));
          reportEntrySet(handle, entry, replaced, undefined);
        },
        async (engine, entry) => {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            tokenOf(options),
            "secret render set",
          );
          const access = engineAccess(engine, resolved?.caller);
          const current = await access.read(handle);
          const keyId = await resolveSecretId(
            engine,
            handle,
            resolved?.caller,
            AuditEventType.POLICY_GRANT,
          );
          const { render: merged, replaced } = placeEntry(current.render, entry);
          await access.write(handle, withRender(current, merged));
          reportEntrySet(handle, entry, replaced, keyId);
        },
      ),
    );

  render
    .command("remove <handle>")
    .description("Remove a render entry from a delivering key")
    .requiredOption("--entry <name>", "Render entry name")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action((handle: string, options: RenderRemoveOptions, cmd: Command) =>
      runRenderCommand(
        cmd,
        options.json,
        () => judgeRemoveOptions(options),
        (client) => removeEntry(restAccess(client), handle, options.entry),
        (engine) => {
          const resolved = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            tokenOf(options),
            "secret render remove",
          );
          return removeEntry(engineAccess(engine, resolved?.caller), handle, options.entry);
        },
      ),
    );

  render
    .command("approve <handle>")
    .description(
      "Approve a key's render entry on a slot's secret: its value may then be written into that entry's file",
    )
    .option(
      "--key <handle>",
      "The delivering key's handle, read under the caller's grant on the key; its entry is shown unless --digest is given",
    )
    .option(
      "--key-id <id>",
      "The delivering key's id, in place of --key (needs --digest): no read of the key",
    )
    .requiredOption("--entry <name>", "Render entry name")
    .option(
      "--digest <hex>",
      "The entry's digest as its key's administrator printed it, approved as given; the entry is not shown",
    )
    .option("--confirm", "Skip confirmation prompt")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action((handle: string, options: RenderApprovalOptions, cmd: Command) =>
      runRenderCommand(
        cmd,
        options.json,
        () => judgeApprovalOptions(options, "approve"),
        async (client) => {
          if (options.key !== undefined) throw restModeUnsupported("secret render approve --key");
          const approval = showApproval({
            key: options.keyId as string,
            entry: options.entry,
            digest: options.digest as string,
          });
          await storeApproval(restAccess(client), handle, approval, options.confirm);
        },
        async (engine) => {
          const token = tokenOf(options);
          const slot = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            token,
            "secret render approve",
          );
          const approval = await approvalInProcess(engine, options, token);
          await storeApproval(
            engineAccess(engine, slot?.caller),
            handle,
            approval,
            options.confirm,
          );
        },
      ),
    );

  render
    .command("revoke <handle>")
    .description("Remove an approval from a slot's secret")
    .option(
      "--key <handle>",
      "The delivering key's handle, read under the caller's grant on the key",
    )
    .option("--key-id <id>", "The delivering key's id, in place of --key: no read of the key")
    .requiredOption("--entry <name>", "Render entry name")
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action((handle: string, options: RenderApprovalOptions, cmd: Command) =>
      runRenderCommand(
        cmd,
        options.json,
        () => judgeApprovalOptions(options, "revoke"),
        async (client) => {
          if (options.key !== undefined) throw restModeUnsupported("secret render revoke --key");
          await removeApproval(restAccess(client), handle, options.keyId as string, options.entry);
        },
        async (engine) => {
          const token = tokenOf(options);
          const slot = resolveTokenCallerForHandle(
            engine,
            "admin",
            handle,
            token,
            "secret render revoke",
          );
          let keyId = options.keyId as string;
          if (options.key !== undefined) {
            const scoped = resolveTokenCallerForHandle(
              engine,
              "read",
              options.key,
              token,
              "secret render revoke",
            );
            const key = await readKey(
              engine,
              options.key,
              scoped?.caller,
              AuditEventType.POLICY_GRANT,
            );
            keyId = key.id;
          }
          await removeApproval(engineAccess(engine, slot?.caller), handle, keyId, options.entry);
        },
      ),
    );

  render
    .command("list <handle>")
    .description("Show a secret's render entries with their slots and digests, and its approvals")
    .option("--template <name>", "Print one entry's template, byte for byte")
    .option(
      "--key <handle>",
      "A delivering key's handle: its policy is read and each approval of its entries whose entry is gone or changed is marked stale",
    )
    .option("--token <jwt>", TOKEN_OPTION_DESCRIPTION)
    .option("--json", "Output as JSON")
    .action((handle: string, options: RenderListOptions, cmd: Command) =>
      runRenderCommand(
        cmd,
        options.json,
        () => judgeListOptions(options),
        async (client) => {
          if (options.key !== undefined) throw restModeUnsupported("secret render list --key");
          const policy = await client.getInjectionPolicy(handle);
          if (options.template !== undefined) {
            writeTemplate(policy, options.template);
            return;
          }
          printJson({
            entries: policy.render.entries.map(renderEntryDetail),
            approvals: policy.render.approvals,
          });
        },
        async (engine) => {
          const token = tokenOf(options);
          const listed = resolveTokenCallerForHandle(
            engine,
            "read",
            handle,
            token,
            "secret render list",
          );
          const key =
            options.key === undefined
              ? undefined
              : resolveTokenCallerForHandle(
                  engine,
                  "read",
                  options.key,
                  token,
                  "secret render list",
                );
          const policy = await engine.getInjectionPolicy(handle, listed?.caller);
          if (options.template !== undefined) {
            writeTemplate(policy, options.template);
            return;
          }
          const keyId = await resolveSecretId(engine, handle, listed?.caller);
          let approvals: ListedApproval[] = policy.render.approvals;
          if (options.key !== undefined) {
            const marked = await readKey(engine, options.key, key?.caller);
            approvals = markStale(approvals, marked.id, marked.policy.render.entries);
          }
          printJson({
            key_id: keyId,
            entries: policy.render.entries.map(renderEntryDetail),
            approvals,
          });
        },
      ),
    );
}
