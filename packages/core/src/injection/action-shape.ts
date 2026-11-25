import type { ImapAction, UseSecretAction } from "@harpoc/shared";
import { isValidName, MAX_SSH_KEY_LINE_CHARS } from "@harpoc/shared";
import { isSshName } from "./ssh-common.js";

const CONTEXTS: Record<UseSecretAction["type"], true> = {
  http: true,
  process: true,
  mcp: true,
  database: true,
  git: true,
  ssh: true,
  smtp: true,
  imap: true,
  websocket: true,
  sftp: true,
  docker_registry: true,
};

export function actionShapeRefusal(action: unknown): string | undefined {
  if (typeof action !== "object" || action === null || Array.isArray(action)) {
    return "action must be an object";
  }
  const type: unknown = (action as { type?: unknown }).type;
  if (typeof type !== "string") return `Unsupported action type: ${typeof type}`;
  if (!Object.hasOwn(CONTEXTS, type)) return `Unsupported action type: ${type}`;
  if (type === "ssh") return sshBootstrapShapeRefusal(action as Record<string, unknown>);
  if (type === "sftp") return sftpRenderShapeRefusal(action as Record<string, unknown>);
  return undefined;
}

const SFTP_RENDER_FORBIDDEN_KEYS = ["host", "user", "port", "remote_path", "local_path"] as const;

function sftpRenderShapeRefusal(action: Record<string, unknown>): string | undefined {
  if (action.operation !== "render") return undefined;
  for (const key of SFTP_RENDER_FORBIDDEN_KEYS) {
    if (action[key] !== undefined) {
      return "an sftp render takes no host, user, port, remote_path or local_path";
    }
  }
  const entry = action.entry;
  if (typeof entry !== "string" || !isValidName(entry)) {
    return "an sftp render's entry must be a name of letters, digits, '_' and '-' of at most 255 characters";
  }
  return undefined;
}

const SSH_BOOTSTRAP_KEYS: Record<string, true> = {
  type: true,
  operation: true,
  host: true,
  user: true,
  port: true,
  public_key: true,
  sudoers: true,
};

function sshBootstrapShapeRefusal(action: Record<string, unknown>): string | undefined {
  if (action.operation === undefined) return undefined;
  if (action.operation !== "bootstrap") return 'ssh operation must be "bootstrap"';
  for (const [key, value] of Object.entries(action)) {
    if (value !== undefined && !Object.hasOwn(SSH_BOOTSTRAP_KEYS, key)) {
      return "an ssh bootstrap takes type, operation, host, user, port, public_key and sudoers alone";
    }
  }
  if (!isSshName(action.host) || !isSshName(action.user)) {
    return "an ssh bootstrap's host and user must be names of letters, digits, '.', '_' and '-'";
  }
  const port = action.port;
  if (
    port !== undefined &&
    !(Number.isInteger(port) && (port as number) >= 1 && (port as number) <= 65_535)
  ) {
    return "an ssh bootstrap's port must be an integer from 1 to 65535";
  }
  if (typeof action.public_key !== "string" || action.public_key.length > MAX_SSH_KEY_LINE_CHARS) {
    return "an ssh bootstrap's public_key must be a string of at most 4096 characters";
  }
  if (action.sudoers !== undefined && typeof action.sudoers !== "boolean") {
    return "an ssh bootstrap's sudoers must be a boolean";
  }
  return undefined;
}

const IMAP_KINDS: Record<ImapAction["operation"]["kind"], true> = {
  search: true,
  fetch: true,
  store: true,
  move: true,
  copy: true,
  expunge: true,
};

export function imapOperationRefusal(action: UseSecretAction): string | undefined {
  if (action.type !== "imap") return undefined;
  const operation: unknown = action.operation;
  if (typeof operation === "object" && operation !== null && !Array.isArray(operation)) {
    const kind: unknown = (operation as { kind?: unknown }).kind;
    if (typeof kind === "string" && Object.hasOwn(IMAP_KINDS, kind)) return undefined;
  }
  return "imap operation must be an object with a supported kind";
}
