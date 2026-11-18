import type { ImapAction, UseSecretAction } from "@harpoc/shared";

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
