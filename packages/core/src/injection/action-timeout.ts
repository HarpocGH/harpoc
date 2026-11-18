import type { UseSecretAction } from "@harpoc/shared";
import {
  dockerRegistryActionSchema,
  gitActionSchema,
  httpActionSchema,
  imapActionSchema,
  MAX_DOCKER_TIMEOUT_MS,
  mcpActionSchema,
  processActionSchema,
  sftpActionSchema,
  smtpActionSchema,
  sshActionSchema,
  websocketActionSchema,
} from "@harpoc/shared";

const TIMEOUT_FIELDS: Record<
  Exclude<UseSecretAction["type"], "database">,
  { safeParse(value: unknown): { success: boolean } }
> = {
  http: httpActionSchema.shape.timeout_ms,
  process: processActionSchema.shape.timeout_ms,
  mcp: mcpActionSchema.shape.timeout_ms,
  git: gitActionSchema.shape.timeout_ms,
  ssh: sshActionSchema.shape.timeout_ms,
  sftp: sftpActionSchema.shape.timeout_ms,
  docker_registry: dockerRegistryActionSchema.shape.timeout_ms,
  smtp: smtpActionSchema.shape.timeout_ms,
  imap: imapActionSchema.shape.timeout_ms,
  websocket: websocketActionSchema.shape.timeout_ms,
};

export function actionTimeoutRefusal(action: UseSecretAction): string | undefined {
  const type: unknown = action.type;
  if (typeof type !== "string" || !Object.hasOwn(TIMEOUT_FIELDS, type)) return undefined;
  const field = TIMEOUT_FIELDS[type as keyof typeof TIMEOUT_FIELDS];
  if (field.safeParse(action.timeout_ms).success) return undefined;
  return type === "docker_registry"
    ? `timeout_ms must be a positive integer up to ${String(MAX_DOCKER_TIMEOUT_MS)}`
    : "timeout_ms must be a positive integer up to 300000";
}
