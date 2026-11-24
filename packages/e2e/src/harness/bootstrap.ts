import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { COMPOSE_DIR, DOCKER } from "./backends.js";
import type { FleetService } from "./backends.js";

export const BOOTSTRAP_OUT = fileURLToPath(
  new URL("../../fixtures/sshd-bootstrap/out", import.meta.url),
);

export const SSHD_BOOTSTRAP = {
  sudo: { service: "sshd-bootstrap-sudo", host: "127.0.0.1", port: 55122 },
  "sudo-rs": { service: "sshd-bootstrap-sudo-rs", host: "127.0.0.1", port: 55123 },
} as const satisfies Record<string, { service: FleetService; host: string; port: number }>;

export type BootstrapService = (typeof SSHD_BOOTSTRAP)[keyof typeof SSHD_BOOTSTRAP]["service"];

export interface HostState {
  keyLines: number;
  dropIn: string | null;
  sudoWaiting: boolean;
}

const HOST_STATE_SCRIPT = [
  'u=$(id -u "$1") || exit 3',
  'h=$(getent passwd "$1" | cut -d: -f6)',
  'n=$(grep -cxF -- "$2" "$h/.ssh/authorized_keys" 2>/dev/null)',
  'echo "${n:-0}"',
  "f=/etc/sudoers.d/harpoc-$u",
  'if [ -e "$f" ]; then stat -c %a:%U "$f"; else echo -; fi',
  'if pgrep -U "$1" -x sudo >/dev/null; then echo waiting; else echo idle; fi',
].join("; ");

const FRESH_HOST_SCRIPT = "if [ -e /home/plain/.ssh ]; then echo used; else echo fresh; fi";

function readOut(dir: string, name: string): string {
  const path = join(dir, name);
  if (!existsSync(path)) {
    throw new Error(
      `fixture sshd-bootstrap/out/${name} is missing — run: pnpm --filter @harpoc/e2e bootstrap`,
    );
  }
  return readFileSync(path, "utf8");
}

function publicKeyLine(dir: string, name: string): string {
  const [type, body] = readOut(dir, name).trim().split(/\s+/);
  if (type === undefined || body === undefined) {
    throw new Error(`malformed public key fixture: sshd-bootstrap/out/${name}`);
  }
  return `${type} ${body}`;
}

export function bootstrapPassword(dir: string = BOOTSTRAP_OUT): string {
  return readOut(dir, "password");
}

export function bootstrapHostKey(dir: string = BOOTSTRAP_OUT): string {
  return publicKeyLine(dir, "hostkey_ed25519.pub");
}

export function agentPublicKey(dir: string = BOOTSTRAP_OUT): string {
  return publicKeyLine(dir, "agent_ed25519.pub");
}

export function agentPrivateKeyPem(dir: string = BOOTSTRAP_OUT): string {
  return readOut(dir, "agent_ed25519");
}

export function parseHostState(text: string): HostState {
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === "") lines.pop();
  const [count, dropIn, sudo] = lines;
  if (
    lines.length !== 3 ||
    count === undefined ||
    !/^[0-9]+$/.test(count) ||
    dropIn === undefined ||
    dropIn === "" ||
    (sudo !== "waiting" && sudo !== "idle")
  ) {
    throw new Error(`unexpected host state: ${JSON.stringify(text)}`);
  }
  return {
    keyLines: Number(count),
    dropIn: dropIn === "-" ? null : dropIn,
    sudoWaiting: sudo === "waiting",
  };
}

function composeExec(service: BootstrapService, argv: string[]): string {
  return execFileSync(DOCKER, ["compose", "exec", "-T", service, ...argv], {
    cwd: COMPOSE_DIR,
    encoding: "utf8",
  });
}

export function hostState(service: BootstrapService, user: string): HostState {
  return parseHostState(
    composeExec(service, ["sh", "-c", HOST_STATE_SCRIPT, "sh", user, agentPublicKey()]),
  );
}

export function assertFreshHost(service: BootstrapService): void {
  if (composeExec(service, ["sh", "-c", FRESH_HOST_SCRIPT]).trim() !== "fresh") {
    throw new Error(
      `backend "${service}" has run the bootstrap already — run: pnpm --filter @harpoc/e2e fleet:recreate`,
    );
  }
}
