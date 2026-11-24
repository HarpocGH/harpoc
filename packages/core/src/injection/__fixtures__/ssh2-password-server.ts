import { spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { AddressInfo } from "node:net";
import ssh2 from "ssh2";
import type { AuthContext, AuthenticationType, Connection, ServerChannel } from "ssh2";
import { generateEd25519HostKeys } from "./ssh2-host-keys.js";

const { Server } = ssh2;

export type PasswordServerAuth =
  | "password" // the user's password is accepted; anything else is refused with the list ["password"]
  | "refuse" // offers ["password"] and refuses every password
  | "no-password" // refuses everything with the list ["publickey"]
  | "open" // accepts the user's "none" request: an account without a password
  | "silent"; // completes the key exchange and never answers an authentication request

export interface PasswordServerExec {
  file: string;
  args: string[];
  env: Record<string, string>;
}

export interface PasswordServerOptions {
  user: string;
  password: string;
  auth?: PasswordServerAuth; // default "password"
  exec: (command: string) => PasswordServerExec | null; // null refuses the exec request
}

export interface PasswordServer {
  port: number;
  hostKeyLine: string; // "<type> <base64>", no comment
  seen: { methods: string[]; passwords: number; commands: string[] };
  close: () => Promise<void>; // kills live children, awaits their close and the server's
}

const CHILD_DEADLINE_MS = 20_000;

/**
 * An ssh2 server on a loopback port that logs one user in by the method `auth` names and hands
 * an exec request's channel to a local process the test names: the channel's input is the
 * process's standard input, its two outputs go back on the channel, its exit status ends it.
 * It records the methods it was asked, how many passwords it saw and the commands, never a password.
 */
export async function startPasswordSshServer(
  options: PasswordServerOptions,
): Promise<PasswordServer> {
  const auth = options.auth ?? "password";
  const offered: AuthenticationType[] = auth === "no-password" ? ["publickey"] : ["password"];
  const hostKeys = generateEd25519HostKeys();
  const seen: PasswordServer["seen"] = { methods: [], passwords: 0, commands: [] };
  const connections = new Set<Connection>();
  const children = new Map<ChildProcess, Promise<void>>();

  const accepts = (ctx: AuthContext): boolean => {
    if (ctx.username !== options.user) return false;
    if (auth === "password") return ctx.method === "password" && ctx.password === options.password;
    return auth === "open" && ctx.method === "none";
  };

  const runChild = (stream: ServerChannel, target: PasswordServerExec): void => {
    const child = spawn(target.file, target.args, {
      env: target.env,
      stdio: "pipe",
      shell: false,
      windowsHide: true,
    });
    let failed = false;
    const deadline = setTimeout(() => child.kill("SIGKILL"), CHILD_DEADLINE_MS);
    children.set(
      child,
      new Promise((resolve) => {
        child.once("close", (code) => {
          clearTimeout(deadline);
          children.delete(child);
          stream.exit(failed || code === null ? 255 : code);
          stream.end();
          resolve();
        });
      }),
    );
    child.on("error", () => {
      failed = true;
    });
    child.stdin.on("error", () => {});
    stream.on("error", () => {});
    stream.pipe(child.stdin);
    child.stdout.pipe(stream, { end: false });
    child.stderr.pipe(stream.stderr, { end: false });
  };

  const server = new Server({ hostKeys: [hostKeys.private] }, (connection) => {
    connections.add(connection);
    connection.once("close", () => connections.delete(connection));
    connection.on("error", () => {});
    connection.on("authentication", (ctx) => {
      seen.methods.push(ctx.method);
      if (ctx.method === "password") seen.passwords += 1;
      if (auth === "silent") return;
      if (accepts(ctx)) ctx.accept();
      else ctx.reject(offered);
    });
    connection.on("ready", () => {
      connection.on("session", (acceptSession) => {
        const session = acceptSession();
        session.on("exec", (acceptExec, rejectExec, info) => {
          seen.commands.push(info.command);
          const target = options.exec(info.command);
          if (target === null) {
            rejectExec();
            return;
          }
          runChild(acceptExec(), target);
        });
        session.on("shell", (_acceptShell, rejectShell) => rejectShell());
        session.on("subsystem", (_acceptSubsystem, rejectSubsystem) => rejectSubsystem());
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;

  let closing: Promise<void> | undefined;
  return {
    port,
    hostKeyLine: hostKeys.public.split(/\s+/).slice(0, 2).join(" "),
    seen,
    close: () => {
      closing ??= (async () => {
        for (const child of children.keys()) child.kill("SIGKILL");
        await Promise.all(children.values());
        for (const connection of connections) connection.end();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      })();
      return closing;
    },
  };
}
