import { randomBytes } from "node:crypto";
import ssh2 from "ssh2";
import type {
  AnyAuthMethod,
  AuthenticationType,
  AuthHandlerMiddleware,
  Client as SshClient,
} from "ssh2";
import { afterEach, describe, expect, it } from "vitest";
import { expectAbsent } from "@harpoc/test-utils";
import {
  type PasswordServer,
  type PasswordServerAuth,
  type PasswordServerExec,
  startPasswordSshServer,
} from "./ssh2-password-server.js";

const { Client } = ssh2;

const USER = "deploy";
const COMMAND = "copy-the-input";
const COPY_INPUT =
  'process.stdin.pipe(process.stdout); process.stderr.write("to-stderr"); process.stdin.on("end", () => { process.exitCode = 7; });';
const LINGER = 'process.stdout.write(String(process.pid) + "\\n"); setInterval(() => {}, 1000);';

type ClientError = Error & { level?: string };

interface Login {
  client: SshClient;
  error: ClientError | null;
  offered: AuthenticationType[][];
  hostKey: Buffer | null;
}

interface Ran {
  stdout: string;
  stderr: string;
  code: number | null;
}

const servers: PasswordServer[] = [];
const clients: SshClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.end();
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function drawPassword(): string {
  return randomBytes(18).toString("base64url");
}

function nodeChild(script: string): PasswordServerExec {
  return { file: process.execPath, args: ["-e", script], env: {} };
}

async function serve(
  password: string,
  auth?: PasswordServerAuth,
  exec: (command: string) => PasswordServerExec | null = () => null,
): Promise<PasswordServer> {
  const server = await startPasswordSshServer({ user: USER, password, auth, exec });
  servers.push(server);
  return server;
}

function login(
  server: PasswordServer,
  username: string,
  password?: string,
  readyTimeout = 10_000,
): Promise<Login> {
  const client = new Client();
  clients.push(client);
  const offered: AuthenticationType[][] = [];
  let hostKey: Buffer | null = null;
  let passwordSent = false;
  const handler = (
    left: AuthenticationType[] | null,
    _partial: boolean | null,
    next: (method: AnyAuthMethod | false) => void,
  ): void => {
    if (left === null) {
      next({ type: "none", username });
      return;
    }
    offered.push(left);
    if (password !== undefined && !passwordSent && left.includes("password")) {
      passwordSent = true;
      next({ type: "password", username, password });
      return;
    }
    next(false);
  };
  return new Promise((resolve) => {
    const settle = (error: ClientError | null): void =>
      resolve({ client, error, offered, hostKey });
    client.once("ready", () => settle(null));
    client.on("error", (err: ClientError) => settle(err));
    client.once("close", () => settle(new Error("the connection closed")));
    client.connect({
      host: "127.0.0.1",
      port: server.port,
      username,
      readyTimeout,
      hostVerifier: (key: Buffer): boolean => {
        hostKey = key;
        return true;
      },
      authHandler: handler as unknown as AuthHandlerMiddleware,
    });
  });
}

function run(client: SshClient, command: string, input: string): Promise<Ran> {
  return new Promise((resolve, reject) => {
    client.exec(command, (err, stream) => {
      if (err) {
        reject(err);
        return;
      }
      let stdout = "";
      let stderr = "";
      let code: number | null = null;
      stream.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      stream.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      stream.on("exit", (status: number | null) => {
        code = status;
      });
      stream.on("close", () => resolve({ stdout, stderr, code }));
      stream.end(input);
    });
  });
}

function refusedRequest(
  open: (callback: (err: Error | undefined) => void) => void,
): Promise<boolean> {
  return new Promise((resolve) => open((err) => resolve(err !== undefined)));
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe("the ssh2 password server against ssh2's own client", () => {
  it("the password is accepted and the command's input reaches the process", async () => {
    const password = drawPassword();
    const server = await serve(password, undefined, (command) =>
      command === COMMAND ? nodeChild(COPY_INPUT) : null,
    );
    const { client, error, hostKey } = await login(server, USER, password);
    expect(error).toBeNull();
    const input = `${randomBytes(12).toString("hex")}\nsecond line\n`;
    const ran = await run(client, COMMAND, input);
    expectAbsent(JSON.stringify(server.seen), password, "what the server records");
    expect(ran).toEqual({ stdout: input, stderr: "to-stderr", code: 7 });
    expect(server.seen).toEqual({
      methods: ["none", "password"],
      passwords: 1,
      commands: [COMMAND],
    });
    const [type, base64] = server.hostKeyLine.split(" ");
    expect(type).toBe("ssh-ed25519");
    expect(server.hostKeyLine.split(" ")).toHaveLength(2);
    expect((hostKey as Buffer).equals(Buffer.from(base64 as string, "base64"))).toBe(true);
  });

  it("a wrong password is refused", async () => {
    const password = drawPassword();
    const wrong = drawPassword();
    const server = await serve(password, undefined, () => nodeChild(COPY_INPUT));
    const { error, offered } = await login(server, USER, wrong);
    expectAbsent(JSON.stringify(server.seen), password, "what the server records");
    expectAbsent(JSON.stringify(server.seen), wrong, "what the server records");
    expect(error?.level).toBe("client-authentication");
    expect(offered).toEqual([["password"], ["password"]]);
    expect(server.seen).toEqual({ methods: ["none", "password"], passwords: 1, commands: [] });
  });

  it("`refuse` refuses the right password", async () => {
    const password = drawPassword();
    const server = await serve(password, "refuse", () => nodeChild(COPY_INPUT));
    const { error, offered } = await login(server, USER, password);
    expectAbsent(JSON.stringify(server.seen), password, "what the server records");
    expect(error?.level).toBe("client-authentication");
    expect(offered).toEqual([["password"], ["password"]]);
    expect(server.seen).toEqual({ methods: ["none", "password"], passwords: 1, commands: [] });
  });

  it("`no-password` offers publickey alone", async () => {
    const password = drawPassword();
    const server = await serve(password, "no-password", () => nodeChild(COPY_INPUT));
    const { error, offered } = await login(server, USER, password);
    expect(error?.level).toBe("client-authentication");
    expect(offered).toEqual([["publickey"]]);
    expect(server.seen).toEqual({ methods: ["none"], passwords: 0, commands: [] });
  });

  it("`open` accepts without a password", async () => {
    const password = drawPassword();
    const server = await serve(password, "open", (command) =>
      command === COMMAND ? nodeChild(COPY_INPUT) : null,
    );
    const { client, error } = await login(server, USER);
    expect(error).toBeNull();
    const ran = await run(client, COMMAND, "input\n");
    expect(ran).toEqual({ stdout: "input\n", stderr: "to-stderr", code: 7 });
    expect(server.seen).toEqual({ methods: ["none"], passwords: 0, commands: [COMMAND] });
  });

  it("`silent` answers no request", async () => {
    const password = drawPassword();
    const server = await serve(password, "silent", () => nodeChild(COPY_INPUT));
    const { error } = await login(server, USER, password, 2_000);
    expect(error?.level).toBe("client-timeout");
    expect(server.seen).toEqual({ methods: ["none"], passwords: 0, commands: [] });
  });

  it.each<PasswordServerAuth>(["password", "refuse", "no-password", "open"])(
    "another user is refused in every mode: %s (`silent` answers nobody)",
    async (auth) => {
      const password = drawPassword();
      const server = await serve(password, auth, () => nodeChild(COPY_INPUT));
      const { error } = await login(server, "intruder", password);
      expectAbsent(JSON.stringify(server.seen), password, "what the server records");
      expect(error?.level).toBe("client-authentication");
      expect(server.seen.commands).toEqual([]);
    },
  );

  it("an exec the handler answers with null is refused, and so are a shell and a subsystem", async () => {
    const password = drawPassword();
    const server = await serve(password, undefined, () => null);
    const { client, error } = await login(server, USER, password);
    expect(error).toBeNull();
    expect(await refusedRequest((done) => client.exec("anything", (err) => done(err)))).toBe(true);
    expect(await refusedRequest((done) => client.shell(false, (err) => done(err)))).toBe(true);
    expect(await refusedRequest((done) => client.subsys("sftp", (err) => done(err)))).toBe(true);
    expect(server.seen.commands).toEqual(["anything"]);
  });

  it("`close` ends a child that is still running", async () => {
    const password = drawPassword();
    const server = await serve(password, undefined, () => nodeChild(LINGER));
    const { client } = await login(server, USER, password);
    const pid = await new Promise<number>((resolve, reject) => {
      client.exec("linger", (err, stream) => {
        if (err) {
          reject(err);
          return;
        }
        let text = "";
        stream.on("data", (chunk: Buffer) => {
          text += chunk.toString("utf8");
          if (text.endsWith("\n")) resolve(Number(text.trim()));
        });
      });
    });
    expect(alive(pid)).toBe(true);
    servers.splice(servers.indexOf(server), 1);
    await server.close();
    expect(alive(pid)).toBe(false);
  }, 10_000);
});
