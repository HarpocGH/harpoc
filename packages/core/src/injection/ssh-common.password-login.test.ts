import { randomBytes } from "node:crypto";
import { SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC, SSH_HOST_KEY_TYPES } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HOST_KEY, KEY_B } from "./__fixtures__/ssh-public-keys.js";
import type { SshPublicKey } from "./ssh-common-keys.js";
import { parseSshPublicKey } from "./ssh-common-keys.js";
import {
  buildSshPasswordEnv,
  knownHostsLines,
  sshHardeningArgs,
  sshPasswordLoginArgs,
  sshPasswordPrompt,
} from "./ssh-common.js";

const KNOWN_HOSTS = {
  file: "/t/harpoc-ssh-x/known_hosts",
  globalFile: "/t/harpoc-ssh-x/global_known_hosts",
};

const AMBIENT = "HARPOC_T3_AMBIENT";
const NOT_LISTED = "HARPOC_T3_NOT_LISTED";

describe("sshPasswordLoginArgs", () => {
  it("the argv, letter for letter", () => {
    expect(sshPasswordLoginArgs(KNOWN_HOSTS, SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC)).toEqual([
      "-F",
      "none",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      'UserKnownHostsFile="/t/harpoc-ssh-x/known_hosts"',
      "-o",
      'GlobalKnownHostsFile="/t/harpoc-ssh-x/global_known_hosts"',
      "-o",
      "PreferredAuthentications=password",
      "-o",
      "PubkeyAuthentication=no",
      "-o",
      "KbdInteractiveAuthentication=no",
      "-o",
      "ChallengeResponseAuthentication=no",
      "-o",
      "PasswordAuthentication=yes",
      "-o",
      "NumberOfPasswordPrompts=1",
      "-o",
      "BatchMode=no",
      "-o",
      "ConnectTimeout=15",
      "-o",
      "IdentityAgent=none",
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "IdentityFile=none",
      "-o",
      "CheckHostIP=no",
      "-o",
      "UpdateHostKeys=no",
      "-o",
      "VerifyHostKeyDNS=no",
      "-o",
      "ControlMaster=no",
      "-o",
      "ControlPath=none",
      "-o",
      "ClearAllForwardings=yes",
      "-o",
      "ForwardAgent=no",
      "-o",
      "ForwardX11=no",
      "-o",
      "RequestTTY=no",
      "-o",
      "EscapeChar=none",
      "-o",
      "LogLevel=ERROR",
    ]);
  });

  it("it shares its first four pairs with sshHardeningArgs", () => {
    expect(
      sshPasswordLoginArgs(KNOWN_HOSTS, SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC).slice(0, 8),
    ).toEqual(sshHardeningArgs(KNOWN_HOSTS, "/t/harpoc-ssh-id-x/identity.pub").slice(0, 8));
  });

  it.each(["-i", "-n", "BatchMode=yes", "PasswordAuthentication=no", "StdinNull=yes"])(
    "no word of it is an identity, a batch switch or a null input: %s",
    (word) => {
      expect(sshPasswordLoginArgs(KNOWN_HOSTS, SSH_BOOTSTRAP_CONNECT_TIMEOUT_SEC)).not.toContain(
        word,
      );
    },
  );
});

describe("knownHostsLines", () => {
  const hostKey = parseSshPublicKey(HOST_KEY, SSH_HOST_KEY_TYPES) as SshPublicKey;
  const rsaKey = parseSshPublicKey(KEY_B, SSH_HOST_KEY_TYPES) as SshPublicKey;

  it("port 22 names the bare host", () => {
    expect(knownHostsLines("host.example", 22, [hostKey])).toEqual([`host.example ${HOST_KEY}`]);
  });

  it("any other port names [host]:port", () => {
    expect(knownHostsLines("host.example", 2222, [hostKey])).toEqual([
      `[host.example]:2222 ${HOST_KEY}`,
    ]);
  });

  it("two keys give two lines in their order", () => {
    expect(knownHostsLines("host.example", 2222, [hostKey, rsaKey])).toEqual([
      `[host.example]:2222 ${HOST_KEY}`,
      `[host.example]:2222 ${KEY_B}`,
    ]);
    expect(knownHostsLines("host.example", 22, [rsaKey, hostKey])).toEqual([
      `host.example ${KEY_B}`,
      `host.example ${HOST_KEY}`,
    ]);
  });
});

describe("sshPasswordPrompt", () => {
  it("is <user>@<host>'s password: with one blank at its end", () => {
    expect(sshPasswordPrompt("deploy", "host.example")).toBe("deploy@host.example's password: ");
  });
});

describe("buildSshPasswordEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("is built from nothing and its own names win", () => {
    const ambientPassword = randomBytes(18).toString("base64url");
    const password = randomBytes(18).toString("base64url");
    const word = randomBytes(18).toString("base64url");
    vi.stubEnv("SSH_AUTH_SOCK", "/ambient/agent.sock");
    vi.stubEnv("DISPLAY", ":0");
    vi.stubEnv("WAYLAND_DISPLAY", "wayland-0");
    vi.stubEnv("SSH_ASKPASS", "/ambient/askpass");
    vi.stubEnv("SSH_ASKPASS_REQUIRE", "never");
    vi.stubEnv("HARPOC_SSH_PASSWORD", ambientPassword);
    vi.stubEnv(AMBIENT, "carried");
    vi.stubEnv(NOT_LISTED, "left behind");
    const helper = {
      launcher: "/t/harpoc-ssh-askpass-x/askpass.sh",
      prompt: "deploy@host.example's password: ",
      word,
      password,
    };

    const env = buildSshPasswordEnv(
      [
        "SSH_AUTH_SOCK",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "HARPOC_SSH_PASSWORD",
        AMBIENT,
      ],
      helper,
    );

    expectAbsent(env.HARPOC_SSH_PASSWORD, ambientPassword, "HARPOC_SSH_PASSWORD");
    expect(Object.keys(env).sort()).toEqual(
      [
        "PATH",
        ...(process.platform === "win32" ? ["SystemRoot", "ProgramData"] : []),
        AMBIENT,
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "HARPOC_SSH_PROMPT",
        "HARPOC_SSH_WORD",
        "HARPOC_SSH_PASSWORD",
      ].sort(),
    );
    expect(env.PATH).toBe(process.env.PATH ?? process.env.Path);
    expect(env[AMBIENT]).toBe("carried");
    expect(env.SSH_ASKPASS).toBe(helper.launcher);
    expect(env.SSH_ASKPASS_REQUIRE).toBe("force");
    expect(env.HARPOC_SSH_PROMPT).toBe(helper.prompt);
    expect(env.HARPOC_SSH_WORD).toBe(word);
    expect(env.HARPOC_SSH_PASSWORD === password).toBe(true);
  });
});
