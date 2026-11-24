import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { expectAbsent } from "@harpoc/test-utils";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type BootstrapStandIns,
  makeBootstrapStandIns,
  runBootstrapScript,
} from "./__fixtures__/bootstrap-standins.js";
import {
  type BootstrapStatus,
  bootstrapStdin,
  readBootstrapStatus,
} from "./ssh-injector-bootstrap-script.js";

const PREFIX = "harpoc-bootstrap-v1";
const FRAMELESS = `\n${PREFIX} - not_attempted not_attempted\n`;
const RULE = "#1000 ALL=(ALL:ALL) NOPASSWD: ALL\n";
const OTHER_KEY = "ssh-rsa AAAAB3OTHER other@host";

function drawFrame(): string {
  return randomBytes(18).toString("base64url");
}

function drawKeyLine(): string {
  return `ssh-ed25519 ${randomBytes(51).toString("base64")}`;
}

function mode(path: string): number {
  return statSync(path).mode & 0o777;
}

interface Ran {
  stdout: string;
  log: string[];
  status: BootstrapStatus | null;
}

describe.skipIf(process.platform === "win32")(
  "the bootstrap script under the leg's /bin/sh, against the stand-ins (no POSIX /bin/sh on win32; the bootstrap is refused on a Windows vault host)",
  () => {
    let s: BootstrapStandIns;
    let frame: string;
    let key: string;

    beforeEach(() => {
      s = makeBootstrapStandIns();
      frame = drawFrame();
      key = drawKeyLine();
    });

    afterEach(() => {
      s.dispose();
    });

    const sshDir = (): string => join(s.home, ".ssh");
    const keysFile = (): string => join(s.home, ".ssh", "authorized_keys");
    const dropIn = (): string => join(s.sudoersDir, "harpoc-1000");
    const withFlag = (password: string = s.password, f: string = frame): Buffer =>
      bootstrapStdin(f, key, Buffer.from(password));
    const keysBefore = (text: string): void => {
      mkdirSync(sshDir(), { mode: 0o700 });
      writeFileSync(keysFile(), text, { mode: 0o600 });
    };

    async function run(
      input: Buffer,
      options: { startup?: string; home?: string; frame?: string; secret?: string } = {},
    ): Promise<Ran> {
      const before = s.log().length;
      const result = await runBootstrapScript(
        s.command,
        options.home ?? s.home,
        input,
        options.startup,
      );
      const log = s.log();
      expectAbsent(result.stdout, options.secret ?? s.password, "the script's output");
      expectAbsent(log.join("\n"), options.secret ?? s.password, "the stand-ins' log");
      expectAbsent(result.stderr, options.secret ?? s.password, "the script's error stream");
      expect(result.stderr).toBe("");
      expect(result.code).toBe(0);
      return {
        stdout: result.stdout,
        log: log.slice(before),
        status: readBootstrapStatus(result.stdout, options.frame ?? frame, (t) => t),
      };
    }

    it("without the flag the key is installed", async () => {
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(mode(sshDir())).toBe(0o700);
      expect(mode(keysFile())).toBe(0o600);
      expect(readFileSync(keysFile(), "utf8")).toBe(`${key}\n`);
      expect(r.log).toEqual([]);
    });

    it("a second run finds the key", async () => {
      await run(bootstrapStdin(frame, key));
      const before = readFileSync(keysFile());
      const second = drawFrame();
      const r = await run(bootstrapStdin(second, key), { frame: second });
      expect(r.status).toEqual({ dropIn: "not_asked", key: "present" });
      expect(readFileSync(keysFile()).equals(before)).toBe(true);
    });

    it("with the flag the drop-in is written before the key", async () => {
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
      expect(readFileSync(dropIn(), "utf8")).toBe(RULE);
      expect(mode(dropIn())).toBe(0o440);
      expect(readFileSync(keysFile(), "utf8")).toBe(`${key}\n`);
      expect(r.log).toEqual([
        "id -u stdin=0",
        `sudo read=${String(s.password.length)}`,
        `visudo -c -f ${s.dir}/sudoers.d/harpoc-1000.tmp stdin=0`,
        `visudo -c -f ${s.dir}/sudoers stdin=0`,
      ]);
    });

    it("a second run with the flag leaves the drop-in", async () => {
      await run(withFlag());
      const before = readFileSync(dropIn());
      const second = drawFrame();
      const r = await run(withFlag(s.password, second), { frame: second });
      expect(r.status).toEqual({ dropIn: "present", key: "present" });
      expect(r.log).toEqual(["id -u stdin=0", `sudo read=${String(s.password.length)}`]);
      expect(readFileSync(dropIn()).equals(before)).toBe(true);
    });

    it.each([
      ["holds the rule among other lines", `Defaults:#1000 !lecture\n${RULE}# kept\n`, "present"],
      ["holds other text", "#1000 ALL=(ALL) ALL\n", "written"],
    ] as const)(
      "a drop-in that holds the rule among other lines is left; one that holds other text is replaced: %s",
      async (_label, text, word) => {
        writeFileSync(dropIn(), text, { mode: 0o440 });
        const r = await run(withFlag());
        expect(r.status).toEqual({ dropIn: word, key: "installed" });
        expect(readFileSync(dropIn(), "utf8")).toBe(word === "present" ? text : RULE);
        expect(readdirSync(s.sudoersDir)).toEqual(["harpoc-1000"]);
      },
    );

    it("a sudo that asks for no password: the password line does not reach the root step's commands", async () => {
      s.set("sudo.mode", "nopasswd");
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
      expect(r.log).toEqual([
        "id -u stdin=0",
        "sudo read=none",
        `visudo -c -f ${s.dir}/sudoers.d/harpoc-1000.tmp stdin=0`,
        `visudo -c -f ${s.dir}/sudoers stdin=0`,
      ]);
    });

    it.each([
      ["outside-after", "outside-after", false],
      ["outside-before", "outside-before", true],
      ["a wrong password", "password", false],
    ] as const)(
      "both ways a sudo refuses, and a wrong password: %s",
      async (_label, sudoMode, unread) => {
        s.set("sudo.mode", sudoMode);
        if (sudoMode === "password") s.set("sudo.password", drawFrame());
        const r = await run(withFlag());
        expect(r.status).toEqual({ dropIn: "refused", key: "not_attempted" });
        expect(existsSync(sshDir())).toBe(false);
        expect(readdirSync(s.sudoersDir)).toEqual([]);
        expect(r.log).toEqual([
          "id -u stdin=0",
          unread ? "sudo read=none" : `sudo read=${String(s.password.length)}`,
        ]);
      },
    );

    it("a temporary file visudo refuses", async () => {
      s.set("visudo.file", "1");
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "refused", key: "not_attempted" });
      expect(readdirSync(s.sudoersDir)).toEqual([]);
      expect(existsSync(sshDir())).toBe(false);
    });

    it("a whole configuration visudo refuses: the drop-in is removed again", async () => {
      s.set("visudo.whole", "1");
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "refused", key: "not_attempted" });
      expect(readdirSync(s.sudoersDir)).toEqual([]);
      expect(existsSync(sshDir())).toBe(false);
    });

    it.each(["", "0", "00", "010", "abc", "10 0", "-1"])(
      "a SUDO_UID that is no number: %j",
      async (uid) => {
        s.set("sudo.uid", uid);
        const r = await run(withFlag());
        expect(r.status).toEqual({ dropIn: "refused", key: "not_attempted" });
        expect(readdirSync(s.sudoersDir)).toEqual([]);
        expect(r.log.some((line) => line.startsWith("visudo"))).toBe(false);
      },
    );

    it("a stale temporary file is replaced", async () => {
      writeFileSync(`${dropIn()}.tmp`, "other text\n", { mode: 0o600 });
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
      expect(readdirSync(s.sudoersDir)).toEqual(["harpoc-1000"]);
      expect(readFileSync(dropIn(), "utf8")).toBe(RULE);
    });

    it("a user who is root starts no sudo", async () => {
      s.set("id.uid", "0");
      const r = await run(withFlag());
      expect(r.status).toEqual({ dropIn: "present", key: "installed" });
      expect(r.log).toEqual(["id -u stdin=0"]);
      expect(readdirSync(s.sudoersDir)).toEqual([]);
    });

    it("every program after the reads has the null device", async () => {
      const r = await run(Buffer.concat([withFlag(), Buffer.from("a fourth line\n")]));
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
      expect(r.log[0]).toBe("id -u stdin=0");
    });

    it.each([
      ["another prefix", (f: string) => `harpoc-bootstrap-v2 ${f} key\n`],
      ["another mode word", (f: string) => `${PREFIX} ${f} keys\n`],
      ["no mode word", (f: string) => `${PREFIX} ${f}\n`],
      ["a fourth word", (f: string) => `${PREFIX} ${f} key key\n`],
      ["23 characters", (f: string) => `${PREFIX} ${f.slice(1)} key\n`],
      ["a + in the part", (f: string) => `${PREFIX} +${f.slice(1)} key\n`],
      ["a * in the part", (f: string) => `${PREFIX} *${f.slice(1)} key\n`],
      ["two blanks", (f: string) => `${PREFIX} ${f}  key\n`],
      ["a leading blank", (f: string) => ` ${PREFIX} ${f} key\n`],
      ["the part and the mode word without the prefix", (f: string) => `${f} key\n`],
    ])("a framing line the script does not accept: %s", async (_label, framing) => {
      const r = await run(Buffer.from(`${framing(frame)}${key}\n`));
      expect(r.stdout).toBe(FRAMELESS);
      expect(r.status).toBeNull();
      expect(existsSync(sshDir())).toBe(false);
      expect(r.log).toEqual([]);
    });

    it.each([
      ["no line feed", (f: string) => `${PREFIX} ${f} key`],
      ["the empty input", () => ""],
    ])("a framing line the script does not accept: %s", async (_label, input) => {
      const r = await run(Buffer.from(input(frame)));
      expect(r.stdout).toBe(FRAMELESS);
      expect(r.status).toBeNull();
      expect(existsSync(sshDir())).toBe(false);
      expect(r.log).toEqual([]);
    });

    it.each(
      ["IFS= read -r x; ", "IFS= read -r x; IFS= read -r x; ", "/bin/cat >/dev/null; "].flatMap(
        (startup) => [[startup, "without the flag"] as const, [startup, "with the flag"] as const],
      ),
    )("an input a start-up file shortened: %j, %s", async (startup, flag) => {
      const input = flag === "with the flag" ? withFlag() : bootstrapStdin(frame, key);
      const r = await run(input, { startup });
      expect(r.stdout).toBe(FRAMELESS);
      expect(existsSync(sshDir())).toBe(false);
      expect(readdirSync(s.sudoersDir)).toEqual([]);
      expect(r.log).toEqual([]);
    });

    it("text a start-up file printed without a line feed", async () => {
      const r = await run(bootstrapStdin(frame, key), { startup: 'printf "Welcome to host"; ' });
      expect(r.stdout).toBe(`Welcome to host\n${PREFIX} ${frame} not_asked installed\n`);
    });

    it.each([
      ["an option in front", (k: string) => `no-pty ${k}`],
      ["a comment", (k: string) => `${k} me@host`],
      ["a second field", (k: string) => `${k} ${k.slice(12, 40)}`],
      ["ssh-dss", (k: string) => `ssh-dss ${k.slice(12)}`],
      ["the type alone", () => "ssh-ed25519"],
      ["an empty field", () => "ssh-ed25519 "],
      ["a * in the field", (k: string) => `${k.slice(0, 40)}*${k.slice(40)}`],
      ["a leading blank", (k: string) => ` ${k}`],
      ["a trailing blank", (k: string) => `${k} `],
      ["the password as the key line", (_k: string, password: string) => password],
    ])("a key line the script does not accept: %s", async (_label, make) => {
      const input = bootstrapStdin(frame, make(key, s.password), Buffer.from(s.password));
      const r = await run(input);
      expect(r.stdout).toBe(`\n${PREFIX} ${frame} not_attempted not_attempted\n`);
      expect(r.status).toEqual({ dropIn: "not_attempted", key: "not_attempted" });
      expect(existsSync(sshDir())).toBe(false);
      expect(r.log).toEqual([]);
    });

    it.each([
      ["without a password line", ""],
      ["with an empty one", "\n"],
    ])("the flag without a password line, and with an empty one: %s", async (_label, third) => {
      const r = await run(Buffer.from(`${PREFIX} ${frame} sudoers\n${key}\n${third}`));
      expect(r.status).toEqual({ dropIn: "not_attempted", key: "not_attempted" });
      expect(existsSync(sshDir())).toBe(false);
      expect(r.log).toEqual([]);
    });

    it("an authorized_keys without a final line feed", async () => {
      keysBefore(OTHER_KEY);
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(readFileSync(keysFile(), "utf8")).toBe(`${OTHER_KEY}\n${key}\n`);
    });

    it.each([
      ["the last line without a line feed", (k: string) => `${OTHER_KEY}\n${k}`],
      ["with a comment behind a space", (k: string) => `${k} me@host\n`],
      ["with a comment behind a tab", (k: string) => `${k}\tme@host\n`],
    ])("a key that is there is left: %s", async (_label, make) => {
      keysBefore(make(key));
      const before = readFileSync(keysFile());
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "present" });
      expect(readFileSync(keysFile()).equals(before)).toBe(true);
    });

    it.each([
      ["behind an option", (k: string) => `no-pty ${k}\n`],
      ["a longer key", (k: string) => `${k}AAAA\n`],
    ])("a key behind an option, and a longer key, are not the key: %s", async (_label, make) => {
      const text = make(key);
      keysBefore(text);
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(readFileSync(keysFile(), "utf8")).toBe(`${text}${key}\n`);
    });

    it("an authorized_keys with carriage returns: the key behind CR LF line ends is not the key", async () => {
      const text = `${OTHER_KEY}\r\n${key}\r\n`;
      keysBefore(text);
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(readFileSync(keysFile(), "utf8")).toBe(`${text}${key}\n`);
    });

    it("a file of 50 000 lines is read twice within the deadline", async () => {
      const lines = Array.from(
        { length: 50_000 },
        () => `ssh-ed25519 ${randomBytes(24).toString("base64")}\n`,
      ).join("");
      keysBefore(lines);
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(readFileSync(keysFile(), "utf8")).toBe(`${lines}${key}\n`);
    });

    it("the modes are tightened", async () => {
      keysBefore(`${OTHER_KEY}\n`);
      chmodSync(sshDir(), 0o755);
      chmodSync(keysFile(), 0o644);
      const r = await run(bootstrapStdin(frame, key));
      expect(r.status).toEqual({ dropIn: "not_asked", key: "installed" });
      expect(mode(sshDir())).toBe(0o700);
      expect(mode(keysFile())).toBe(0o600);
    });

    it.each([
      ["authorized_keys a directory", "dir"],
      [".ssh a file", "file"],
      ["HOME handed as rel", "relative"],
    ] as const)("a file that cannot be written is failed: %s", async (_label, kind) => {
      if (kind === "dir") mkdirSync(keysFile(), { recursive: true });
      if (kind === "file") writeFileSync(sshDir(), "");
      const r = await run(
        bootstrapStdin(frame, key),
        kind === "relative" ? { home: "rel", startup: `cd ${s.dir}; ` } : {},
      );
      expect(r.status).toEqual({ dropIn: "not_asked", key: "failed" });
      expect(existsSync(join(s.dir, "rel"))).toBe(false);
    });

    it.each([
      ["a leading and a trailing blank", (r: string) => ` ${r} `],
      ["one beginning -n ", (r: string) => `-n ${r}`],
      ["one holding \\c%s\\\\", (r: string) => `${r}\\c%s\\\\`],
    ])("the password reaches sudo byte for byte: %s", async (_label, make) => {
      const password = make(drawFrame());
      s.set("sudo.password", password);
      const r = await run(withFlag(password), { secret: password });
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
    });

    it("the script uses its own PATH", async () => {
      const planted = join(s.dir, "planted");
      mkdirSync(planted);
      writeFileSync(join(planted, "sudo"), `#!/bin/sh\necho planted >>"${s.dir}/log"\n`, {
        mode: 0o755,
      });
      chmodSync(join(planted, "sudo"), 0o755);
      const r = await run(withFlag(), {
        startup: `PATH=${planted}:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; `,
      });
      expect(r.status).toEqual({ dropIn: "written", key: "installed" });
      expect(r.log.includes("planted")).toBe(false);
    });
  },
);
