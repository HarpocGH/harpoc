import { describe, expect, it } from "vitest";
import { BOOTSTRAP_REMOTE_COMMAND } from "../ssh-injector-bootstrap-script.js";
import { standInCommand } from "./bootstrap-standins.js";

const DIR = "/tmp/harpoc-bootstrap-Ab1_.-";
const TEXTS = [
  "PATH=/usr/sbin:/usr/bin:/sbin:/bin;",
  "D=/etc/sudoers.d;",
  "visudo -c -f /etc/sudoers ||",
] as const;

function count(text: string, part: string): number {
  return text.split(part).length - 1;
}

describe("standInCommand", () => {
  it("the three texts are replaced", () => {
    const command = standInCommand(BOOTSTRAP_REMOTE_COMMAND, DIR);
    expect(count(command, `PATH=${DIR}/bin:/usr/sbin:/usr/bin:/sbin:/bin;`)).toBe(2);
    expect(count(command, `D=${DIR}/sudoers.d;`)).toBe(1);
    expect(count(command, `visudo -c -f ${DIR}/sudoers ||`)).toBe(1);
    expect(command.includes("/etc/")).toBe(false);
    expect(
      command
        .split(`PATH=${DIR}/bin:`)
        .join("PATH=")
        .split(`D=${DIR}/sudoers.d;`)
        .join("D=/etc/sudoers.d;")
        .split(`-f ${DIR}/sudoers ||`)
        .join("-f /etc/sudoers ||"),
    ).toBe(BOOTSTRAP_REMOTE_COMMAND);
  });

  it.each(TEXTS)("a text that is missing or doubled is refused: %s", (text) => {
    expect(() => standInCommand(BOOTSTRAP_REMOTE_COMMAND.replace(text, ""), DIR)).toThrow(
      /occurs \d+ times/,
    );
    expect(() => standInCommand(BOOTSTRAP_REMOTE_COMMAND.replace(text, text + text), DIR)).toThrow(
      /occurs \d+ times/,
    );
  });

  it("a command that still names /etc/ is refused", () => {
    expect(() => standInCommand(`${BOOTSTRAP_REMOTE_COMMAND} /etc/passwd`, DIR)).toThrow(
      "still names /etc/",
    );
  });

  it.each(["/tmp/harpoc bootstrap", "/tmp/harpoc$bootstrap"])(
    "a directory with a blank or a $ is refused: %j",
    (dir) => {
      expect(() => standInCommand(BOOTSTRAP_REMOTE_COMMAND, dir)).toThrow("outside A-Z a-z 0-9");
    },
  );
});
