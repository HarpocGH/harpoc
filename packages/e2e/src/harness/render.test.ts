import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { PLANTED, RENDER_TARGET, parseRemoteEntry, parseRenderAddress } from "./render.js";

const FLEET_UP = "run: pnpm --filter @harpoc/e2e fleet:up";
const SUM = createHash("sha256").update(PLANTED).digest("hex");

describe("the render target's readers", () => {
  it("names sshd-pinned's sftp-server as the harpoc login reaches it, port 2222", () => {
    expect(RENDER_TARGET).toStrictEqual({
      service: "sshd-pinned",
      port: 2222,
      user: "harpoc",
      dir: "/home/harpoc/render",
    });
  });

  it.each([
    [
      "a regular file",
      `regular file:600:harpoc:10\n${SUM}\n`,
      { kind: "file", mode: "600", owner: "harpoc", size: 10, sha256: SUM },
    ],
    [
      "an empty regular file",
      `regular empty file:644:harpoc:0\n${SUM}\n`,
      { kind: "file", mode: "644", owner: "harpoc", size: 0, sha256: SUM },
    ],
    [
      "a link, with CRLF line ends",
      "symbolic link:777:harpoc:30\r\n-\r\n",
      { kind: "link", mode: "777", owner: "harpoc", size: 30, sha256: null },
    ],
    [
      "a directory",
      "directory:755:harpoc:4096\n-\n",
      { kind: "directory", mode: "755", owner: "harpoc", size: 4096, sha256: null },
    ],
    ["nothing", "-\n-\n", { kind: "none", mode: "", owner: "", size: 0, sha256: null }],
  ])("parseRemoteEntry reads the fixed text's two lines for %s", (_what, text, entry) => {
    expect(parseRemoteEntry(text)).toStrictEqual(entry);
  });

  it.each([
    ["a third type", "socket:755:harpoc:0\n-\n"],
    ["a third line", `regular file:600:harpoc:10\n${SUM}\nextra\n`],
    ["one line", "regular file:600:harpoc:10\n"],
    ["a file without its sum", "regular file:600:harpoc:10\n-\n"],
    ["a sum beside a directory", `directory:755:harpoc:4096\n${SUM}\n`],
    ["a sum beside nothing", `-\n${SUM}\n`],
    ["a mode that is not octal", `regular file:6x0:harpoc:10\n${SUM}\n`],
    ["no owner", `regular file:600::10\n${SUM}\n`],
    ["a size that is not a number", `regular file:600:harpoc:ten\n${SUM}\n`],
    ["a fifth field", `regular file:600:harpoc:10:x\n${SUM}\n`],
  ])("parseRemoteEntry throws on %s", (_what, text) => {
    expect(() => parseRemoteEntry(text)).toThrow("unexpected remote entry");
  });

  it("renderAddress's parse takes the first plain dotted IPv4 of the inspect line", () => {
    expect(parseRenderAddress("172.18.0.4 ")).toBe("172.18.0.4");
    expect(parseRenderAddress("fd00::4 10.89.0.7 172.18.0.4 \n")).toBe("10.89.0.7");
  });

  it.each([
    ["an empty line", ""],
    ["blanks alone", "  \n"],
    ["an IPv6 address alone", "fd00::4 "],
    ["an octet over 255", "172.18.0.256 "],
    ["a leading zero", "172.18.0.04 "],
    ["three octets", "172.18.4 "],
  ])("renderAddress's parse refuses %s with the fleet's recovery", (_what, text) => {
    expect(() => parseRenderAddress(text)).toThrow(FLEET_UP);
  });
});
