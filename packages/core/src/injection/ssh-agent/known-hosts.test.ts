import { describe, expect, it } from "vitest";
import { fixtureKnownHostsLine, fixturePublicBlob } from "../__fixtures__/agent-client.js";
import { hostsForHostKey, matchKnownHostsLine } from "./known-hosts.js";

const KEY = fixturePublicBlob("ecdsa256_openssh");
const OTHER = fixturePublicBlob("ed25519_openssh");
const line = (hosts: string): string => fixtureKnownHostsLine("ecdsa256_openssh", hosts);

describe("matchKnownHostsLine — the concrete names a pinned line gives a bound host key", () => {
  it("a bare host", () => {
    expect(matchKnownHostsLine(line("git.example.com"), KEY)).toEqual([
      { host: "git.example.com" },
    ]);
  });

  it("a [host]:port name carries its port", () => {
    expect(matchKnownHostsLine(line("[127.0.0.1]:2222"), KEY)).toEqual([
      { host: "127.0.0.1", port: 2222 },
    ]);
  });

  it("an IPv6 literal in brackets", () => {
    expect(matchKnownHostsLine(line("[2001:db8::1]:22"), KEY)).toEqual([
      { host: "2001:db8::1", port: 22 },
    ]);
  });

  it("two names comma-joined (ssh-keyscan's host,address form)", () => {
    expect(matchKnownHostsLine(line("a.example,192.0.2.3"), KEY)).toEqual([
      { host: "a.example" },
      { host: "192.0.2.3" },
    ]);
  });

  it("keeps the pin's spelling (host_allowlist matching lowercases it)", () => {
    expect(matchKnownHostsLine(line("Git.Example.COM"), KEY)).toEqual([
      { host: "Git.Example.COM" },
    ]);
  });

  it("a CRLF-terminated line and a trailing comment", () => {
    expect(matchKnownHostsLine(`${line("a.example")} harpoc pin\r\n`, KEY)).toEqual([
      { host: "a.example" },
    ]);
  });

  it("a 4096-byte line (the schema's bound) still matches", () => {
    const base = `${line("a.example")} `;
    const full = base + "c".repeat(4096 - base.length);
    expect(full.length).toBe(4096);
    expect(matchKnownHostsLine(full, KEY)).toEqual([{ host: "a.example" }]);
  });

  it("an unpadded base64 key reads as the padded one", () => {
    const padded = line("a.example");
    expect(padded.endsWith("=")).toBe(true);
    expect(matchKnownHostsLine(padded.replace(/=+$/, ""), KEY)).toEqual([{ host: "a.example" }]);
  });

  it("skips the wildcard names of a line and keeps its concrete ones", () => {
    expect(matchKnownHostsLine(line("a.example,*.example,b?.example"), KEY)).toEqual([
      { host: "a.example" },
    ]);
  });

  it("a hashed pattern after a comma names nothing", () => {
    const hashed = "|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg=";
    expect(matchKnownHostsLine(line(`a.example,${hashed}`), KEY)).toEqual([{ host: "a.example" }]);
  });

  it.each([
    ["another key", line("a.example"), OTHER],
    [
      "a keytype field that does not name the key",
      line("a.example").replace("ecdsa-sha2-nistp256", "ssh-ed25519"),
      KEY,
    ],
    ["an @cert-authority line", `@cert-authority ${line("*.example")}`, KEY],
    ["an @revoked line", `@revoked ${line("a.example")}`, KEY],
    ["an unknown marker", `@trusted ${line("a.example")}`, KEY],
    ["a hashed name", line("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg="), KEY],
    ["a line holding a negation", line("a.example,!b.example"), KEY],
    ["a wildcard-only line", line("*"), KEY],
    ["a bracketed name without a port", line("[a.example]"), KEY],
    ["port 0", line("[a.example]:0"), KEY],
    ["port 65536", line("[a.example]:65536"), KEY],
    ["a stray bracket", line("a.example]"), KEY],
    ["a comment line", `# ${line("a.example")}`, KEY],
    ["an empty line", "", KEY],
    ["a line without a key", "a.example ecdsa-sha2-nistp256", KEY],
    ["a key that is not base64", "a.example ecdsa-sha2-nistp256 not*base64", KEY],
  ])("gives no name for %s", (_label, text, key) => {
    expect(matchKnownHostsLine(text, key)).toEqual([]);
  });
});

describe("hostsForHostKey — over a secret's pin list", () => {
  it("collects every line's names in pin order, each once", () => {
    const lines = [
      fixtureKnownHostsLine("ed25519_openssh", "other.example"),
      line("a.example,[a.example]:2222"),
      line("A.EXAMPLE,b.example"),
    ];
    expect(hostsForHostKey(lines, KEY)).toEqual([
      { host: "a.example" },
      { host: "a.example", port: 2222 },
      { host: "b.example" },
    ]);
  });

  it("gives nothing when an @revoked line holds the key, whatever else the list pins", () => {
    expect(hostsForHostKey([line("a.example"), `@revoked ${line("old.example")}`], KEY)).toEqual(
      [],
    );
  });

  it("gives nothing for a key no line pins", () => {
    expect(hostsForHostKey([line("a.example")], OTHER)).toEqual([]);
  });
});
