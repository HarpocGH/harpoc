import { describe, expect, it } from "vitest";
import { DEDICATED_CONTEXT_BINARIES, dedicatedContextForBinary } from "./dedicated-contexts.js";
import { knownInterpreterName } from "./interpreters.js";
import { normalizeBinaryBasename } from "./binary-name.js";

describe("dedicatedContextForBinary", () => {
  it("maps git and ssh to their dedicated contexts", () => {
    expect(dedicatedContextForBinary("git")).toBe("git");
    expect(dedicatedContextForBinary("ssh")).toBe("ssh");
  });

  it("matches absolute paths on both separator styles", () => {
    expect(dedicatedContextForBinary("/usr/bin/git")).toBe("git");
    expect(dedicatedContextForBinary("C:\\Program Files\\Git\\cmd\\git.exe")).toBe("git");
    expect(dedicatedContextForBinary("C:\\Windows\\System32\\OpenSSH\\ssh.exe")).toBe("ssh");
  });

  it("matches case-insensitively and strips executable extensions", () => {
    expect(dedicatedContextForBinary("GIT.EXE")).toBe("git");
    expect(dedicatedContextForBinary("Ssh.exe")).toBe("ssh");
  });

  it("leaves sibling tools alone — only the driver binaries have dedicated contexts", () => {
    for (const sibling of [
      "ssh-keygen",
      "ssh-agent",
      "ssh-add",
      "sshd",
      "git-upload-pack",
      "git-receive-pack",
      "gitk",
    ]) {
      expect(dedicatedContextForBinary(sibling)).toBeNull();
    }
  });

  it("returns null for ordinary binaries the process context may run", () => {
    for (const ordinary of ["node", "curl", "aws", "kubectl", "psql", "rsync"]) {
      expect(dedicatedContextForBinary(ordinary)).toBeNull();
    }
  });

  it("does not claim interpreters — those are the acknowledgement gate's business", () => {
    for (const interpreter of ["bash", "sh", "node", "npx", "python3", "env"]) {
      expect(dedicatedContextForBinary(interpreter)).toBeNull();
      expect(knownInterpreterName(interpreter)).not.toBeNull();
    }
  });

  it("keeps the two gates on one basename derivation (drift guard)", () => {
    // Both gates classify allowlist entries by basename; if the shared
    // normalization changed shape, one gate could see a name the other misses.
    for (const entry of ["/usr/bin/GIT.EXE", "C:\\tools\\Python3.12.EXE", "  ssh  "]) {
      expect(dedicatedContextForBinary(entry)).toBe(
        DEDICATED_CONTEXT_BINARIES.get(normalizeBinaryBasename(entry)) ?? null,
      );
    }
    expect(normalizeBinaryBasename("C:\\tools\\Python3.12.EXE")).toBe("python");
    expect(knownInterpreterName("C:\\tools\\Python3.12.EXE")).toBe("python");
  });
});
