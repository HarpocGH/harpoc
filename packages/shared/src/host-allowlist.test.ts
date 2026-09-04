import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "./errors.js";
import {
  assertBindAllowed,
  buildAllowedHostSet,
  checkRequestHost,
  isLoopbackBindHost,
  LOOPBACK_BIND_HOSTS,
  normalizeAllowedHost,
  parseHostHeader,
  parseOriginHeader,
} from "./host-allowlist.js";

describe("isLoopbackBindHost", () => {
  it.each(["127.0.0.1", "::1", "localhost", "LOCALHOST", " 127.0.0.1 "])(
    "%j is loopback",
    (host) => {
      expect(isLoopbackBindHost(host)).toBe(true);
    },
  );

  it.each(["0.0.0.0", "::", "192.168.1.5", "vault.example", "", "127.0.0.2"])(
    "%j is not loopback",
    (host) => {
      expect(isLoopbackBindHost(host)).toBe(false);
    },
  );

  it("names exactly the three loopback forms", () => {
    expect([...LOOPBACK_BIND_HOSTS].sort()).toEqual(["127.0.0.1", "::1", "localhost"]);
  });
});

describe("normalizeAllowedHost", () => {
  it.each([
    ["Vault.Example", "vault.example"],
    [" vault.example ", "vault.example"],
    ["10.0.0.5", "10.0.0.5"],
    ["[::1]", "::1"],
    ["fe80::1", "fe80::1"],
    ["2001:db8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:1"],
  ])("%j → %j", (entry, expected) => {
    expect(normalizeAllowedHost(entry)).toBe(expected);
  });

  it.each([
    "",
    "vault.example:3000",
    "https://vault.example",
    "vault.example/path",
    "a b",
    "[::1",
    "-port",
    "--port",
  ])("%j is refused (a scheme, a path, a port, a leading hyphen or a stray character)", (entry) => {
    expect(normalizeAllowedHost(entry)).toBeNull();
  });
});

describe("parseHostHeader", () => {
  it.each([
    ["vault.example", "vault.example"],
    ["Vault.Example:3001", "vault.example"],
    ["127.0.0.1:3000", "127.0.0.1"],
    ["[::1]:3001", "::1"],
    ["[::1]", "::1"],
    ["localhost", "localhost"],
  ])("%j → %j", (value, expected) => {
    expect(parseHostHeader(value)).toBe(expected);
  });

  it.each([undefined, "", "vault.example:abc", "[::1", "evil.example/x", "a b", ":3000", "[::1]x"])(
    "%j is unparsable",
    (value) => {
      expect(parseHostHeader(value)).toBeNull();
    },
  );
});

describe("parseOriginHeader", () => {
  it.each([
    ["http://vault.example:3000", "vault.example"],
    ["https://Vault.Example", "vault.example"],
    ["https://[::1]:8443", "::1"],
    ["http://127.0.0.1:3001", "127.0.0.1"],
  ])("%j → %j", (value, expected) => {
    expect(parseOriginHeader(value)).toBe(expected);
  });

  it.each([undefined, "null", "not a url", "", 'foo://a"b', "foo:bar"])(
    "%j is unparsable",
    (value) => {
      expect(parseOriginHeader(value)).toBeNull();
    },
  );
});

describe("buildAllowedHostSet", () => {
  it("adds the loopback names on a loopback bind", () => {
    const set = buildAllowedHostSet("127.0.0.1", ["Vault.Example"]);
    expect([...set].sort()).toEqual(["127.0.0.1", "::1", "localhost", "vault.example"]);
  });

  it("holds exactly the entries on a non-loopback bind", () => {
    expect([...buildAllowedHostSet("0.0.0.0", ["vault.example", "[::1]"])].sort()).toEqual([
      "::1",
      "vault.example",
    ]);
  });

  it("a loopback bind with no entries allows the three loopback names", () => {
    expect([...buildAllowedHostSet("localhost", [])].sort()).toEqual([
      "127.0.0.1",
      "::1",
      "localhost",
    ]);
  });
});

describe("checkRequestHost", () => {
  const allowed = buildAllowedHostSet("127.0.0.1", ["vault.example"]);

  it("accepts an allowed Host with or without a port, and no Origin", () => {
    expect(checkRequestHost({ host: "vault.example:3000" }, allowed)).toEqual({
      ok: true,
    });
    expect(checkRequestHost({ host: "127.0.0.1:3000" }, allowed)).toEqual({
      ok: true,
    });
    expect(checkRequestHost({ host: "localhost" }, allowed)).toEqual({
      ok: true,
    });
  });

  it("refuses a missing, unparsable or unlisted Host, naming the parsed hostname only", () => {
    expect(checkRequestHost({}, allowed)).toEqual({
      ok: false,
      header: "Host",
      hostname: null,
    });
    expect(checkRequestHost({ host: "a b" }, allowed)).toEqual({
      ok: false,
      header: "Host",
      hostname: null,
    });
    expect(checkRequestHost({ host: "evil.example:3000" }, allowed)).toEqual({
      ok: false,
      header: "Host",
      hostname: "evil.example",
    });
  });

  it("checks Origin only when present, against the same set", () => {
    expect(
      checkRequestHost({ host: "vault.example", origin: "https://vault.example" }, allowed),
    ).toEqual({ ok: true });
    expect(
      checkRequestHost({ host: "vault.example", origin: "http://evil.example" }, allowed),
    ).toEqual({
      ok: false,
      header: "Origin",
      hostname: "evil.example",
    });
    expect(checkRequestHost({ host: "vault.example", origin: "null" }, allowed)).toEqual({
      ok: false,
      header: "Origin",
      hostname: null,
    });
    // A non-special scheme's authority is barely validated by `URL`, so the
    // hostname is gated by the same character class as `Host` — the refusal
    // reports no hostname rather than carrying `a"b` into the 403.
    expect(checkRequestHost({ host: "vault.example", origin: 'foo://a"b' }, allowed)).toEqual({
      ok: false,
      header: "Origin",
      hostname: null,
    });
  });
});

describe("assertBindAllowed", () => {
  it("refuses a non-loopback bind with no allowed host", () => {
    expect(() => assertBindAllowed("0.0.0.0", [])).toThrow(VaultError);
    try {
      assertBindAllowed("0.0.0.0", []);
    } catch (err) {
      expect((err as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
      expect((err as VaultError).message).toBe(
        "A non-loopback bind (0.0.0.0) requires --allowed-host <name> naming every host name clients use to reach this listener (repeatable); loopback binds allow 127.0.0.1, ::1 and localhost automatically",
      );
    }
  });

  it("refuses an invalid entry on any bind", () => {
    try {
      assertBindAllowed("127.0.0.1", ["vault.example:3000"]);
      expect.unreachable("must throw");
    } catch (err) {
      expect((err as VaultError).code).toBe(ErrorCode.INVALID_INPUT);
      expect((err as VaultError).message).toBe(
        'Invalid allowed host "vault.example:3000": a host name or IP address, without scheme, path or port',
      );
    }
  });

  it("accepts a non-loopback bind with an entry, and a loopback bind with none", () => {
    expect(() => assertBindAllowed("0.0.0.0", ["vault.example"])).not.toThrow();
    expect(() => assertBindAllowed("127.0.0.1", [])).not.toThrow();
    expect(() => assertBindAllowed("::1", ["extra.example"])).not.toThrow();
  });
});
