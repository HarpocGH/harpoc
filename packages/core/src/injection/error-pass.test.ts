import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError, echoField, echoHandle, recordOf } from "@harpoc/shared";
import { expectAbsent } from "@harpoc/test-utils";
import { leaveError, leaveFixed, passError } from "./error-pass.js";
import { outside } from "./output-sanitizer.js";

const PW_FIXTURE = "pw-fixture-k2q9";

const urlError = (action: unknown): VaultError =>
  VaultError.urlNotAllowed(echoField(action, "url"));

describe("passError", () => {
  it("a recorded error passes an injector's pass as itself", () => {
    const e = VaultError.vaultLocked();

    expect(Object.is(passError(e, ["e"]), e)).toBe(true);
  });

  it("an unrecorded error is redacted whole with the whole list", () => {
    const e = new VaultError(ErrorCode.DB_QUERY_FAILED, `user bob, password ${PW_FIXTURE}`);

    const out = passError(e, [PW_FIXTURE, "bob"]) as VaultError;

    expectAbsent(out.message, PW_FIXTURE);
    expect(out.message).toBe("user [REDACTED], password [REDACTED]");
  });

  it("a recorded error built anew from its code and message is redacted whole", () => {
    const e = VaultError.secretRevoked(echoHandle("secret://x"));
    const copy = new VaultError(e.code, e.message);

    expect(recordOf(copy)).toBeUndefined();
    expect((passError(copy, ["x"]) as VaultError).message).toBe(
      "Secret revoked: secret://[REDACTED]",
    );
  });
});

describe("leaveError", () => {
  it("the choke point writes a recorded error from its record", () => {
    const e = VaultError.urlNotAllowed(echoField({ url: "derived" }, "url"));

    const out = leaveError(e, ["e"], { action: { url: "https://x/e" } });

    expect(out.message).toBe("URL not in secret allowlist: https://x/e");
    expect(out.code).toBe(ErrorCode.URL_NOT_ALLOWED);
    expect(recordOf(out)).toBeUndefined();
  });

  it.each(["a", "c", "d", "e", "t", "secret", "RED"])(
    "the vault's own words are not scanned: %s",
    (v) => {
      const e = VaultError.secretRevoked(echoHandle("secret://x"));

      expect(leaveError(e, [v], { handle: "secret://x" }).message).toBe(
        "Secret revoked: secret://x",
      );
    },
  );

  it("a field that is gone leaves the fixed word", () => {
    expect(leaveError(urlError({ url: "derived" }), ["e"], { action: {} }).message).toBe(
      "URL not in secret allowlist: [unreadable]",
    );
  });

  it.each([42, null, ["https://x/e"], { href: "https://x/e" }])(
    "a quoted field that is no string leaves the fixed word: %j",
    (url) => {
      expect(leaveError(urlError({ url: "derived" }), ["e"], { action: { url } }).message).toBe(
        "URL not in secret allowlist: [unreadable]",
      );
    },
  );

  it("an empty quoted field leaves today's text without a suffix", () => {
    const action = { url: "" };

    expect(leaveError(urlError(action), ["e"], { action }).message).toBe(
      "URL not in secret allowlist",
    );
  });

  it("a quoted field of 10 MiB leaves as sent, with no scan of it", () => {
    const action = { url: `https://x/${"e".repeat(10 * 1024 * 1024)}` };

    const out = leaveError(urlError({ url: "derived" }), ["e"], { action });

    expect(out.message === `URL not in secret allowlist: ${action.url}`).toBe(true);
  });

  it("an error changed after its assembly leaves as it was assembled", () => {
    const e = urlError({ url: "derived" });
    (e as { message: string }).message = "forged";

    expect(leaveError(e, ["e"], { action: { url: "https://x/e" } }).message).toBe(
      "URL not in secret allowlist: https://x/e",
    );
  });

  it("a recorded error through an injector's pass and then the choke point is written from its record", () => {
    const e = VaultError.secretRevoked(echoHandle("secret://x"));

    const out = leaveError(passError(e, ["e"]) as VaultError, ["e"], { handle: "secret://x" });

    expect(out.message).toBe("Secret revoked: secret://x");
  });

  it.each(["e", "R", "RED"])(
    "an unrecorded error through an injector's pass and then the choke point keeps every marker whole: %s",
    (v) => {
      const u = new VaultError(ErrorCode.GIT_OPERATION_FAILED, `remote said ${v} and ${v}${v}`);

      const out = leaveError(passError(u, [v]) as VaultError, [v], {});

      expect(out.message.split("[REDACTED]").join("").includes("[")).toBe(false);
    },
  );

  it("two calls do not read each other's action", () => {
    const first = { url: "https://one.example/a" };
    const second = { url: "https://two.example/b" };
    const one = urlError(first);
    const two = urlError(second);
    const shared = urlError({ url: "derived" });

    expect(leaveError(two, ["e"], { action: second }).message).toBe(
      "URL not in secret allowlist: https://two.example/b",
    );
    expect(leaveError(one, ["e"], { action: first }).message).toBe(
      "URL not in secret allowlist: https://one.example/a",
    );
    expect(leaveError(shared, ["e"], { action: first }).message).toBe(
      "URL not in secret allowlist: https://one.example/a",
    );
    expect(leaveError(shared, ["e"], { action: second }).message).toBe(
      "URL not in secret allowlist: https://two.example/b",
    );
  });

  it("the choke point writes a recorded error's details from its record, leaf by leaf with the call", () => {
    const e = VaultError.mcpTimeout(echoField({ server: "derived-at-site" }, "server"));

    const out = leaveError(e, ["e"], { action: { server: "as-sent-e" } });

    expect(out.message).toBe("MCP tool call to server 'as-sent-e' timed out");
    expect(out.details).toStrictEqual({ server: "as-sent-e" });
    expect(recordOf(out)).toBeUndefined();
  });

  it("outside text is redacted there and nowhere else", () => {
    const e = VaultError.dbQueryFailed(outside(`server said ${PW_FIXTURE}`, [PW_FIXTURE]));

    const out = leaveError(e, ["a"], {});

    expectAbsent(out.message, PW_FIXTURE);
    expect(out.message).toBe("Database query failed: server said [REDACTED]");
  });
});

describe("leaveFixed", () => {
  it("on the two paths an unrecorded error leaves with its code and the fixed text", () => {
    const out = leaveFixed(new VaultError(ErrorCode.FS_ISOLATION_UNAVAILABLE, "x e y"), {});

    expect(out.code).toBe(ErrorCode.FS_ISOLATION_UNAVAILABLE);
    expect(out.message).toBe("the operation failed");
  });

  it("on the two paths a recorded error leaves from its record", () => {
    const e = VaultError.secretRevoked(echoHandle("secret://x"));

    const out = leaveFixed(e, { handle: "secret://y" });

    expect(out.code).toBe(ErrorCode.SECRET_REVOKED);
    expect(out.message).toBe("Secret revoked: secret://y");
    expect(recordOf(out)).toBeUndefined();
  });

  it("on the two paths a recorded error's details leave from its record, leaf by leaf with the call", () => {
    const e = VaultError.mcpTimeout(echoField({ server: "derived-at-site" }, "server"));

    const out = leaveFixed(e, { action: { server: "as-sent-e" } });

    expect(out.code).toBe(ErrorCode.MCP_TIMEOUT);
    expect(out.details).toStrictEqual({ server: "as-sent-e" });
    expect(recordOf(out)).toBeUndefined();
  });
});
