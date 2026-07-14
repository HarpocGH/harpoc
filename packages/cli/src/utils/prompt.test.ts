import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { promptConfirm, promptHidden } from "./prompt.js";

function sink(): PassThrough {
  return new PassThrough();
}

describe("promptHidden", () => {
  it("resolves a single-chunk line including its newline (piped stdin)", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.write("hunter2\n");
    await expect(p).resolves.toBe("hunter2");
  });

  it("resolves a CRLF-terminated line", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.write("hunter2\r\n");
    await expect(p).resolves.toBe("hunter2");
  });

  it("pushes back input after the terminator for the next prompt", async () => {
    const input = new PassThrough();
    const first = promptHidden("1: ", input, sink());
    input.write("alpha\nbeta\n");
    await expect(first).resolves.toBe("alpha");
    const second = promptHidden("2: ", input, sink());
    await expect(second).resolves.toBe("beta");
  });

  it("pushes back across CRLF pairs", async () => {
    const input = new PassThrough();
    const first = promptHidden("1: ", input, sink());
    input.write("alpha\r\nbeta\r\n");
    await expect(first).resolves.toBe("alpha");
    const second = promptHidden("2: ", input, sink());
    await expect(second).resolves.toBe("beta");
  });

  it("treats EOF as the line terminator", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.end("partial");
    await expect(p).resolves.toBe("partial");
  });

  it("resolves empty on immediate EOF instead of dangling", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.end();
    await expect(p).resolves.toBe("");
  });

  it("a prompt after EOF resolves empty instead of hanging", async () => {
    const input = new PassThrough();
    const first = promptHidden("1: ", input, sink());
    input.end("only\n");
    await expect(first).resolves.toBe("only");
    const second = promptHidden("2: ", input, sink());
    await expect(second).resolves.toBe("");
  });

  it("assembles per-character chunks (TTY-style delivery)", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    for (const ch of ["a", "b", "c"]) {
      input.write(ch);
    }
    input.write("\r");
    await expect(p).resolves.toBe("abc");
  });

  it("applies backspace within a chunk", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.write("abcd\x7f\x7f\n");
    await expect(p).resolves.toBe("ab");
  });

  it("rejects on Ctrl+C", async () => {
    const input = new PassThrough();
    const p = promptHidden("pw: ", input, sink());
    input.write("ab\x03");
    await expect(p).rejects.toThrow("User cancelled");
  });

  it("writes the prompt to the output stream, never the value", async () => {
    const input = new PassThrough();
    const out = sink();
    let seen = "";
    out.on("data", (d: Buffer) => {
      seen += d.toString("utf8");
    });
    const p = promptHidden("Secret value: ", input, out);
    input.write("super-hidden\n");
    await p;
    expect(seen).toContain("Secret value: ");
    expect(seen).not.toContain("super-hidden");
  });

  it("never echoes typed characters when the output is a TTY", async () => {
    const input = new PassThrough() as PassThrough & {
      isTTY: boolean;
      setRawMode: (mode: boolean) => unknown;
    };
    input.isTTY = true;
    input.setRawMode = () => input;
    const out = sink() as PassThrough & { isTTY: boolean };
    out.isTTY = true;
    let seen = "";
    out.on("data", (d: Buffer) => {
      seen += d.toString("utf8");
    });
    const p = promptHidden("Password: ", input, out);
    for (const ch of ["h", "u", "n", "t", "e", "r", "2"]) {
      input.write(ch);
    }
    input.write("\r");
    await expect(p).resolves.toBe("hunter2");
    expect(seen).toContain("Password: ");
    expect(seen).not.toContain("hunter2");
    expect(seen.replace("Password: ", "").replace(/\r?\n/g, "")).toBe("");
  });
});

describe("promptConfirm", () => {
  it("resolves true for a newline-terminated y", async () => {
    const input = new PassThrough();
    const p = promptConfirm("Delete?", input, sink());
    input.write("y\n");
    await expect(p).resolves.toBe(true);
  });

  it("is case-insensitive and trims whitespace", async () => {
    const input = new PassThrough();
    const p = promptConfirm("Delete?", input, sink());
    input.write(" Y \r\n");
    await expect(p).resolves.toBe(true);
  });

  it("resolves false for n and for an empty line", async () => {
    const input = new PassThrough();
    const first = promptConfirm("1?", input, sink());
    input.write("n\n\n");
    await expect(first).resolves.toBe(false);
    const second = promptConfirm("2?", input, sink());
    await expect(second).resolves.toBe(false);
  });

  it("treats EOF as the line terminator: piped y without newline confirms", async () => {
    const input = new PassThrough();
    const p = promptConfirm("Delete?", input, sink());
    input.end("y");
    await expect(p).resolves.toBe(true);
  });

  it("settles false on immediate EOF instead of dangling", async () => {
    const input = new PassThrough();
    const p = promptConfirm("Delete?", input, sink());
    input.end();
    await expect(p).resolves.toBe(false);
  });

  it("a prompt after EOF resolves false instead of hanging", async () => {
    const input = new PassThrough();
    const first = promptConfirm("1?", input, sink());
    input.end("y\n");
    await expect(first).resolves.toBe(true);
    const second = promptConfirm("2?", input, sink());
    await expect(second).resolves.toBe(false);
  });

  it("pushes back input after the terminator for the next prompt", async () => {
    const input = new PassThrough();
    const confirm = promptConfirm("Sure?", input, sink());
    input.write("y\nleftover\n");
    await expect(confirm).resolves.toBe(true);
    const next = promptHidden("pw: ", input, sink());
    await expect(next).resolves.toBe("leftover");
  });

  it("rejects on a stream error", async () => {
    const input = new PassThrough();
    const p = promptConfirm("Delete?", input, sink());
    input.destroy(new Error("boom"));
    await expect(p).rejects.toThrow("boom");
  });

  it("writes the prompt with the [y/N] hint to the output stream", async () => {
    const input = new PassThrough();
    const out = sink();
    let seen = "";
    out.on("data", (d: Buffer) => {
      seen += d.toString("utf8");
    });
    const p = promptConfirm("Delete secret x?", input, out);
    input.write("y\n");
    await p;
    expect(seen).toContain("Delete secret x? [y/N] ");
  });
});
