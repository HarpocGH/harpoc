import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import { injectionPolicyInputSchema } from "@harpoc/shared";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import { CreateSecretForm, DeleteForm, PolicyEditor, RotateForm } from "./secret-forms";

afterEach(cleanup);

/** What the create route answers (201) — not a SecretInfo. */
const created = { handle: "secret://n1", status: "created", message: "Secret created" };

const valueInput = () => screen.getByLabelText(/Value/) as HTMLInputElement;

describe("CreateSecretForm", () => {
  it("creates a secret, clears the value field, never echoes the value", async () => {
    const create = vi.fn().mockResolvedValue(created);
    const onDone = vi.fn();
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={onDone} />,
    );
    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.input(valueInput(), { target: { value: "s3cret-bytes" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    const body = create.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(body["name"]).toBe("n1");
    expect(body["type"]).toBe("api_key");
    // The wire takes base64, and the plaintext must not reach the request at all.
    expect(body["value"]).toBe("czNjcmV0LWJ5dGVz");
    await waitFor(() => expect(valueInput().value).toBe(""));
    expect(document.body.textContent).not.toContain("s3cret-bytes");
    expect(document.body.textContent).not.toContain("czNjcmV0LWJ5dGVz");
    expect(onDone).toHaveBeenCalled();
  });

  it("keeps the value input write-only", () => {
    render(
      <CreateSecretForm api={{ createSecret: vi.fn() } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    expect(valueInput().type).toBe("password");
    expect(valueInput().getAttribute("autocomplete")).toBe("off");
  });

  it("encodes a value bare btoa would reject", async () => {
    const create = vi.fn().mockResolvedValue(created);
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.input(valueInput(), { target: { value: "pässwörd✓" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect((create.mock.calls[0]?.[0] as Record<string, unknown>)["value"]).toBe(
      "cMOkc3N3w7ZyZOKckw==",
    );
  });

  it("omits value and project when they are blank (PENDING secret)", async () => {
    const create = vi.fn().mockResolvedValue(created);
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    const body = create.mock.calls[0]?.[0] as Record<string, unknown>;
    expect("value" in body).toBe(false);
    expect("project" in body).toBe(false);
  });

  it("sends the project when one is given", async () => {
    const create = vi.fn().mockResolvedValue(created);
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.input(screen.getByLabelText(/Project/), { target: { value: "myproj" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect((create.mock.calls[0]?.[0] as Record<string, unknown>)["project"]).toBe("myproj");
  });

  it("reads a file into the write-only value without echoing it or losing its newlines", async () => {
    const create = vi.fn().mockResolvedValue(created);
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    const pem = "-----BEGIN KEY-----\nline2\n-----END KEY-----";
    fireEvent.change(screen.getByLabelText(/Load from file/), {
      target: { files: [new File([pem], "key.pem", { type: "text/plain" })] },
    });
    await waitFor(() => expect(screen.getByText(/key\.pem/)).toBeTruthy());
    // A single-line input applies the HTML value-sanitization algorithm and
    // strips newlines, which would silently flatten a PEM into one unusable
    // line — so the file's text is held in state and the typed field steps
    // aside rather than displaying (and mangling) it.
    expect(valueInput().value).toBe("");
    expect(valueInput().disabled).toBe(true);
    expect(document.body.textContent).not.toContain("BEGIN KEY");

    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect((create.mock.calls[0]?.[0] as Record<string, unknown>)["value"]).toBe(
      "LS0tLS1CRUdJTiBLRVktLS0tLQpsaW5lMgotLS0tLUVORCBLRVktLS0tLQ==",
    );
    // Nothing of the file survives the submit — not the text, not the name.
    await waitFor(() => expect(screen.queryByText(/key\.pem/)).toBeNull());
    expect(valueInput().disabled).toBe(false);
  });

  it("returns the typed field when a loaded file is cleared", async () => {
    const create = vi.fn().mockResolvedValue(created);
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={vi.fn()} />,
    );
    fireEvent.change(screen.getByLabelText(/Load from file/), {
      target: { files: [new File(["from-file"], "key.pem", { type: "text/plain" })] },
    });
    await waitFor(() => expect(valueInput().disabled).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Clear file" }));
    expect(valueInput().disabled).toBe(false);

    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "n1" } });
    fireEvent.input(valueInput(), { target: { value: "typed" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect((create.mock.calls[0]?.[0] as Record<string, unknown>)["value"]).toBe("dHlwZWQ=");
  });

  it("renders the refusal and does not report done", async () => {
    const create = vi.fn().mockRejectedValue(new ApiError(400, "INVALID_INPUT", "Invalid name"));
    const onDone = vi.fn();
    render(
      <CreateSecretForm api={{ createSecret: create } as unknown as ApiClient} onDone={onDone} />,
    );
    fireEvent.input(screen.getByLabelText(/Name/), { target: { value: "bad name" } });
    fireEvent.input(valueInput(), { target: { value: "s3cret-bytes" } });
    fireEvent.submit(screen.getByRole("button", { name: "Create secret" }));
    await waitFor(() => expect(screen.getByText("Invalid name")).toBeTruthy());
    expect(document.querySelector(".error-text")?.textContent).toBe("Invalid name");
    expect(onDone).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("s3cret-bytes");
  });
});

describe("RotateForm", () => {
  const newValue = () => screen.getByLabelText(/New value/) as HTMLInputElement;

  it("submits write-only and clears the value", async () => {
    const rotate = vi.fn().mockResolvedValue({});
    render(
      <RotateForm
        api={{ rotateSecret: rotate } as unknown as ApiClient}
        handle="k1"
        onDone={vi.fn()}
      />,
    );
    fireEvent.input(newValue(), { target: { value: "v2-bytes" } });
    fireEvent.submit(screen.getByRole("button", { name: "Rotate" }));
    // base64 on the wire — the rotate route parses `value` with the same
    // base64-validated schema the create route uses.
    await waitFor(() => expect(rotate).toHaveBeenCalledWith("k1", "djItYnl0ZXM="));
    await waitFor(() => expect(newValue().value).toBe(""));
    expect(document.body.textContent).not.toContain("v2-bytes");
    expect(newValue().type).toBe("password");
    expect(newValue().getAttribute("autocomplete")).toBe("off");
  });

  it("encodes a non-Latin1 value as UTF-8 base64", async () => {
    const rotate = vi.fn().mockResolvedValue({});
    render(
      <RotateForm
        api={{ rotateSecret: rotate } as unknown as ApiClient}
        handle="k1"
        onDone={vi.fn()}
      />,
    );
    fireEvent.input(newValue(), { target: { value: "pässwörd✓" } });
    fireEvent.submit(screen.getByRole("button", { name: "Rotate" }));
    await waitFor(() => expect(rotate).toHaveBeenCalledWith("k1", "cMOkc3N3w7ZyZOKckw=="));
  });

  it("refuses to rotate to an empty value", () => {
    // `z.string().base64()` accepts the empty string, so an accidental empty
    // submit would irreversibly rotate the credential to zero bytes.
    render(
      <RotateForm
        api={{ rotateSecret: vi.fn() } as unknown as ApiClient}
        handle="k1"
        onDone={vi.fn()}
      />,
    );
    expect((screen.getByRole("button", { name: "Rotate" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    fireEvent.input(newValue(), { target: { value: "v2-bytes" } });
    expect((screen.getByRole("button", { name: "Rotate" }) as HTMLButtonElement).disabled).toBe(
      false,
    );
  });

  it("keeps the typed value and reports the refusal when the rotate fails", async () => {
    const rotate = vi.fn().mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "nope"));
    const onDone = vi.fn();
    render(
      <RotateForm
        api={{ rotateSecret: rotate } as unknown as ApiClient}
        handle="k1"
        onDone={onDone}
      />,
    );
    fireEvent.input(newValue(), { target: { value: "v2-bytes" } });
    fireEvent.submit(screen.getByRole("button", { name: "Rotate" }));
    await waitFor(() => expect(screen.getByText("nope")).toBeTruthy());
    expect(newValue().value).toBe("v2-bytes");
    expect(onDone).not.toHaveBeenCalled();
  });
});

describe("DeleteForm", () => {
  it("requires the typed name to match before deleting", async () => {
    const del = vi.fn().mockResolvedValue(undefined);
    render(
      <DeleteForm
        api={{ deleteSecret: del } as unknown as ApiClient}
        handle="k1"
        secretName="k1"
        onDone={vi.fn()}
      />,
    );
    const button = screen.getByRole("button", { name: "Delete secret" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText(/Type the name/), { target: { value: "wrong" } });
    expect(button.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText(/Type the name/), { target: { value: "k1" } });
    expect(button.disabled).toBe(false);
    fireEvent.submit(button);
    await waitFor(() => expect(del).toHaveBeenCalledWith("k1"));
  });

  it("confirms against the name, not the project-scoped handle", async () => {
    const del = vi.fn().mockResolvedValue(undefined);
    const onDone = vi.fn();
    render(
      <DeleteForm
        api={{ deleteSecret: del } as unknown as ApiClient}
        handle="myproj/k1"
        secretName="k1"
        onDone={onDone}
      />,
    );
    fireEvent.input(screen.getByLabelText(/Type the name/), { target: { value: "k1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Delete secret" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("myproj/k1"));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("renders the refusal", async () => {
    const del = vi.fn().mockRejectedValue(new ApiError(409, "SECRET_REVOKED", "already revoked"));
    render(
      <DeleteForm
        api={{ deleteSecret: del } as unknown as ApiClient}
        handle="k1"
        secretName="k1"
        onDone={vi.fn()}
      />,
    );
    fireEvent.input(screen.getByLabelText(/Type the name/), { target: { value: "k1" } });
    fireEvent.submit(screen.getByRole("button", { name: "Delete secret" }));
    await waitFor(() => expect(screen.getByText("already revoked")).toBeTruthy());
  });
});

describe("PolicyEditor", () => {
  it("submits the whole policy with acknowledge_interpreters when checked", async () => {
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{ response_mode: "filtered" }}
        onDone={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Acknowledge/));
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect(put.mock.calls[0]?.[0]).toBe("k1");
    const body = put.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body["acknowledge_interpreters"]).toBe(true);
    expect(body["response_mode"]).toBe("filtered");
    // Whole-policy PUT: every list the editor owns travels, empty or not.
    expect(body["url_allowlist"]).toEqual([]);
    expect(body["command_allowlist"]).toEqual([]);
    expect(body["host_allowlist"]).toEqual([]);
    expect(body["network_isolation"]).toBe(false);
    expect(body["fs_isolation"]).toBe(false);
  });

  it("unticks the acknowledgement after a successful save", async () => {
    // The waiver is a per-operation audited decision everywhere else (a CLI
    // flag per invocation, a request field per REST call). The editor now
    // survives a save, so a box left ticked would acknowledge the NEXT
    // interpreter addition without anyone deciding to.
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    const ack = () => screen.getByLabelText(/Acknowledge/) as HTMLInputElement;
    fireEvent.click(ack());
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
    expect((put.mock.calls[0]?.[1] as Record<string, unknown>)["acknowledge_interpreters"]).toBe(
      true,
    );

    await waitFor(() => expect(ack().checked).toBe(false));
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
    expect("acknowledge_interpreters" in (put.mock.calls[1]?.[1] as object)).toBe(false);
  });

  it("keeps the acknowledgement ticked when the save was refused", async () => {
    // Only success consumes the decision — a refused save is one the operator
    // is about to retry, and re-ticking a box they never got value from is
    // friction, not a decision.
    const put = vi.fn().mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "nope"));
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Acknowledge/));
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByText("nope")).toBeTruthy());
    expect((screen.getByLabelText(/Acknowledge/) as HTMLInputElement).checked).toBe(true);
  });

  it("omits the acknowledgement when the box is not ticked", async () => {
    const put = vi.fn().mockResolvedValue(undefined);
    const onDone = vi.fn();
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={onDone}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    expect("acknowledge_interpreters" in (put.mock.calls[0]?.[1] as object)).toBe(false);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("edits the lists as comma-separated text and the toggles as booleans", async () => {
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{ url_allowlist: ["a"], response_mode: "filtered" }}
        onDone={vi.fn()}
      />,
    );
    // The stored list arrives in the field rather than silently vanishing on save.
    expect((screen.getByLabelText(/URL allowlist/) as HTMLInputElement).value).toBe("a");
    fireEvent.input(screen.getByLabelText(/Command allowlist/), {
      target: { value: "/usr/bin/git, /bin/sh ," },
    });
    fireEvent.input(screen.getByLabelText(/Host allowlist/), { target: { value: "db.internal" } });
    fireEvent.change(screen.getByLabelText(/Response mode/), { target: { value: "status_only" } });
    fireEvent.click(screen.getByLabelText(/Network isolation/));
    fireEvent.click(screen.getByLabelText(/Filesystem isolation/));
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const body = put.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body["url_allowlist"]).toEqual(["a"]);
    expect(body["command_allowlist"]).toEqual(["/usr/bin/git", "/bin/sh"]);
    expect(body["host_allowlist"]).toEqual(["db.internal"]);
    expect(body["response_mode"]).toBe("status_only");
    expect(body["network_isolation"]).toBe(true);
    expect(body["fs_isolation"]).toBe(true);
  });

  it("resubmits the fields it does not edit rather than resetting them", async () => {
    // PUT replaces the whole policy, so a field the editor has no input for
    // would be wiped by a save that merely omitted it.
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{ env_allowlist: ["CI"], response_header_allowlist: ["x-request-id"] }}
        onDone={vi.fn()}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const body = put.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body["env_allowlist"]).toEqual(["CI"]);
    expect(body["response_header_allowlist"]).toEqual(["x-request-id"]);
  });

  it("resubmits the mail policy fields it does not edit (a PUT replaces the whole policy)", async () => {
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{ smtp_recipient_allowlist: ["*@corp.example"], imap_read_only: true }}
        onDone={vi.fn()}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const body = put.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body["smtp_recipient_allowlist"]).toEqual(["*@corp.example"]);
    expect(body["imap_read_only"]).toBe(true);
  });

  it("sends every injectionPolicyInputSchema key on save (drift pin)", async () => {
    const put = vi.fn().mockResolvedValue(undefined);
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(put).toHaveBeenCalled());
    const body = put.mock.calls[0]?.[1] as Record<string, unknown>;
    for (const key of Object.keys(injectionPolicyInputSchema.shape)) {
      expect(body, key).toHaveProperty(key);
    }
  });

  it("says out loud that saving replaces the whole policy", () => {
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: vi.fn() } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    expect(screen.getByText(/Saving replaces the whole policy/)).toBeTruthy();
  });

  it("renders INTERPRETER_NOT_ACKNOWLEDGED as an actionable message", async () => {
    const put = vi
      .fn()
      .mockRejectedValue(
        new ApiError(403, "INTERPRETER_NOT_ACKNOWLEDGED", "sh is a known interpreter"),
      );
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByText(/known interpreter/)).toBeTruthy());
    // The refusal has a remedy in this very form — name it.
    expect(screen.getByText(/acknowledgement box/)).toBeTruthy();
  });

  it("does not offer the acknowledgement remedy for an unrelated refusal", async () => {
    const put = vi.fn().mockRejectedValue(new ApiError(403, "ACCESS_DENIED", "nope"));
    render(
      <PolicyEditor
        api={{ putInjectionPolicy: put } as unknown as ApiClient}
        handle="k1"
        initial={{}}
        onDone={vi.fn()}
      />,
    );
    fireEvent.submit(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByText("nope")).toBeTruthy());
    expect(screen.queryByText(/acknowledgement box/)).toBeNull();
  });
});
