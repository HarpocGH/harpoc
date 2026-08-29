import { useState } from "preact/hooks";
import type { InjectionPolicyInput, ResponseMode } from "@harpoc/shared";
import type { ApiClient, SetInjectionPolicyRequest } from "../api/client";
import { ApiError } from "../api/client";
import { toBase64 } from "../encoding";

/**
 * The four mutating forms. Every one of them is write-only in the direction
 * that matters: a value the operator types goes out as base64 and is dropped
 * from state on success, and no form ever reads a value back — the UI has no
 * route that returns one.
 */

interface SubmitState {
  error: Error | null;
  busy: boolean;
  onSubmit: (event: Event) => void;
}

/**
 * Submit plumbing shared by the four forms: prevent the native navigation, run
 * the action, and keep the refusal as the `Error` it arrived as — the code on
 * an `ApiError` is what tells one refusal from another.
 */
function useSubmit(action: () => Promise<void>): SubmitState {
  const [error, setError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const onSubmit = (event: Event): void => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    action().then(
      () => setBusy(false),
      (err: unknown) => {
        setError(err instanceof Error ? err : new Error(String(err)));
        setBusy(false);
      },
    );
  };
  return { error, busy, onSubmit };
}

const splitList = (text: string): string[] =>
  text
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");

export function CreateSecretForm({ api, onDone }: { api: ApiClient; onDone: () => void }) {
  const [name, setName] = useState("");
  const [project, setProject] = useState("");
  const [value, setValue] = useState("");
  const [file, setFile] = useState<{ name: string; text: string } | null>(null);
  // Remounts the file input so re-picking the SAME file after a clear still
  // fires a change event.
  const [fileKey, setFileKey] = useState(0);
  const resetFileInput = (): void => setFileKey((k) => k + 1);

  const effective = file === null ? value : file.text;
  const { error, busy, onSubmit } = useSubmit(async () => {
    await api.createSecret({
      name,
      type: "api_key",
      ...(project === "" ? {} : { project }),
      ...(effective === "" ? {} : { value: toBase64(effective) }),
    });
    setName("");
    setProject("");
    setValue("");
    setFile(null);
    resetFileInput();
    onDone();
  });

  return (
    <form onSubmit={onSubmit}>
      <h2>Create a secret</h2>
      <p class="empty">
        Creates an <code>api_key</code> secret. OAuth tokens and certificates have their own
        lifecycles — <code>harpoc oauth connect</code> and <code>harpoc cert import</code>. Leaving
        the value empty creates the secret pending, to be filled in later.
      </p>
      <label for="new-name">Name</label>
      <input
        id="new-name"
        autocomplete="off"
        value={name}
        onInput={(e) => setName(e.currentTarget.value)}
        required
      />
      <label for="create-project">Project (optional)</label>
      <input
        id="create-project"
        autocomplete="off"
        value={project}
        onInput={(e) => setProject(e.currentTarget.value)}
      />
      <label for="new-value">Value (write-only — the UI never displays it again)</label>
      <input
        id="new-value"
        type="password"
        autocomplete="off"
        value={file === null ? value : ""}
        disabled={file !== null}
        onInput={(e) => setValue(e.currentTarget.value)}
      />
      <label for="create-file">Load from file</label>
      <input
        key={fileKey}
        id="create-file"
        type="file"
        onChange={(e) => {
          const picked = e.currentTarget.files?.[0];
          if (picked === undefined) return;
          // Read in the browser, not uploaded: what leaves is the same base64
          // `value` field a typed secret produces. This is the multi-line path
          // — and it is why the text is held here rather than in the input: a
          // single-line input strips newlines from its value, which would turn
          // a PEM key into one unusable line without saying so.
          const reader = new FileReader();
          reader.onload = () =>
            setFile({
              name: picked.name,
              text: typeof reader.result === "string" ? reader.result : "",
            });
          reader.readAsText(picked);
        }}
      />
      {file === null && (
        <p class="empty">The file is read in this browser; only the value is sent.</p>
      )}
      {file !== null && (
        <>
          <p class="empty">
            Value read from <code>{file.name}</code> ({file.text.length} characters) in this browser
            — the file itself is not uploaded, and its text is not displayed.
          </p>
          <p>
            <button
              type="button"
              onClick={() => {
                setFile(null);
                resetFileInput();
              }}
            >
              Clear file
            </button>
          </p>
        </>
      )}
      {error && <p class="error-text">{error.message}</p>}
      <p>
        <button type="submit" disabled={busy}>
          Create secret
        </button>
      </p>
    </form>
  );
}

export function RotateForm({
  api,
  handle,
  onDone,
}: {
  api: ApiClient;
  handle: string;
  onDone: () => void;
}) {
  const [value, setValue] = useState("");

  const { error, busy, onSubmit } = useSubmit(async () => {
    await api.rotateSecret(handle, toBase64(value));
    setValue("");
    onDone();
  });

  return (
    <form onSubmit={onSubmit}>
      <h2>Rotate value</h2>
      <p class="empty">
        The new value replaces the stored one and bumps the version. The old value is not shown
        before, during or after.
      </p>
      <label for="rotate-value">New value (write-only)</label>
      <input
        id="rotate-value"
        type="password"
        autocomplete="off"
        value={value}
        onInput={(e) => setValue(e.currentTarget.value)}
        required
      />
      {error && <p class="error-text">{error.message}</p>}
      <p>
        {/* An empty value is a valid base64 string, so the API would accept it
            and rotate the credential to zero bytes — irreversibly. */}
        <button type="submit" disabled={busy || value === ""}>
          Rotate
        </button>
      </p>
    </form>
  );
}

export function DeleteForm({
  api,
  handle,
  secretName,
  onDone,
}: {
  api: ApiClient;
  handle: string;
  secretName: string;
  onDone: () => void;
}) {
  const [confirmName, setConfirmName] = useState("");
  const canDelete = confirmName === secretName;

  const { error, busy, onSubmit } = useSubmit(async () => {
    await api.deleteSecret(handle);
    setConfirmName("");
    onDone();
  });

  return (
    <form onSubmit={onSubmit}>
      <h2>Danger zone</h2>
      <p class="empty">
        Deleting revokes the secret: it can no longer be read, used or rotated, and there is no
        undo. Its audit trail stays.
      </p>
      <label for="delete-confirm">Type the name to confirm</label>
      <input
        id="delete-confirm"
        autocomplete="off"
        placeholder={secretName}
        value={confirmName}
        onInput={(e) => setConfirmName(e.currentTarget.value)}
      />
      {error && <p class="error-text">{error.message}</p>}
      <p>
        <button type="submit" class="danger" disabled={!canDelete || busy}>
          Delete secret
        </button>
      </p>
    </form>
  );
}

export function PolicyEditor({
  api,
  handle,
  initial,
  onDone,
}: {
  api: ApiClient;
  handle: string;
  initial: InjectionPolicyInput;
  onDone: () => void;
}) {
  const [urls, setUrls] = useState((initial.url_allowlist ?? []).join(", "));
  const [commands, setCommands] = useState((initial.command_allowlist ?? []).join(", "));
  const [hosts, setHosts] = useState((initial.host_allowlist ?? []).join(", "));
  const [mode, setMode] = useState<ResponseMode>(initial.response_mode ?? "filtered");
  const [networkIsolation, setNetworkIsolation] = useState(initial.network_isolation ?? false);
  const [fsIsolation, setFsIsolation] = useState(initial.fs_isolation ?? false);
  const [ack, setAck] = useState(false);

  const { error, busy, onSubmit } = useSubmit(async () => {
    const body: SetInjectionPolicyRequest = {
      url_allowlist: splitList(urls),
      command_allowlist: splitList(commands),
      host_allowlist: splitList(hosts),
      // Not edited here, and a PUT replaces the whole policy — resubmitting
      // them unchanged is the difference between "not edited" and "cleared".
      // Covers env_allowlist, response_header_allowlist, smtp_recipient_allowlist
      // and imap_read_only.
      env_allowlist: initial.env_allowlist ?? [],
      response_header_allowlist: initial.response_header_allowlist ?? [],
      smtp_recipient_allowlist: initial.smtp_recipient_allowlist ?? [],
      imap_read_only: initial.imap_read_only ?? false,
      response_mode: mode,
      network_isolation: networkIsolation,
      fs_isolation: fsIsolation,
      ...(ack ? { acknowledge_interpreters: true } : {}),
    };
    await api.putInjectionPolicy(handle, body);
    // The waiver is per operation, as it is on every other path (a CLI flag per
    // invocation, a request field per REST call) — and this editor outlives its
    // saves, so a box left ticked would acknowledge the next interpreter
    // addition on behalf of an operator who never saw it.
    setAck(false);
    onDone();
  });

  return (
    <form onSubmit={onSubmit}>
      <h2>Edit injection policy</h2>
      <p class="empty">
        Saving replaces the whole policy (REST PUT semantics) — omitted lists reset.
      </p>
      <p class="empty">
        <code>env_allowlist</code>, <code>response_header_allowlist</code>,{" "}
        <code>smtp_recipient_allowlist</code> and <code>imap_read_only</code> are not editable here
        and are sent back unchanged.
      </p>
      <label for="policy-urls">URL allowlist (comma-separated)</label>
      <input
        id="policy-urls"
        autocomplete="off"
        value={urls}
        onInput={(e) => setUrls(e.currentTarget.value)}
      />
      <label for="policy-commands">Command allowlist (comma-separated absolute paths)</label>
      <input
        id="policy-commands"
        autocomplete="off"
        value={commands}
        onInput={(e) => setCommands(e.currentTarget.value)}
      />
      <label for="policy-hosts">Host allowlist (comma-separated)</label>
      <input
        id="policy-hosts"
        autocomplete="off"
        value={hosts}
        onInput={(e) => setHosts(e.currentTarget.value)}
      />
      <label for="policy-mode">Response mode</label>
      <select
        id="policy-mode"
        value={mode}
        onChange={(e) => setMode(e.currentTarget.value as ResponseMode)}
      >
        <option value="full">full — no vault-layer redaction</option>
        <option value="filtered">filtered (default)</option>
        <option value="status_only">status_only — no body</option>
      </select>
      <label for="policy-network">
        <input
          id="policy-network"
          type="checkbox"
          checked={networkIsolation}
          onChange={(e) => setNetworkIsolation(e.currentTarget.checked)}
        />
        Network isolation for process-mediated children
      </label>
      <label for="policy-fs">
        <input
          id="policy-fs"
          type="checkbox"
          checked={fsIsolation}
          onChange={(e) => setFsIsolation(e.currentTarget.checked)}
        />
        Filesystem isolation for process-mediated children
      </label>
      <label for="ack">
        <input
          id="ack"
          type="checkbox"
          checked={ack}
          onChange={(e) => setAck(e.currentTarget.checked)}
        />
        Acknowledge adding a known interpreter (audited)
      </label>
      {error && <p class="error-text">{error.message}</p>}
      {error instanceof ApiError && error.code === "INTERPRETER_NOT_ACKNOWLEDGED" && (
        <p class="error-text">
          Tick the acknowledgement box and save again — the addition is audited either way.
        </p>
      )}
      <p>
        <button type="submit" disabled={busy}>
          Save policy
        </button>
      </p>
    </form>
  );
}
