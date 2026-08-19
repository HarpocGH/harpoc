import type { AuditEventType } from "@harpoc/shared";
import { useState } from "preact/hooks";
import type { ApiClient, AuditVerifyReport } from "../api/client";
import { useAsync } from "../hooks";

export function AuditPage({ api }: { api: ApiClient }) {
  const [eventType, setEventType] = useState("");
  const [successFilter, setSuccessFilter] = useState<"all" | "ok" | "failed">("all");
  const [limit, setLimit] = useState(100);
  const [report, setReport] = useState<AuditVerifyReport | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const events = useAsync(
    () =>
      api.queryAudit({
        // The API rejects an unknown event type with 400 — that refusal is
        // surfaced as the load error, not pre-empted with client-side
        // validation against the known-type union.
        event_type: eventType === "" ? undefined : (eventType as AuditEventType),
        success: successFilter === "all" ? undefined : successFilter === "ok",
        limit,
      }),
    [eventType, successFilter, limit],
  );

  return (
    <>
      <h1>Audit</h1>
      <div class="panel">
        <label for="event-type">Event type</label>
        <input
          id="event-type"
          value={eventType}
          onInput={(e) => setEventType(e.currentTarget.value)}
        />
        <label for="outcome">Outcome</label>
        <select
          id="outcome"
          value={successFilter}
          onChange={(e) => setSuccessFilter(e.currentTarget.value as "all" | "ok" | "failed")}
        >
          <option value="all">all</option>
          <option value="ok">ok</option>
          <option value="failed">failed</option>
        </select>
        <label for="limit">Limit</label>
        <input
          id="limit"
          type="number"
          min={1}
          max={1000}
          value={limit}
          onInput={(e) => setLimit(Number(e.currentTarget.value) || 100)}
        />
        <button
          type="button"
          onClick={() => {
            setVerifyError(null);
            api.verifyAuditChain().then(setReport, (err: unknown) => {
              setVerifyError(err instanceof Error ? err.message : String(err));
            });
          }}
        >
          Verify chain
        </button>
        {report !== null && report.valid && (
          <p class="mono" style="color: var(--patina)">
            chain intact — {report.checked} rows checked, {report.legacy} legacy rows skipped
          </p>
        )}
        {report !== null && !report.valid && (
          <p class="error-text">chain broken at row {report.first_broken_id ?? "?"}</p>
        )}
        {verifyError !== null && <p class="error-text">{verifyError}</p>}
      </div>

      {events.error && <p class="error-text">{events.error.message}</p>}
      {events.data && events.data.length === 0 && (
        <p class="empty">
          No matching events. The trail starts at <code>vault.unlock</code>.
        </p>
      )}
      {events.data && events.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>time</th>
              <th>event</th>
              <th>principal</th>
              <th>outcome</th>
            </tr>
          </thead>
          <tbody>
            {events.data.map((e) => (
              <tr key={e.id}>
                <td>{new Date(e.timestamp).toISOString()}</td>
                <td>{e.event_type}</td>
                <td>{e.principal_id ?? "-"}</td>
                <td>
                  <span class="chip" data-tone={e.success ? "ok" : "bad"}>
                    {e.success ? "ok" : "failed"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
