const TONE: Record<string, string> = {
  active: "ok",
  ok: "ok",
  pending: "warn",
  expiring: "warn",
  expired: "bad",
  revoked: "bad",
  failed: "bad",
};

export function StatusChip({ status }: { status: string }) {
  return (
    <span class="chip" data-tone={TONE[status] ?? ""}>
      {status}
    </span>
  );
}
