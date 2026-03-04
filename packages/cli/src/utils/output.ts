import { ErrorCode, VaultError } from "@harpoc/shared";

/**
 * Print a table of objects to stdout.
 */
export function printTable(rows: Record<string, unknown>[]): void {
  if (rows.length === 0) {
    console.log("No results.");
    return;
  }

  const firstRow = rows[0];
  if (!firstRow) return;

  const keys = Object.keys(firstRow);
  const widths = keys.map((key) => {
    const maxValueLen = rows.reduce((max, row) => {
      const val = formatCell(row[key]);
      return Math.max(max, val.length);
    }, 0);
    return Math.max(key.length, maxValueLen);
  });

  // Header
  const header = keys.map((key, i) => key.padEnd(widths[i] ?? 0)).join("  ");
  const separator = widths.map((w) => "-".repeat(w)).join("  ");
  console.log(header);
  console.log(separator);

  // Rows
  for (const row of rows) {
    const line = keys.map((key, i) => formatCell(row[key]).padEnd(widths[i] ?? 0)).join("  ");
    console.log(line);
  }
}

/**
 * Print data as JSON to stdout.
 */
export function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

/**
 * Print a single key-value record.
 */
export function printRecord(record: Record<string, unknown>): void {
  const maxKeyLen = Math.max(...Object.keys(record).map((k) => k.length));
  for (const [key, value] of Object.entries(record)) {
    console.log(`${key.padEnd(maxKeyLen)}  ${formatCell(value)}`);
  }
}

/**
 * Print a success message to stderr.
 */
export function printSuccess(message: string): void {
  console.error(`OK: ${message}`);
}

/**
 * Print an error message to stderr and exit.
 */
export function handleError(err: unknown, json = false): never {
  if (err instanceof VaultError) {
    if (json) {
      console.error(JSON.stringify({ error: err.code, message: err.message }));
    } else {
      const msg = formatVaultError(err);
      console.error(`Error: ${msg}`);
    }
    process.exit(1);
  }

  if (err instanceof Error) {
    if (json) {
      console.error(JSON.stringify({ error: "UNKNOWN", message: err.message }));
    } else {
      console.error(`Error: ${err.message}`);
    }
    process.exit(1);
  }

  console.error("Error: An unexpected error occurred");
  process.exit(1);
}

function formatVaultError(err: VaultError): string {
  switch (err.code) {
    case ErrorCode.VAULT_LOCKED:
      return "Vault is locked. Run 'harpoc unlock' first.";
    case ErrorCode.VAULT_NOT_FOUND:
      return "No vault found. Run 'harpoc init' to create one.";
    case ErrorCode.INVALID_PASSWORD:
      return "Invalid password.";
    case ErrorCode.LOCKOUT_ACTIVE: {
      const retryMs = (err.details?.retry_after_ms as number) ?? 0;
      const retrySec = Math.ceil(retryMs / 1000);
      return `Account locked. Try again in ${retrySec}s.`;
    }
    case ErrorCode.SECRET_NOT_FOUND:
      return err.message;
    case ErrorCode.DUPLICATE_SECRET:
      return err.message;
    default:
      return `[${err.code}] ${err.message}`;
  }
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "number") return String(value);
  return String(value);
}

/**
 * Format a Unix timestamp (seconds or milliseconds) to a readable date string.
 */
export function formatTimestamp(ts: number | null): string {
  if (ts === null) return "-";
  // If the timestamp looks like seconds (< 10 billion), convert to ms
  const ms = ts < 1e10 ? ts * 1000 : ts;
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}
