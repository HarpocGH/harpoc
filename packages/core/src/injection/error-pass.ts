import type { EchoSource } from "@harpoc/shared";
import { VaultError, recordOf, renderRecordedDetails, renderVaultText } from "@harpoc/shared";
import { redactErrorMessage } from "./output-sanitizer.js";

/** The one text an unrecorded error leaves with on a path where a marker would show where a value stands. */
export const UNCLASSIFIED_TEXT = "the operation failed";

/**
 * An injector's pass: a recorded error passes as the same object, record kept,
 * and every other `VaultError` is redacted whole with the context's whole list.
 */
export function passError(err: unknown, values: readonly string[]): unknown {
  if (!(err instanceof VaultError) || recordOf(err) !== undefined) return err;
  return redactErrorMessage(err, values);
}

/**
 * A recorded error written from its record, each echo read from `call`, as a
 * new error built from strings, which carries no record.
 */
function fromRecord(err: VaultError, call: EchoSource): VaultError | undefined {
  const record = recordOf(err);
  if (record === undefined) return undefined;
  const message = renderVaultText(record.message, call);
  return record.details === undefined
    ? new VaultError(err.code, message)
    : new VaultError(err.code, message, renderRecordedDetails(record.details, call));
}

/** The choke point's pass: a recorded error leaves as its record says, any other redacted whole. */
export function leaveError(
  err: VaultError,
  values: readonly string[],
  call: EchoSource,
): VaultError {
  return fromRecord(err, call) ?? (redactErrorMessage(err, values) as VaultError);
}

/** The pass of a path whose texts are all recorded: any other error keeps its code and leaves with one fixed text. */
export function leaveFixed(err: VaultError, call: EchoSource): VaultError {
  return fromRecord(err, call) ?? new VaultError(err.code, UNCLASSIFIED_TEXT);
}
