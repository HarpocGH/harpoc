import * as dns from "node:dns";
import { constants } from "node:os";
import { getSystemErrorMap } from "node:util";
import type { TextPart } from "@harpoc/shared";
import { token } from "@harpoc/shared";

/** The error codes of the local system: libuv's errno names, node's dns codes, and `UNKNOWN`. */
export const LOCAL_ERROR_CODES: ReadonlySet<string> = new Set([
  ...[...getSystemErrorMap().values()].map(([name]) => name),
  ...Object.values(dns as Record<string, unknown>).filter(
    (value): value is string => typeof value === "string",
  ),
  "UNKNOWN",
]);

/** The codes undici's `lib/core/errors.js` (8.12.4) gives its errors. */
const UNDICI_ERROR_CODES = [
  "UND_ERR_ABORT",
  "UND_ERR_ABORTED",
  "UND_ERR_BODY_TIMEOUT",
  "UND_ERR_BPL_MISSING_UPSTREAM",
  "UND_ERR_CLOSED",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_DESTROYED",
  "UND_ERR_HEADERS_OVERFLOW",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_INFO",
  "UND_ERR_INVALID_ARG",
  "UND_ERR_INVALID_RETURN_VALUE",
  "UND_ERR_MAX_ORIGINS_REACHED",
  "UND_ERR_NOT_SUPPORTED",
  "UND_ERR_PRX_CONN",
  "UND_ERR_PRX_TLS",
  "UND_ERR_REDIRECT_MAX",
  "UND_ERR_REQ_CONTENT_LENGTH_MISMATCH",
  "UND_ERR_REQ_RETRY",
  "UND_ERR_RES_CONTENT_LENGTH_MISMATCH",
  "UND_ERR_RES_EXCEEDED_MAX_SIZE",
  "UND_ERR_RESPONSE",
  "UND_ERR_SOCKET",
  "UND_ERR_SOCKS5",
  "UND_ERR_WS_MESSAGE_SIZE_EXCEEDED",
];

/** The certificate codes the vault names; a TLS library's other codes, `ERR_SSL_*` among them, are a peer's choice. */
const CERTIFICATE_ERROR_CODES = [
  "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "ERR_TLS_CERT_ALTNAME_INVALID",
];

/** The codes a failure a remote side causes is named by: the local ones, undici's and the certificate codes. */
export const REMOTE_ERROR_CODES: ReadonlySet<string> = new Set([
  ...LOCAL_ERROR_CODES,
  ...UNDICI_ERROR_CODES,
  ...CERTIFICATE_ERROR_CODES,
]);

const PLATFORMS: Record<NodeJS.Platform, true> = {
  aix: true,
  android: true,
  cygwin: true,
  darwin: true,
  freebsd: true,
  haiku: true,
  linux: true,
  netbsd: true,
  openbsd: true,
  sunos: true,
  win32: true,
};

export const PLATFORM_WORDS: readonly string[] = Object.freeze(Object.keys(PLATFORMS));

export const SIGNAL_WORDS: ReadonlySet<string> = new Set(Object.keys(constants.signals));

export function errnoToken(code: unknown, other = "unknown error"): TextPart {
  return token(code, LOCAL_ERROR_CODES, other);
}
