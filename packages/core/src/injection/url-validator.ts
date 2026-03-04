import { promises as dns } from "node:dns";
import { ErrorCode, VaultError } from "@harpoc/shared";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** RFC 1918 and link-local IPv4 ranges. */
const PRIVATE_IPV4_RANGES: [number, number, number][] = [
  // 10.0.0.0/8
  [10, 0, 8],
  // 172.16.0.0/12
  [172, 16, 12],
  // 192.168.0.0/16
  [192, 168, 16],
  // 169.254.0.0/16 (link-local)
  [169, 254, 16],
];

/**
 * Check if an IPv4 address is in a private range.
 */
export function isPrivateIp(ip: string): boolean {
  // IPv4-mapped IPv6 (::ffff:x.x.x.x or ::ffff:XXXX:XXXX hex) — extract IPv4 part and recurse
  const normalized = ip.replace(/^\[|\]$/g, "");

  // Dotted-decimal form: ::ffff:192.168.1.1
  const ffmpDotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(normalized);
  if (ffmpDotted?.[1]) {
    return isPrivateIp(ffmpDotted[1]);
  }

  // Hex form: ::ffff:c0a8:0101 (as produced by URL parser)
  const ffmpHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(normalized);
  if (ffmpHex?.[1] && ffmpHex[2]) {
    const high = parseInt(ffmpHex[1], 16);
    const low = parseInt(ffmpHex[2], 16);
    const ipv4 = `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
    return isPrivateIp(ipv4);
  }

  // IPv4
  const parts = ip.split(".");
  if (parts.length === 4) {
    const octets = parts.map(Number);
    if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) return false;

    for (const [prefix0, prefix1, cidr] of PRIVATE_IPV4_RANGES) {
      if (cidr === 8 && octets[0] === prefix0) return true;
      if (cidr === 12 && octets[0] === prefix0 && (octets[1] ?? 0) >= prefix1 && (octets[1] ?? 0) <= prefix1 + 15) return true;
      if (cidr === 16 && octets[0] === prefix0 && octets[1] === prefix1) return true;
    }

    // Loopback 127.0.0.0/8
    if (octets[0] === 127) return true;

    // 0.0.0.0/8 — routes to localhost on many OSes
    if (octets[0] === 0) return true;

    return false;
  }

  // IPv6 ULA fc00::/7 and loopback ::1
  const normalizedLower = normalized.toLowerCase();
  if (normalizedLower === "::1") return true;
  if (normalizedLower.startsWith("fc") || normalizedLower.startsWith("fd")) return true;
  if (normalizedLower.startsWith("fe80")) return true; // link-local

  return false;
}

/**
 * Check if a hostname is a loopback address.
 */
export function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

export interface ValidatedUrl {
  url: URL;
  resolvedAddress?: string;
}

/**
 * Validate a URL for use in secret injection.
 *
 * Rules:
 * - Must be a valid URL
 * - Must use HTTPS (exception: HTTP for loopback)
 * - Must not target private/internal IP ranges (SSRF prevention)
 * - DNS resolution is checked to prevent DNS rebinding attacks
 *
 * Returns the validated URL and the resolved IP address (if DNS was performed).
 * Callers should use the resolved address to connect directly, preventing TOCTOU
 * DNS rebinding attacks.
 */
export async function validateUrl(urlStr: string): Promise<ValidatedUrl> {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new VaultError(ErrorCode.URL_INVALID, `Invalid URL: ${urlStr}`);
  }

  const hostname = url.hostname;

  // Scheme check
  if (url.protocol === "http:") {
    if (!isLoopback(hostname)) {
      throw new VaultError(
        ErrorCode.URL_HTTPS_REQUIRED,
        "HTTP is only allowed for loopback addresses (localhost, 127.0.0.1, ::1)",
      );
    }
  } else if (url.protocol !== "https:") {
    throw new VaultError(
      ErrorCode.URL_HTTPS_REQUIRED,
      `Only HTTPS URLs are allowed, got ${url.protocol}`,
    );
  }

  // SSRF check — skip for loopback
  if (!isLoopback(hostname) && isPrivateIp(hostname)) {
    throw new VaultError(
      ErrorCode.SSRF_BLOCKED,
      `SSRF blocked: ${hostname} resolves to a private/internal IP address`,
    );
  }

  // DNS rebinding protection: resolve hostname and check resolved IP
  let resolvedAddress: string | undefined;
  if (!isLoopback(hostname) && !isPrivateIp(hostname) && !isIpAddress(hostname)) {
    try {
      const { address } = await dns.lookup(hostname);
      if (isPrivateIp(address)) {
        throw new VaultError(
          ErrorCode.SSRF_BLOCKED,
          `SSRF blocked: ${hostname} resolves to private IP ${address}`,
        );
      }
      resolvedAddress = address;
    } catch (err) {
      if (err instanceof VaultError) throw err;
      throw new VaultError(
        ErrorCode.DNS_RESOLUTION_FAILED,
        `DNS resolution failed for ${hostname}: ${err instanceof Error ? err.message : "unknown"}`,
      );
    }
  }

  return { url, resolvedAddress };
}

/** Check if a string looks like an IP address (v4 or v6). */
function isIpAddress(host: string): boolean {
  const normalized = host.replace(/^\[|\]$/g, "");
  // IPv4: four dot-separated octets
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)) return true;
  // IPv6: contains a colon
  if (normalized.includes(":")) return true;
  return false;
}
