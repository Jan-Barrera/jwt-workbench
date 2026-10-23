export type JwksUrlValidationCode = "OK" | "INVALID_URL" | "BLOCKED_HOST";

export type JwksUrlValidation =
  | { code: "OK"; url: URL }
  | { code: Exclude<JwksUrlValidationCode, "OK">; message: string };

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
]);

export function validateJwksFetchUrl(raw: string): JwksUrlValidation {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { code: "INVALID_URL", message: "Enter a JWKS URL." };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { code: "INVALID_URL", message: "URL is not valid." };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return {
      code: "INVALID_URL",
      message: "Only http and https JWKS URLs are allowed.",
    };
  }

  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host)) {
    return {
      code: "BLOCKED_HOST",
      message: "Fetching from loopback addresses is not allowed.",
    };
  }

  if (isPrivateOrLinkLocalHost(host)) {
    return {
      code: "BLOCKED_HOST",
      message: "Fetching from private or link-local addresses is not allowed.",
    };
  }

  return { code: "OK", url };
}

function isPrivateOrLinkLocalHost(host: string): boolean {
  if (host.endsWith(".local") || host.endsWith(".internal")) {
    return true;
  }

  const ipv4 = parseIpv4(host);
  if (!ipv4) {
    return false;
  }

  const [a, b] = ipv4;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;

  return false;
}

function parseIpv4(host: string): [number, number, number, number] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => Number.parseInt(part, 10));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) {
    return null;
  }
  return nums as [number, number, number, number];
}

export const JWKS_FETCH_MAX_BYTES = 512 * 1024;
export const JWKS_FETCH_TIMEOUT_MS = 10_000;
