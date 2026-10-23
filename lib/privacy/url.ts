import { looksLikeJwt } from "./scrub";

/** Query parameter names that must never carry JWTs or secrets in the URL. */
export const SENSITIVE_QUERY_PARAM_NAMES = new Set([
  "token",
  "jwt",
  "access_token",
  "id_token",
  "refresh_token",
  "bearer",
  "authorization",
  "auth",
  "api_key",
  "apikey",
  "key",
  "secret",
  "password",
  "private_key",
]);

export type SanitizeSearchParamsResult = {
  sanitized: URLSearchParams;
  removed: string[];
};

function isSensitiveQueryParam(name: string, value: string): boolean {
  const lower = name.toLowerCase();
  if (SENSITIVE_QUERY_PARAM_NAMES.has(lower)) {
    return true;
  }
  if (
    lower.includes("token") ||
    lower.includes("secret") ||
    lower.includes("password") ||
    lower.endsWith("_key") ||
    lower === "key"
  ) {
    return true;
  }
  return looksLikeJwt(value);
}

/** Removes sensitive query parameters and JWT-shaped values from a search string. */
export function sanitizeUrlSearchParams(
  searchParams: URLSearchParams,
): SanitizeSearchParamsResult {
  const sanitized = new URLSearchParams();
  const removed: string[] = [];

  for (const [name, value] of searchParams.entries()) {
    if (isSensitiveQueryParam(name, value)) {
      removed.push(name);
    } else {
      sanitized.append(name, value);
    }
  }

  return { sanitized, removed };
}

/** Builds a pathname + optional query string with sensitive parameters removed. */
export function buildCleanUrl(
  pathname: string,
  searchParams: URLSearchParams,
): string {
  const { sanitized } = sanitizeUrlSearchParams(searchParams);
  const query = sanitized.toString();
  return query ? `${pathname}?${query}` : pathname;
}
