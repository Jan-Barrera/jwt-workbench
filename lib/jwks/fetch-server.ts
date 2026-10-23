import {
  JWKS_FETCH_MAX_BYTES,
  JWKS_FETCH_TIMEOUT_MS,
  validateJwksFetchUrl,
} from "./url";

export type FetchJwksServerCode =
  | "OK"
  | "INVALID_URL"
  | "BLOCKED_HOST"
  | "UNREACHABLE"
  | "HTTP_ERROR"
  | "TOO_LARGE"
  | "INVALID_JSON";

export type FetchJwksServerResult =
  | { code: "OK"; body: string }
  | { code: Exclude<FetchJwksServerCode, "OK">; message: string };

export async function fetchJwksFromUrl(
  rawUrl: string,
): Promise<FetchJwksServerResult> {
  const validation = validateJwksFetchUrl(rawUrl);
  if (validation.code !== "OK") {
    return validation;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), JWKS_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(validation.url.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "follow",
      signal: controller.signal,
      cache: "no-store",
    });

    if (!response.ok) {
      return {
        code: "HTTP_ERROR",
        message: `JWKS endpoint returned HTTP ${response.status}.`,
      };
    }

    const reader = response.body?.getReader();
    if (!reader) {
      const text = await response.text();
      if (text.length > JWKS_FETCH_MAX_BYTES) {
        return {
          code: "TOO_LARGE",
          message: "JWKS response exceeds the size limit.",
        };
      }
      return validateJsonBody(text);
    }

    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > JWKS_FETCH_MAX_BYTES) {
        await reader.cancel();
        return {
          code: "TOO_LARGE",
          message: "JWKS response exceeds the size limit.",
        };
      }
      chunks.push(value);
    }

    const body = new TextDecoder().decode(
      concatUint8Arrays(chunks, total),
    );
    return validateJsonBody(body);
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      return {
        code: "UNREACHABLE",
        message: "JWKS request timed out.",
      };
    }
    return {
      code: "UNREACHABLE",
      message: "Could not reach the JWKS endpoint.",
    };
  } finally {
    clearTimeout(timeout);
  }
}

function validateJsonBody(body: string): FetchJwksServerResult {
  try {
    JSON.parse(body);
  } catch {
    return {
      code: "INVALID_JSON",
      message: "JWKS endpoint did not return valid JSON.",
    };
  }
  return { code: "OK", body };
}

function concatUint8Arrays(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}
