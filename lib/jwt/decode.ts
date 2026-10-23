export type JwtSegmentParts = {
  header: string;
  payload: string;
  signature: string;
};

export type JwtDecodeSuccess = {
  ok: true;
  normalizedToken: string;
  segments: JwtSegmentParts;
  header: unknown;
  payload: unknown;
  headerJson: string;
  payloadJson: string;
};

export type JwtDecodeErrorCode =
  | "EMPTY"
  | "MALFORMED_STRUCTURE"
  | "INVALID_BASE64"
  | "INVALID_JSON";

export type JwtDecodeError = {
  ok: false;
  error: string;
  code: JwtDecodeErrorCode;
  part?: "header" | "payload";
};

export type JwtDecodeResult = JwtDecodeSuccess | JwtDecodeError;

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]+$/;

export function normalizeJwtInput(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  const bearerMatch = /^Bearer\s+(.+)$/i.exec(trimmed);
  return bearerMatch ? bearerMatch[1].trim() : trimmed;
}

function base64UrlDecodeToUtf8(segment: string): string {
  if (!BASE64URL_SEGMENT.test(segment)) {
    throw new Error("invalid base64url");
  }
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4;
  const padded =
    padding === 0 ? base64 : base64 + "=".repeat(4 - padding);

  if (typeof Buffer !== "undefined") {
    return Buffer.from(padded, "base64").toString("utf8");
  }

  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function parseJsonSegment(
  utf8: string,
  part: "header" | "payload",
): { ok: true; value: unknown } | JwtDecodeError {
  try {
    const value: unknown = JSON.parse(utf8);
    return { ok: true, value };
  } catch {
    return {
      ok: false,
      error: `${part === "header" ? "Header" : "Payload"} is not valid JSON.`,
      code: "INVALID_JSON",
      part,
    };
  }
}

export function decodeJwt(raw: string): JwtDecodeResult {
  const token = normalizeJwtInput(raw);
  if (!token) {
    return {
      ok: false,
      error: "Enter a JWT to decode.",
      code: "EMPTY",
    };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return {
      ok: false,
      error: `Expected a compact JWT with 3 dot-separated segments; got ${parts.length}.`,
      code: "MALFORMED_STRUCTURE",
    };
  }

  const [headerSeg, payloadSeg, signatureSeg] = parts;
  if (!headerSeg || !payloadSeg || !signatureSeg) {
    return {
      ok: false,
      error: "JWT segments must not be empty.",
      code: "MALFORMED_STRUCTURE",
    };
  }

  let headerUtf8: string;
  let payloadUtf8: string;
  try {
    headerUtf8 = base64UrlDecodeToUtf8(headerSeg);
  } catch {
    return {
      ok: false,
      error: "Header is not valid Base64URL.",
      code: "INVALID_BASE64",
      part: "header",
    };
  }
  try {
    payloadUtf8 = base64UrlDecodeToUtf8(payloadSeg);
  } catch {
    return {
      ok: false,
      error: "Payload is not valid Base64URL.",
      code: "INVALID_BASE64",
      part: "payload",
    };
  }

  const headerParsed = parseJsonSegment(headerUtf8, "header");
  if (!headerParsed.ok) {
    return headerParsed;
  }

  const payloadParsed = parseJsonSegment(payloadUtf8, "payload");
  if (!payloadParsed.ok) {
    return payloadParsed;
  }

  const headerJson = JSON.stringify(headerParsed.value, null, 2);
  const payloadJson = JSON.stringify(payloadParsed.value, null, 2);

  return {
    ok: true,
    normalizedToken: token,
    segments: {
      header: headerSeg,
      payload: payloadSeg,
      signature: signatureSeg,
    },
    header: headerParsed.value,
    payload: payloadParsed.value,
    headerJson,
    payloadJson,
  };
}
