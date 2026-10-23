export type Base64UrlSuccess = {
  ok: true;
  output: string;
};

export type Base64UrlError = {
  ok: false;
  message: string;
};

export type Base64UrlResult = Base64UrlSuccess | Base64UrlError;

const BASE64URL_SEGMENT = /^[A-Za-z0-9_-]*$/;

function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToBytes(segment: string): Uint8Array {
  if (!BASE64URL_SEGMENT.test(segment)) {
    throw new Error("invalid base64url");
  }

  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4;
  const padded = padding === 0 ? base64 : base64 + "=".repeat(4 - padding);

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }

  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function encodeBase64Url(text: string): Base64UrlResult {
  if (!text) {
    return { ok: false, message: "Enter text to encode." };
  }

  try {
    return { ok: true, output: bytesToBase64Url(utf8ToBytes(text)) };
  } catch {
    return { ok: false, message: "Text could not be encoded as UTF-8." };
  }
}

export function decodeBase64Url(encoded: string): Base64UrlResult {
  const trimmed = encoded.trim();
  if (!trimmed) {
    return { ok: false, message: "Enter Base64URL text to decode." };
  }

  try {
    const bytes = base64UrlToBytes(trimmed);
    return { ok: true, output: bytesToUtf8(bytes) };
  } catch {
    return {
      ok: false,
      message:
        "Input is not valid Base64URL. Use only A–Z, a–z, 0–9, hyphen, and underscore.",
    };
  }
}
