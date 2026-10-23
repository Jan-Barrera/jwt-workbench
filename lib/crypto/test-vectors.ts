import type { SupportedAlgorithm } from "./algorithms";

export type SignatureTestVector = {
  id: string;
  algorithm: SupportedAlgorithm;
  token: string;
  keyMaterial: string;
  /** When omitted, format is auto-detected from key material. */
  keyFormat?: "auto" | "secret" | "pem" | "jwk";
  description: string;
};

/** Well-known jwt.io HS256 sample (RFC 7519 appendix example). */
export const JWT_IO_HS256: SignatureTestVector = {
  id: "jwt.io-hs256",
  algorithm: "HS256",
  description: "jwt.io debugger HS256 sample token",
  token:
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  keyMaterial: "your-256-bit-secret",
};

/** Static vectors checked on every test run. Dynamic per-algorithm vectors are generated in tests. */
export const STATIC_SIGNATURE_VECTORS: readonly SignatureTestVector[] = [
  JWT_IO_HS256,
];
