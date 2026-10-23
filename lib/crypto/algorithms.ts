/** Supported JWS signing algorithms (via jose / Web Crypto). */
export const SUPPORTED_ALGORITHMS = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
] as const;

export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];

const HMAC_ALGORITHMS = new Set<string>(["HS256", "HS384", "HS512"]);

export function isSupportedAlgorithm(
  alg: string,
): alg is SupportedAlgorithm {
  return (SUPPORTED_ALGORITHMS as readonly string[]).includes(alg);
}

export function isHmacAlgorithm(alg: string): boolean {
  return HMAC_ALGORITHMS.has(alg);
}

/** Maps UI / header labels to the jose JWS algorithm name. */
export function toJoseAlgorithm(algorithm: SupportedAlgorithm): string {
  if (algorithm === "Ed25519") return "EdDSA";
  return algorithm;
}

/** Maps jose / header algorithm names to the workbench label. */
export function headerAlgorithmLabel(algorithm: SupportedAlgorithm): string {
  if (algorithm === "Ed25519") return "EdDSA";
  return algorithm;
}

export function headerAlgorithmsMatch(
  headerAlg: string,
  selected: SupportedAlgorithm,
): boolean {
  if (headerAlg === selected) return true;
  if (
    (headerAlg === "EdDSA" && selected === "Ed25519") ||
    (headerAlg === "Ed25519" && selected === "EdDSA")
  ) {
    return true;
  }
  return false;
}

export function expectedJwkKty(
  alg: SupportedAlgorithm,
): "oct" | "RSA" | "EC" | "OKP" {
  if (isHmacAlgorithm(alg)) return "oct";
  if (alg.startsWith("RS") || alg.startsWith("PS")) return "RSA";
  if (alg.startsWith("ES")) return "EC";
  return "OKP";
}
