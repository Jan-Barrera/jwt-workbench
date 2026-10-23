/** PEM labels that indicate private key material (never used for verification). */
export const PRIVATE_PEM_LABELS = [
  "PRIVATE KEY",
  "RSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
] as const;

export function pemLabel(material: string): string | null {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(material);
  return match?.[1] ?? null;
}

export function isPrivatePemLabel(label: string): boolean {
  return (PRIVATE_PEM_LABELS as readonly string[]).includes(label);
}

export type DetectedKeyFormat = "secret" | "pem" | "jwk";

export function detectKeyFormat(material: string): DetectedKeyFormat {
  const trimmed = material.trim();
  if (trimmed.startsWith("{")) return "jwk";
  if (trimmed.includes("-----BEGIN ")) return "pem";
  return "secret";
}
