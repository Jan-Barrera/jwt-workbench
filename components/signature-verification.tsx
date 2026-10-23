"use client";

import {
  type VerifyJwtCode,
  type VerifyJwtResult,
  type VerifyKeyFormat,
  isHmacAlgorithm,
} from "@/lib/jwt/verify";

type SignatureVerificationFormProps = {
  algorithm: string | null;
  keyMaterial: string;
  keyFormat: VerifyKeyFormat;
  onKeyMaterialChange: (value: string) => void;
  onKeyFormatChange: (value: VerifyKeyFormat) => void;
  result: VerifyJwtResult | null;
};

const KEY_FORMATS: { value: VerifyKeyFormat; label: string }[] = [
  { value: "auto", label: "Auto" },
  { value: "secret", label: "Shared secret" },
  { value: "pem", label: "Public key (PEM)" },
  { value: "jwk", label: "JWK" },
];

export function SignatureVerificationForm({
  algorithm,
  keyMaterial,
  keyFormat,
  onKeyMaterialChange,
  onKeyFormatChange,
  result,
}: SignatureVerificationFormProps) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-zinc-200 bg-white px-3 py-3 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-col gap-1">
          <h3 className="text-sm font-medium text-zinc-900 dark:text-zinc-100">
            Signature verification
          </h3>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Cryptographic check using a key you supply. This is separate from
            decoding and claim validation. Keys stay in this browser.
          </p>
        </div>
        <SignatureStatusBadge result={result} />
      </div>

      <p className="text-sm text-zinc-700 dark:text-zinc-300">
        Declared algorithm:{" "}
        <span className="font-mono font-medium">
          {algorithm ?? "(missing)"}
        </span>
      </p>

      <fieldset className="flex flex-col gap-2">
        <legend className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          Key format
        </legend>
        <div className="flex flex-wrap gap-1">
          {KEY_FORMATS.map((option) => {
            const active = keyFormat === option.value;
            return (
              <label
                key={option.value}
                className={`cursor-pointer rounded-md px-2.5 py-1 text-xs font-medium transition ${
                  active
                    ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                    : "bg-zinc-100 text-zinc-700 hover:bg-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-700"
                }`}
              >
                <input
                  type="radio"
                  name="jwt-key-format"
                  value={option.value}
                  checked={active}
                  onChange={() => onKeyFormatChange(option.value)}
                  className="sr-only"
                />
                {option.label}
              </label>
            );
          })}
        </div>
      </fieldset>

      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium text-zinc-800 dark:text-zinc-200">
          Verification key
        </span>
        <textarea
          id="jwt-verify-key"
          name="jwt-verify-key"
          rows={4}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          placeholder={keyPlaceholder(algorithm, keyFormat)}
          value={keyMaterial}
          onChange={(e) => onKeyMaterialChange(e.target.value)}
          className="w-full resize-y rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-sm text-zinc-900 shadow-sm outline-none ring-zinc-400 focus:ring-2 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-100"
        />
      </label>

      {result && result.code !== "MISSING_KEY" && (
        <p
          className={`text-sm ${
            result.ok
              ? "text-emerald-800 dark:text-emerald-300"
              : "text-zinc-700 dark:text-zinc-300"
          }`}
          role="status"
        >
          {result.message}
        </p>
      )}
    </div>
  );
}

export function SignatureStatusBadge({
  result,
}: {
  result: VerifyJwtResult | null;
}) {
  const code = result?.code ?? "MISSING_KEY";
  return (
    <span
      className={`inline-flex shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${statusStyles(code)}`}
      title="Cryptographic signature status; not the same as decoded JSON"
      role="status"
    >
      {statusLabel(code)}
    </span>
  );
}

function statusLabel(code: VerifyJwtCode): string {
  switch (code) {
    case "PASS":
      return "Signature verified";
    case "INVALID_SIGNATURE":
      return "Invalid signature";
    case "UNSUPPORTED_ALGORITHM":
    case "NONE_ALGORITHM":
      return "Unsupported algorithm";
    case "MALFORMED_KEY":
      return "Malformed key";
    case "KEY_TYPE_MISMATCH":
      return "Key mismatch";
    case "MALFORMED_TOKEN":
      return "Cannot verify";
    case "MISSING_KEY":
      return "Not verified";
  }
}

function statusStyles(code: VerifyJwtCode): string {
  switch (code) {
    case "PASS":
      return "bg-emerald-100 text-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-200";
    case "INVALID_SIGNATURE":
    case "MALFORMED_TOKEN":
      return "bg-red-100 text-red-900 dark:bg-red-950/60 dark:text-red-200";
    case "UNSUPPORTED_ALGORITHM":
    case "NONE_ALGORITHM":
    case "MALFORMED_KEY":
    case "KEY_TYPE_MISMATCH":
      return "bg-amber-100 text-amber-950 dark:bg-amber-950/50 dark:text-amber-100";
    case "MISSING_KEY":
      return "bg-sky-100 text-sky-900 dark:bg-sky-950/50 dark:text-sky-200";
  }
}

function keyPlaceholder(
  algorithm: string | null,
  format: VerifyKeyFormat,
): string {
  if (format === "secret") {
    return "shared secret";
  }
  if (format === "pem") {
    return "-----BEGIN PUBLIC KEY-----";
  }
  if (format === "jwk") {
    return '{ "kty": "...", ... }';
  }
  if (algorithm && isHmacAlgorithm(algorithm)) {
    return "Shared secret or oct JWK";
  }
  if (algorithm) {
    return "PEM public key or JWK";
  }
  return "Shared secret, PEM public key, or JWK";
}
