export const REGISTERED_CLAIMS = [
  "iss",
  "sub",
  "aud",
  "exp",
  "nbf",
  "iat",
  "jti",
] as const;

export type RegisteredClaimName = (typeof REGISTERED_CLAIMS)[number];

const CLAIM_META: Record<
  RegisteredClaimName,
  { friendlyName: string; description: string }
> = {
  iss: {
    friendlyName: "Issuer",
    description: "Principal that issued the JWT.",
  },
  sub: {
    friendlyName: "Subject",
    description: "Subject of the JWT (often a user or client identifier).",
  },
  aud: {
    friendlyName: "Audience",
    description: "Recipients the JWT is intended for.",
  },
  exp: {
    friendlyName: "Expiration Time",
    description: "Time after which the JWT must not be accepted.",
  },
  nbf: {
    friendlyName: "Not Before",
    description: "Time before which the JWT must not be accepted.",
  },
  iat: {
    friendlyName: "Issued At",
    description: "Time at which the JWT was issued.",
  },
  jti: {
    friendlyName: "JWT ID",
    description: "Unique identifier for this JWT.",
  },
};

export type ClaimValidityStatus =
  | "expired"
  | "not_yet_valid"
  | "active"
  | null;

export type InspectedClaim = {
  name: string;
  friendlyName: string | null;
  description: string | null;
  rawValue: string;
  interpretedValue: string | null;
  status: ClaimValidityStatus;
  statusLabel: string | null;
};

function isRegisteredClaim(name: string): name is RegisteredClaimName {
  return (REGISTERED_CLAIMS as readonly string[]).includes(name);
}

function formatRawValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function formatNumericDate(seconds: number): string {
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return "Invalid date";
  }

  const local = date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
  const utc = date.toLocaleString("en-US", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  });

  return `Local: ${local}\nUTC: ${utc}`;
}

function interpretAud(value: unknown): string | null {
  if (typeof value === "string") {
    return `Audience: ${value}`;
  }
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    if (value.length === 0) return "Audience: (empty list)";
    return `Audiences: ${value.join(", ")}`;
  }
  return null;
}

function statusForTimeClaim(
  claim: "exp" | "nbf",
  seconds: number,
  nowMs: number,
): { status: ClaimValidityStatus; statusLabel: string | null } {
  const claimMs = seconds * 1000;
  if (Number.isNaN(claimMs)) {
    return { status: null, statusLabel: null };
  }

  if (claim === "exp") {
    if (nowMs > claimMs) {
      return { status: "expired", statusLabel: "Expired" };
    }
    return { status: "active", statusLabel: "Not expired" };
  }

  if (nowMs < claimMs) {
    return { status: "not_yet_valid", statusLabel: "Not yet valid" };
  }
  return { status: "active", statusLabel: "Valid now" };
}

function inspectSingleClaim(
  name: string,
  value: unknown,
  nowMs: number,
): InspectedClaim {
  if (isRegisteredClaim(name)) {
    const meta = CLAIM_META[name];
    let interpretedValue: string | null = null;
    let status: ClaimValidityStatus = null;
    let statusLabel: string | null = null;

    if (name === "aud") {
      interpretedValue = interpretAud(value);
    } else if (name === "exp" || name === "nbf" || name === "iat") {
      if (isNumericDate(value)) {
        interpretedValue = formatNumericDate(value);
        if (name === "exp" || name === "nbf") {
          const timeStatus = statusForTimeClaim(name, value, nowMs);
          status = timeStatus.status;
          statusLabel = timeStatus.statusLabel;
        }
      }
    }

    return {
      name,
      friendlyName: meta.friendlyName,
      description: meta.description,
      rawValue: formatRawValue(value),
      interpretedValue,
      status,
      statusLabel,
    };
  }

  return {
    name,
    friendlyName: null,
    description: null,
    rawValue: formatRawValue(value),
    interpretedValue: null,
    status: null,
    statusLabel: null,
  };
}

export function inspectPayloadClaims(
  payload: unknown,
  now: Date = new Date(),
): InspectedClaim[] {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return [];
  }

  const record = payload as Record<string, unknown>;
  const keys = Object.keys(record);
  const registered = REGISTERED_CLAIMS.filter((name) => keys.includes(name));
  const custom = keys.filter((name) => !isRegisteredClaim(name));

  const nowMs = now.getTime();
  const ordered = [...registered, ...custom];

  return ordered.map((name) => inspectSingleClaim(name, record[name], nowMs));
}
