import { decodeJwt, type JwtDecodeError, type JwtDecodeResult } from "./decode";

export type CompareFieldKind = "added" | "removed" | "changed" | "unchanged";

export type CompareFieldDiff = {
  path: string;
  kind: CompareFieldKind;
  rawValueA: string | null;
  rawValueB: string | null;
  interpretedValueA: string | null;
  interpretedValueB: string | null;
};

export type CompareSectionSummary = {
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
};

export type CompareSection = {
  fields: CompareFieldDiff[];
  summary: CompareSectionSummary;
};

export type JwtCompareSuccess = {
  ok: true;
  header: CompareSection;
  payload: CompareSection;
  signaturesDiffer: boolean;
};

export type JwtCompareError = {
  ok: false;
  token: "A" | "B";
  error: string;
  code: JwtDecodeError["code"];
  part?: JwtDecodeError["part"];
};

export type JwtCompareResult = JwtCompareSuccess | JwtCompareError;

const TIME_CLAIMS = new Set(["exp", "nbf", "iat"]);

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

function leafName(path: string): string {
  const bracket = path.lastIndexOf("[");
  const dot = path.lastIndexOf(".");
  const splitAt = Math.max(bracket, dot);
  if (splitAt === -1) return path;
  if (splitAt === bracket) {
    return path.slice(0, bracket);
  }
  return path.slice(splitAt + 1);
}

function interpretValue(path: string, value: unknown): string | null {
  const name = leafName(path);
  if (TIME_CLAIMS.has(name) && isNumericDate(value)) {
    return formatNumericDate(value);
  }
  if (name === "aud") {
    if (typeof value === "string") return `Audience: ${value}`;
    if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
      if (value.length === 0) return "Audience: (empty list)";
      return `Audiences: ${value.join(", ")}`;
    }
  }
  return null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, index) => deepEqual(item, b[index]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    return keysA.every((key) => deepEqual(a[key], b[key]));
  }
  return false;
}

function pushField(
  out: CompareFieldDiff[],
  path: string,
  kind: CompareFieldKind,
  valueA: unknown | undefined,
  valueB: unknown | undefined,
): void {
  out.push({
    path,
    kind,
    rawValueA: valueA === undefined ? null : formatRawValue(valueA),
    rawValueB: valueB === undefined ? null : formatRawValue(valueB),
    interpretedValueA:
      valueA === undefined ? null : interpretValue(path, valueA),
    interpretedValueB:
      valueB === undefined ? null : interpretValue(path, valueB),
  });
}

function expandSubtree(
  value: unknown,
  path: string,
  kind: "added" | "removed",
  out: CompareFieldDiff[],
): void {
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) {
      pushField(out, path, kind, kind === "removed" ? value : undefined, kind === "added" ? value : undefined);
      return;
    }
    for (const key of keys) {
      expandSubtree(value[key], path ? `${path}.${key}` : key, kind, out);
    }
    return;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      pushField(out, path, kind, kind === "removed" ? value : undefined, kind === "added" ? value : undefined);
      return;
    }
    for (let index = 0; index < value.length; index += 1) {
      expandSubtree(value[index], `${path}[${index}]`, kind, out);
    }
    return;
  }

  pushField(
    out,
    path,
    kind,
    kind === "removed" ? value : undefined,
    kind === "added" ? value : undefined,
  );
}

function compareValues(
  valueA: unknown,
  valueB: unknown,
  path: string,
  out: CompareFieldDiff[],
): void {
  if (deepEqual(valueA, valueB)) {
    if (path) {
      pushField(out, path, "unchanged", valueA, valueB);
      return;
    }

    if (isPlainObject(valueA) && isPlainObject(valueB)) {
      const keys = [...new Set([...Object.keys(valueA), ...Object.keys(valueB)])].sort();
      for (const key of keys) {
        compareValues(valueA[key], valueB[key], key, out);
      }
      return;
    }

    if (Array.isArray(valueA) && Array.isArray(valueB)) {
      for (let index = 0; index < valueA.length; index += 1) {
        compareValues(valueA[index], valueB[index], `[${index}]`, out);
      }
    }
    return;
  }

  if (isPlainObject(valueA) && isPlainObject(valueB)) {
    const keys = [...new Set([...Object.keys(valueA), ...Object.keys(valueB)])].sort();
    for (const key of keys) {
      const childPath = path ? `${path}.${key}` : key;
      const inA = Object.prototype.hasOwnProperty.call(valueA, key);
      const inB = Object.prototype.hasOwnProperty.call(valueB, key);
      if (inA && inB) {
        compareValues(valueA[key], valueB[key], childPath, out);
      } else if (inA) {
        expandSubtree(valueA[key], childPath, "removed", out);
      } else {
        expandSubtree(valueB[key], childPath, "added", out);
      }
    }
    return;
  }

  if (Array.isArray(valueA) && Array.isArray(valueB)) {
    const maxLength = Math.max(valueA.length, valueB.length);
    for (let index = 0; index < maxLength; index += 1) {
      const childPath = `${path}[${index}]`;
      if (index >= valueA.length) {
        expandSubtree(valueB[index], childPath, "added", out);
      } else if (index >= valueB.length) {
        expandSubtree(valueA[index], childPath, "removed", out);
      } else {
        compareValues(valueA[index], valueB[index], childPath, out);
      }
    }
    return;
  }

  if (path) {
    pushField(out, path, "changed", valueA, valueB);
  }
}

function summarize(fields: CompareFieldDiff[]): CompareSectionSummary {
  return fields.reduce<CompareSectionSummary>(
    (acc, field) => {
      acc[field.kind] += 1;
      return acc;
    },
    { added: 0, removed: 0, changed: 0, unchanged: 0 },
  );
}

function compareSection(valueA: unknown, valueB: unknown): CompareSection {
  const fields: CompareFieldDiff[] = [];
  compareValues(valueA, valueB, "", fields);
  const flattened = fields.filter((field) => field.path.length > 0);
  return {
    fields: flattened,
    summary: summarize(flattened),
  };
}

function decodeToken(
  raw: string,
  token: "A" | "B",
): JwtDecodeResult | JwtCompareError {
  const result = decodeJwt(raw);
  if (result.ok) {
    return result;
  }
  return {
    ok: false,
    token,
    error: result.error,
    code: result.code,
    part: result.part,
  };
}

export function compareJwts(tokenA: string, tokenB: string): JwtCompareResult {
  const decodedA = decodeToken(tokenA, "A");
  if (!decodedA.ok && "token" in decodedA) {
    return decodedA;
  }

  const decodedB = decodeToken(tokenB, "B");
  if (!decodedB.ok && "token" in decodedB) {
    return decodedB;
  }

  const successA = decodedA as Extract<JwtDecodeResult, { ok: true }>;
  const successB = decodedB as Extract<JwtDecodeResult, { ok: true }>;

  return {
    ok: true,
    header: compareSection(successA.header, successB.header),
    payload: compareSection(successA.payload, successB.payload),
    signaturesDiffer:
      successA.segments.signature !== successB.segments.signature,
  };
}

export function filterChangedFields(fields: CompareFieldDiff[]): CompareFieldDiff[] {
  return fields.filter((field) => field.kind !== "unchanged");
}
