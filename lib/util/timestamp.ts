export type TimestampUnit = "seconds" | "milliseconds";

export type TimestampSuccess = {
  ok: true;
  raw: string;
  unit: TimestampUnit;
  epochSeconds: number;
  utc: string;
  local: string;
};

export type TimestampError = {
  ok: false;
  message: string;
};

export type TimestampResult = TimestampSuccess | TimestampError;

const DATE_FORMAT: Intl.DateTimeFormatOptions = {
  dateStyle: "full",
  timeStyle: "long",
};

function formatUtc(date: Date): string {
  return date.toLocaleString("en-US", {
    ...DATE_FORMAT,
    timeZone: "UTC",
  });
}

function formatLocal(date: Date): string {
  return date.toLocaleString(undefined, DATE_FORMAT);
}

function parseNumericTimestamp(value: string): TimestampResult {
  if (!/^-?\d+$/.test(value)) {
    return {
      ok: false,
      message: "Enter a whole-number Unix timestamp (seconds or milliseconds).",
    };
  }

  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric)) {
    return {
      ok: false,
      message: "Timestamp is too large to represent safely.",
    };
  }

  let unit: TimestampUnit;
  let epochSeconds: number;

  if (value.length >= 13) {
    unit = "milliseconds";
    epochSeconds = numeric / 1000;
  } else {
    unit = "seconds";
    epochSeconds = numeric;
  }

  const date = new Date(epochSeconds * 1000);
  if (Number.isNaN(date.getTime())) {
    return { ok: false, message: "Timestamp does not represent a valid date." };
  }

  return {
    ok: true,
    raw: value,
    unit,
    epochSeconds,
    utc: formatUtc(date),
    local: formatLocal(date),
  };
}

export function convertUnixTimestamp(input: string): TimestampResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, message: "Enter a Unix timestamp." };
  }

  return parseNumericTimestamp(trimmed);
}
