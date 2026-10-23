export type JsonFormatMode = "pretty" | "minify";

export type JsonFormatSuccess = {
  ok: true;
  output: string;
};

export type JsonFormatError = {
  ok: false;
  message: string;
};

export type JsonFormatResult = JsonFormatSuccess | JsonFormatError;

function formatParseError(error: unknown): string {
  if (error instanceof SyntaxError) {
    const match = /position (\d+)/i.exec(error.message);
    if (match) {
      return `Invalid JSON near character ${match[1]}. Check quotes, commas, and brackets.`;
    }
    return "Invalid JSON. Check quotes, commas, and brackets.";
  }
  return "Invalid JSON.";
}

export function formatJson(text: string, mode: JsonFormatMode): JsonFormatResult {
  const trimmed = text.trim();
  if (!trimmed) {
    return { ok: false, message: "Paste JSON to format." };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (error) {
    return { ok: false, message: formatParseError(error) };
  }

  try {
    const output =
      mode === "pretty"
        ? JSON.stringify(parsed, null, 2)
        : JSON.stringify(parsed);
    return { ok: true, output };
  } catch {
    return { ok: false, message: "Value could not be serialized as JSON." };
  }
}
