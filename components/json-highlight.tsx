type JsonHighlightProps = {
  json: string;
};

type Token = { type: "key" | "string" | "number" | "boolean" | "null" | "punct"; text: string };

function tokenizeJson(json: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < json.length) {
    const ch = json[i];

    if (ch === '"' ) {
      let end = i + 1;
      while (end < json.length) {
        if (json[end] === "\\") {
          end += 2;
          continue;
        }
        if (json[end] === '"') {
          end += 1;
          break;
        }
        end += 1;
      }
      const raw = json.slice(i, end);
      let isKey = false;
      let j = end;
      while (j < json.length && /\s/.test(json[j])) j += 1;
      if (json[j] === ":") isKey = true;
      tokens.push({ type: isKey ? "key" : "string", text: raw });
      i = end;
      continue;
    }

    if (/[0-9-]/.test(ch)) {
      let end = i + 1;
      while (end < json.length && /[0-9.eE+-]/.test(json[end])) end += 1;
      tokens.push({ type: "number", text: json.slice(i, end) });
      i = end;
      continue;
    }

    if (json.startsWith("true", i) || json.startsWith("false", i)) {
      const word = json.startsWith("true", i) ? "true" : "false";
      tokens.push({ type: "boolean", text: word });
      i += word.length;
      continue;
    }

    if (json.startsWith("null", i)) {
      tokens.push({ type: "null", text: "null" });
      i += 4;
      continue;
    }

    tokens.push({ type: "punct", text: ch });
    i += 1;
  }

  return tokens;
}

const colorClass: Record<Token["type"], string> = {
  key: "text-sky-700 dark:text-sky-300",
  string: "text-emerald-700 dark:text-emerald-300",
  number: "text-amber-700 dark:text-amber-300",
  boolean: "text-violet-700 dark:text-violet-300",
  null: "text-zinc-500 dark:text-zinc-400",
  punct: "text-zinc-500 dark:text-zinc-400",
};

export function JsonHighlight({ json }: JsonHighlightProps) {
  const tokens = tokenizeJson(json);

  return (
    <pre
      className="overflow-x-auto font-mono text-sm leading-relaxed text-zinc-800 dark:text-zinc-100"
      aria-label="JSON"
    >
      <code>
        {tokens.map((token, index) => (
          <span key={index} className={colorClass[token.type]}>
            {token.text}
          </span>
        ))}
      </code>
    </pre>
  );
}
