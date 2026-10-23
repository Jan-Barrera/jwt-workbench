import { LocalPrivacyIndicator } from "./local-privacy-indicator";

type PrivacyToolbarProps = {
  variant?: "local" | "development";
  indicatorMessage?: string;
  description: string;
  onClear: () => void;
  canClear: boolean;
  clearLabel?: string;
};

export function PrivacyToolbar({
  variant = "local",
  indicatorMessage,
  description,
  onClear,
  canClear,
  clearLabel = "Clear",
}: PrivacyToolbarProps) {
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex flex-col gap-1">
        <LocalPrivacyIndicator
          variant={variant}
          message={indicatorMessage}
        />
        <p className="text-sm text-zinc-600 dark:text-zinc-400">{description}</p>
      </div>
      <button
        type="button"
        onClick={onClear}
        disabled={!canClear}
        className="shrink-0 rounded-md border border-zinc-200 px-3 py-1.5 text-sm font-medium text-zinc-700 transition hover:bg-zinc-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-800"
      >
        {clearLabel}
      </button>
    </div>
  );
}
