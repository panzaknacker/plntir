export function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Ungültiger Zeitpunkt";
  return new Intl.DateTimeFormat("de-DE", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(parsed);
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Noch nicht gemessen";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${new Intl.NumberFormat("de-DE", { maximumFractionDigits: index === 0 ? 0 : 1 }).format(amount)} ${units[index]}`;
}
