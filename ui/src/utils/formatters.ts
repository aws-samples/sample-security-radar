/**
 * Utility formatters for amounts, dates, durations.
 * All formatting is pure (no side effects), making it unit-testable.
 */

/** Format USD amount with appropriate suffix (K/M/B) */
export function formatAmount(usd: number): string {
  return compactUsd(usd, { B: 2, M: 1, K: 1 }) ?? `$${usd.toLocaleString()}`;
}

/** "$1.0M", "$950.0K" … with the unit chosen AFTER rounding: $999,960 rounds to 1000.0 K, which is $1.0M (audit 03:
 *  the page showed 「$1000.0K」). digits = decimals per unit. Below $1K: null (the caller formats it). */
export function compactUsd(v: number, digits: { B: number; M: number; K: number }): string | null {
  const a = Math.abs(v);
  const units: [string, number][] = [['B', 1e9], ['M', 1e6], ['K', 1e3]];
  for (let i = 0; i < units.length; i++) {
    const [u, n] = units[i];
    if (a < n) continue;
    const shown = (v / n).toFixed(digits[u as 'B' | 'M' | 'K']);
    if (i > 0 && Math.abs(Number(shown)) >= 1000) {           // rounded up into the next unit
      const [up, un] = units[i - 1];
      return `$${(v / un).toFixed(digits[up as 'B' | 'M' | 'K'])}${up}`;
    }
    return `$${shown}${u}`;
  }
  return null;
}

/** ISO timestamp → "Oct 23, 09:45 UTC" */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', timeZone: 'UTC',
  }) + ', ' + d.toLocaleTimeString('en-US', {
    hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC',
  }) + ' UTC';
}

/** ISO timestamp → relative "3h ago" / "2d ago" */
export function formatRelative(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 1)    return 'just now';
  if (diffMin < 60)   return `${diffMin}m ago`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24)     return `${diffH}h ago`;
  const diffD = Math.floor(diffH / 24);
  if (diffD < 30)     return `${diffD}d ago`;
  const diffMo = Math.floor(diffD / 30);
  return `${diffMo}mo ago`;
}

/** Duration between two ISO timestamps: "3h 14m" */
export function formatDuration(fromIso: string, toIso: string): string {
  const diffMs = new Date(toIso).getTime() - new Date(fromIso).getTime();
  if (diffMs < 0) return '—';
  const totalMin = Math.floor(diffMs / 60_000);
  if (totalMin < 60)  return `${totalMin}m`;
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h < 24) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return rh > 0 ? `${d}d ${rh}h` : `${d}d`;
}

/** Truncate tx hash: "0x7f3a…9f0a" */
export function truncateHash(hash: string, chars = 6): string {
  if (hash.length <= chars * 2 + 2) return hash;
  return `${hash.slice(0, chars + 2)}…${hash.slice(-chars)}`;
}

/** EPSS score → "97.4%" */
export function formatEpss(epss: number): string {
  return `${(epss * 100).toFixed(1)}%`;
}
