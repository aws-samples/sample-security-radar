/**
 * Utility formatters for amounts, dates, durations.
 * All formatting is pure (no side effects), making it unit-testable.
 */

/** Format USD amount with appropriate suffix (K/M/B) */
export function formatAmount(usd: number): string {
  if (usd >= 1_000_000_000) return `$${(usd / 1_000_000_000).toFixed(2)}B`;
  if (usd >= 1_000_000)     return `$${(usd / 1_000_000).toFixed(1)}M`;
  if (usd >= 1_000)         return `$${(usd / 1_000).toFixed(1)}K`;
  return `$${usd.toLocaleString()}`;
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
