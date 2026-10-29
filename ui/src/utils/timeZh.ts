/** Chinese time wording for the detail page (pure; tested in src/test/evidence.test.ts). */

/** ms → "0 分钟" / "2 小时 5 分" / "2 天 9 小时". Negative ⇒ null (caller shows "—"). */
export function durationZh(ms: number | null): string | null {
  if (ms === null || Number.isNaN(ms) || ms < 0) return null;
  const min = Math.floor(ms / 60_000);
  if (min < 60) return `${min} 分钟`;
  const h = Math.floor(min / 60), m = min % 60;
  if (h < 24) return m ? `${h} 小时 ${m} 分` : `${h} 小时`;
  const d = Math.floor(h / 24), rh = h % 24;
  return rh ? `${d} 天 ${rh} 小时` : `${d} 天`;
}

/** ISO → "3 天前"; future (client clock skew) ⇒ "刚刚" rather than a negative age. */
export function agoZh(iso: string, nowMs: number = Date.now()): string {
  const d = nowMs - Date.parse(iso);
  if (Number.isNaN(d)) return '—';
  if (d < 60_000) return '刚刚';
  return `${durationZh(d)}前`;
}

/** ISO → "10-21 07:00" (UTC; callers append "UTC" once per block, not per value). */
export function utcShort(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return '—';
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(t.getUTCMonth() + 1)}-${p(t.getUTCDate())} ${p(t.getUTCHours())}:${p(t.getUTCMinutes())}`;
}
