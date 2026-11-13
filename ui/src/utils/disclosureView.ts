/** When the world knew vs when the radar knew (radar.cvemeta.disclosure decides; this only words it).
 * Live 2026-11-02: CVE-2026-98432 was published 10-15 by the Linux CNA; the page said only 「首见 10-29」. */
import type { Disclosure } from '@/types/site-data';

/** Full date + minute: a disclosure can be years old (utcShort drops the year — CVE-2025-39682 read 「于 09-05」). */
export const fmtDisclosureAt = (iso: string): string => `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;

export interface DisclosureLine { published: string; lag: string; late: boolean }

/** Lag under a day reads as "same day"; ≥ 3 days is flagged late (Limits.LATE_DETECTION_HOURS on the backend). */
export function disclosureLine(d: Disclosure | null | undefined, fmt: (iso: string) => string): DisclosureLine | null {
  if (!d) return null;
  const by = d.assigner ? `CNA ${d.assigner}` : 'CVE 记录';
  const published = `${d.cve} 于 ${fmt(d.at)} 公开（${by}）`;
  if (d.lag_hours === null) return { published, lag: '', late: false };
  const days = Math.floor(d.lag_hours / 24);
  // resurfaced (backend decides, Limits.RESURFACED_DAYS): an old CVE back in view (KEV listing, new exploitation) —
  // "N days late" would read as a miss (live: CVE-2025-39682, KEV-listed 377 days after publication)
  if (d.resurfaced) return { published, lag: `旧漏洞，公开 ${days} 天后因新的利用/通报再次被报道`, late: false };
  const lag = d.lag_hours < 24 ? '公开当天即有报道' : `首篇报道晚于公开 ${days} 天`;
  return { published, lag, late: d.lag_hours >= 72 };
}

/** The CVE table's 「公开（CNA）」 cell: a blank must say why (live: 3 CVEs are not in the CVE List). */
export function publishedCell(c: { published_at?: string | null; assigner?: string | null; cve_record?: string | null }): string {
  if (c.published_at) return `${c.published_at.slice(0, 10)}${c.assigner ? ` · ${c.assigner}` : ''}`;
  if (c.cve_record === 'NOT_FOUND') return 'CVE 列表中暂无记录（预留或编号有误），每天复查';
  return '待查询';
}

/** List card / wall drawer chip: 「CVE 公开 10-15」 (year added when it differs from the first report's — an old CVE
 * back in the news must not read as this year's), 「旧漏洞 · CVE 公开 2025-09-05」 when resurfaced. null = no record. */
export function cardDisclosure(cd: { at: string; resurfaced: boolean } | null | undefined, firstSeen: string): string | null {
  if (!cd) return null;
  const date = cd.at.slice(0, 4) === firstSeen.slice(0, 4) ? cd.at.slice(5, 10) : cd.at.slice(0, 10);
  return `${cd.resurfaced ? '旧漏洞 · ' : ''}CVE 公开 ${date}`;
}
