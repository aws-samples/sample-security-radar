/** Root-cause title correction (radar.retitle): one line under the title saying it was corrected, by whom, from what. */
import type { EventSummary } from '@/types/site-data';
import { safeHref } from '@/utils/safeHref';

export interface TitleFix { text: string; href: string | undefined; host: string; original: string }

/** null when the title is the structured record's own; the source link only if it is a safe https URL. */
export function titleFix(ev: Pick<EventSummary, 'title_override'>, fmt: (iso: string) => string): TitleFix | null {
  const f = ev.title_override;
  if (!f) return null;
  const href = safeHref(f.source);
  let host = '';
  try { host = new URL(f.source).hostname.replace(/^www\./, ''); } catch { host = ''; }
  return { text: `标题已按根因修正 · ${f.by} · ${fmt(f.at)}${f.note ? ` · ${f.note}` : ''}`, href, host, original: f.original };
}
