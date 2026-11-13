/** The event's clocks, worded (radar.pipeline.sighting / ItemRef.collected_at decide; this only formats).
 * Live 2026-11-03, CVE-2026-98432: the page called THN's 15:57 publication 「雷达首见」; the radar captured it at 16:28. */
import type { ItemRef, Sighting } from '@/types/site-data';
import { durationZh, utcShort } from '@/utils/timeZh';

const sameDay = (a: string, b: string) => a.slice(0, 10) === b.slice(0, 10);
const hm = (iso: string) => iso.slice(11, 16);

/** Over a day between publication and capture ⇒ the report predates the radar's watch (backfill), said so. */
function lagWords(min: number | null): string {
  if (min === null) return '';
  if (min < 1) return '发布当分钟即采集';
  const d = durationZh(min * 60_000);
  return min >= 24 * 60 ? `发布 ${d}后补录` : `发布后 ${d}`;
}

export interface SightingLine { report: string; collected: string }

export function sightingLine(s: Sighting | null | undefined): SightingLine | null {
  if (!s) return null;
  // a backfilled report can be from another year — utcShort drops the year, so use the full date then
  const backfill = (s.collect_lag_minutes ?? 0) >= 24 * 60;
  const at = s.first_report_date_only ? `${backfill ? s.first_report_at.slice(0, 10) : s.first_report_at.slice(5, 10)}（只给日期）`
    : `${backfill ? `${s.first_report_at.slice(0, 10)} ${hm(s.first_report_at)}` : utcShort(s.first_report_at)} UTC`;
  return {
    report: `首报 ${at}（${s.first_report_source} 发布）`,
    // which report the radar caught first, when it is not the first report itself (THN's tweet before its article)
    collected: `雷达采集 ${utcShort(s.first_collected_at)} UTC（${s.first_collected_source && s.first_collected_source !== s.first_report_source ? `经 ${s.first_collected_source}，` : ''}${lagWords(s.collect_lag_minutes)}）`,
  };
}

/** One evidence item's time: publication and capture apart; an undated source shows capture only, labelled. */
export function itemTime(it: Pick<ItemRef, 'published_at' | 'collected_at' | 'published_is_collected' | 'date_only'>): string {
  // a date-only source (DeFiLlama, KEV dateAdded) must not read as "00:00" — that time was never stated
  const pub = it.date_only ? `${it.published_at.slice(5, 10)}（来源只给日期）` : `${utcShort(it.published_at)} UTC`;
  if (it.date_only && it.collected_at) return `发布 ${pub} · 采集 ${utcShort(it.collected_at)}`;
  if (!it.collected_at) return `发布 ${pub}`;                       // older publisher: no capture time in the doc
  if (it.published_is_collected) return `采集 ${utcShort(it.collected_at)} UTC（来源未标发布时间）`;
  const lag = Math.round((Date.parse(it.collected_at) - Date.parse(it.published_at)) / 60_000);
  if (lag < 1) return `发布 ${pub} · 当即采集`;
  const got = sameDay(it.published_at, it.collected_at) ? hm(it.collected_at) : utcShort(it.collected_at);
  return `发布 ${pub} · 采集 ${got}`;
}
