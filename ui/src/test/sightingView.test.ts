import { describe, expect, it } from 'vitest';
import { itemTime, sightingLine } from '@/utils/sightingView';

describe('sightingLine (CVE-2026-98432: THN 15:57, radar 16:28)', () => {
  it('keeps the first report and the radar capture apart', () => {
    const l = sightingLine({ first_report_at: '2026-10-29T15:57:05Z', first_report_source: 'The Hacker News',
      first_collected_at: '2026-10-29T16:28:30Z', first_collected_source: 'The Hacker News', collect_lag_minutes: 31 })!;
    expect(l.report).toBe('首报 10-29 15:57 UTC（The Hacker News 发布）');
    expect(l.collected).toBe('雷达采集 10-29 16:28 UTC（发布后 31 分钟）');
  });
  it('a backfilled report says so', () => {
    const l = sightingLine({ first_report_at: '2025-09-05T00:00:00Z', first_report_source: 'CISA KEV',
      first_collected_at: '2026-09-18T00:00:00Z', first_collected_source: 'CISA KEV', collect_lag_minutes: 378 * 24 * 60, first_report_date_only: false })!;
    expect(l.collected).toContain('发布 378 天后补录');
    expect(l.report).toBe('首报 2025-09-05 00:00 UTC（CISA KEV 发布）');
  });
  it('names the report caught first when it is not the first report', () => {
    const l = sightingLine({ first_report_at: '2026-10-29T15:57:05Z', first_report_source: 'The Hacker News',
      first_collected_at: '2026-10-29T16:28:30Z', first_collected_source: 'X @TheHackersNews', collect_lag_minutes: 31 })!;
    expect(l.collected).toBe('雷达采集 10-29 16:28 UTC（经 X @TheHackersNews，发布后 31 分钟）');
  });
  it('a date-only first report says so (KEV dateAdded)', () => {
    const l = sightingLine({ first_report_at: '2026-09-18T00:00:00Z', first_report_source: 'CISA KEV', first_report_date_only: true,
      first_collected_at: '2026-10-23T05:14:00Z', first_collected_source: 'CISA KEV', collect_lag_minutes: 35 * 24 * 60 + 314 })!;
    expect(l.report).toBe('首报 2026-09-18（只给日期）（CISA KEV 发布）');
  });
  it('nothing without a sighting', () => { expect(sightingLine(null)).toBeNull(); });
});

describe('itemTime', () => {
  it('publication and capture apart, capture without the date on the same day', () => {
    expect(itemTime({ published_at: '2026-10-29T15:57:05Z', collected_at: '2026-10-29T16:28:30Z', published_is_collected: false }))
      .toBe('发布 10-29 15:57 UTC · 采集 16:28');
  });
  it('a date-only source does not show a made-up 00:00', () => {
    expect(itemTime({ published_at: '2026-10-29T00:00:00Z', collected_at: '2026-10-30T00:18:00Z', published_is_collected: false, date_only: true }))
      .toBe('发布 10-29（来源只给日期） · 采集 10-30 00:18');
  });
  it('an undated source shows the capture time, labelled', () => {
    expect(itemTime({ published_at: '2026-10-29T16:28:30Z', collected_at: '2026-10-29T16:28:30Z', published_is_collected: true }))
      .toBe('采集 10-29 16:28 UTC（来源未标发布时间）');
  });
  it('a capture on another day keeps its date; an older doc shows publication only', () => {
    expect(itemTime({ published_at: '2026-10-29T23:50:00Z', collected_at: '2026-10-30T00:20:00Z', published_is_collected: false }))
      .toBe('发布 10-29 23:50 UTC · 采集 10-30 00:20');
    expect(itemTime({ published_at: '2026-10-29T15:57:05Z' })).toBe('发布 10-29 15:57 UTC');
  });
});
