import { describe, expect, it } from 'vitest';
import { cardDisclosure, disclosureLine, fmtDisclosureAt, publishedCell } from '@/utils/disclosureView';

const fmt = (iso: string) => iso.slice(0, 10);

describe('disclosureLine', () => {
  it('states the CVE publication and the radar lag (CVE-2026-98432: 10-15 vs 10-29)', () => {
    const l = disclosureLine({ at: '2026-10-15T12:08:22Z', cve: 'CVE-2026-98432', assigner: 'Linux', lag_hours: 339.8, resurfaced: false }, fmt)!;
    expect(l.published).toBe('CVE-2026-98432 于 2026-10-15 公开（CNA Linux）');
    expect(l.lag).toBe('首篇报道晚于公开 14 天');
    expect(l.late).toBe(true);
  });
  it('a same-day sighting is not late', () => {
    const l = disclosureLine({ at: '2026-10-15T00:00:00Z', cve: 'CVE-1', assigner: null, lag_hours: 5, resurfaced: false }, fmt)!;
    expect(l.lag).toBe('公开当天即有报道');
    expect(l.late).toBe(false);
    expect(l.published).toContain('CVE 记录');
  });
  it('a resurfaced CVE is not worded as a late detection (CVE-2025-39682 via KEV)', () => {
    const l = disclosureLine({ at: '2025-09-05T00:00:00Z', cve: 'CVE-2025-39682', assigner: 'Linux', lag_hours: 377.3 * 24, resurfaced: true }, fmt)!;
    expect(l.lag).toBe('旧漏洞，公开 377 天后因新的利用/通报再次被报道');
    expect(l.late).toBe(false);
  });
  it('the date keeps its year (a 2025 CVE must not read as this year)', () => {
    expect(fmtDisclosureAt('2025-09-05T17:20:48Z')).toBe('2025-09-05 17:20 UTC');
  });
  it('no CVE record ⇒ nothing', () => {
    expect(disclosureLine(null, fmt)).toBeNull();
    expect(disclosureLine(undefined, fmt)).toBeNull();
  });
});

describe('publishedCell', () => {
  it('a blank says why', () => {
    expect(publishedCell({ published_at: '2026-10-15T12:08:22Z', assigner: 'Linux' })).toBe('2026-10-15 · Linux');
    expect(publishedCell({ published_at: null, cve_record: 'NOT_FOUND' })).toBe('CVE 列表中暂无记录（预留或编号有误），每天复查');
    expect(publishedCell({ published_at: null, cve_record: null })).toBe('待查询');
  });
});

describe('cardDisclosure', () => {
  it('CVE-2026-98432: published 10-15, first reported 10-29', () => {
    expect(cardDisclosure({ at: '2026-10-15T12:08:22Z', resurfaced: false }, '2026-10-29T15:57:05Z')).toBe('CVE 公开 10-15');
  });
  it('an old CVE keeps its year and says so', () => {
    expect(cardDisclosure({ at: '2025-09-05T17:20:48Z', resurfaced: true }, '2026-09-18T00:00:00Z')).toBe('旧漏洞 · CVE 公开 2025-09-05');
  });
  it('no record ⇒ nothing', () => { expect(cardDisclosure(null, '2026-10-29T00:00:00Z')).toBeNull(); });
});
