/** AWS's own fix status on the event page (radar.awsfix; Neo 2026-11-18: highlight what AWS fixed). */
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { AwsFixPanel } from '@/components/detail/AwsFixPanel';
import type { AwsFix } from '@/types/site-data';

const FIX: AwsFix = {
  cve: 'CVE-2026-114938', url: 'https://explore.alas.aws.amazon.com/CVE-2026-114938.html', checked_at: '2026-11-18T02:01:00Z',
  line: '🟧 AWS 已修复：Corretto 17/21/25/27 ｜ 不受影响：Corretto 8/11、Graviton',
  summary: {
    fixed: [{ package: 'Corretto 17', platforms: ['Amazon Linux 2023'] }],
    no_fix: [{ package: 'Corretto 22', platforms: ['Amazon Linux 2023'] }],
    not_affected: [{ package: 'Corretto 8', platforms: ['Amazon Linux 2 - Corretto8 Extra'] }],
    advisories: ['ALAS2023-2026-3478'],
  },
};

describe('AwsFixPanel', () => {
  it('leads with what AWS fixed, then what it will not fix, then what is not affected, with the source', () => {
    const html = renderToStaticMarkup(<AwsFixPanel fix={FIX} />);
    expect(html).toContain('🟧 AWS 已修复：Corretto 17/21/25/27');
    const order = ['已修复', '不出修复', '不受影响'].map(w => html.indexOf(`>${w}<`));
    expect(order.every(i => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).not.toContain('>待修复<');
    expect(html).toContain('href="https://explore.alas.aws.amazon.com/CVE-2026-114938.html"');
    expect(html).toContain('ALAS2023-2026-3478');
  });
  it('says nothing when AWS status is unknown', () => {
    expect(renderToStaticMarkup(<AwsFixPanel fix={null} />)).toBe('');
  });
});
