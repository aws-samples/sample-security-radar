/** R3.2 — what the page says when it cannot show what it was asked for. */
import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { PageBoundary } from '@/components/PageBoundary';
import { compactUsd, formatAmount } from '@/utils/formatters';
import { fmtUsd } from '@/utils/attackTxView';

describe('amounts', () => {
  it('choose the unit after rounding: never 「$1000.0K」', () => {
    expect(formatAmount(999_960)).toBe('$1.0M');
    expect(formatAmount(999_940)).toBe('$999.9K');
    expect(formatAmount(999_999_999)).toBe('$1.00B');
    expect(formatAmount(1_234)).toBe('$1.2K');
    expect(formatAmount(950)).toBe('$950');
    expect(fmtUsd(999_960)).toBe('$1.00M');
    expect(compactUsd(-2_500_000, { B: 2, M: 1, K: 1 })).toBe('$-2.5M');
  });
});

describe('a page that throws', () => {
  it('shows a failure for that page, with the reason, instead of a white screen', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const Boom = () => { throw new Error('unknown stage "pivot"'); };
    const state = PageBoundary.getDerivedStateFromError(new Error('unknown stage "pivot"'));
    expect(state).toEqual({ error: new Error('unknown stage "pivot"') });
    const b = new PageBoundary({ resetKey: '/events/x', children: <Boom /> });
    b.state = { error: new Error('unknown stage "pivot"'), key: '/events/x' };
    const html = renderToStaticMarkup(<>{b.render()}</>);
    expect(html).toContain('这一页显示失败') ;
    expect(html).toContain('unknown stage');
    // another route clears it
    expect(PageBoundary.getDerivedStateFromProps({ resetKey: '/', children: null }, b.state)).toEqual({ error: null, key: '/' });
    expect(PageBoundary.getDerivedStateFromProps({ resetKey: '/events/x', children: null }, b.state)).toBeNull();
  });
});
