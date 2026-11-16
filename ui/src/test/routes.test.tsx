/** R3.6 — lazy pages: while a page's chunk loads, the layout says so (inside the page boundary), never a blank main. */
import { describe, expect, it, vi } from 'vitest';
import { lazy } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { ThemeProvider } from '@/contexts/ThemeContext';

describe('a page still loading', () => {
  it('shows the loading line inside the layout', () => {
    vi.stubGlobal('window', { matchMedia: () => ({ matches: false }) });   // node test env: ThemeProvider reads it
    const Never = lazy(() => new Promise<{ default: () => null }>(() => {}));
    const html = renderToStaticMarkup(
      <ThemeProvider><MemoryRouter initialEntries={['/ops']}>
        <Routes><Route path="/" element={<Layout />}><Route path="ops" element={<Never />} /></Route></Routes>
      </MemoryRouter></ThemeProvider>);
    expect(html).toContain('role="status"');
    expect(html).toContain('加载中');
    expect(html).toContain('<nav');                     // the chrome is there while the page loads
  });
});
