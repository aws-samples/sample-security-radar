import { Suspense, useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { PageBoundary } from '@/components/PageBoundary';
import { SiteStatus } from '@/components/SiteStatus';
import { NavIcon, type NavIconName } from '@/components/nav/NavIcon';
import { useTheme } from '@/contexts/ThemeContext';
import { initialNavMode, isWallPath, storeNavMode, type NavMode } from '@/utils/navMode';

const navItems: { to: string; label: string; icon: NavIconName; exact?: boolean; aria?: string }[] = [
  { to: '/',        label: 'Radar',   icon: 'radar', exact: true },
  { to: '/vuln',    label: 'Vulnerabilities', icon: 'vuln' },
  { to: '/web3',    label: 'Web3',    icon: 'web3' },
  { to: '/wall',    label: 'Dashboard', icon: 'wall', aria: 'Dashboard（大屏）' },
  { to: '/continuum', label: 'Continuum', icon: 'continuum', aria: 'AWS Continuum 融入' },
  { to: '/search', label: 'Search', icon: 'search', aria: 'Search · 搜索全部事件' },
  { to: '/announcements', label: 'Exchange Notices', icon: 'announce', aria: 'Exchange Notices · 交易所公告' },
  { to: '/subscribe', label: 'Subscribe', icon: 'subscribe', aria: 'Subscribe · 订阅：feed / webhook / agent' },
  { to: '/sources', label: 'Sources', icon: 'sources' },
  { to: '/ops',     label: 'Ops',     icon: 'ops', aria: 'Ops · 需要人处理的事' },
  { to: '/mitigate', label: 'Mitigation', icon: 'mitigate', aria: 'Mitigation · 缓解（WAF / DNS Firewall / Inspector）' },
];

/** The app shell (styles/layout.css): sidebar ↔ icon rail from 800 px (R9.1), top bar + menu below (R9.2). */
export function Layout() {
  const { pathname } = useLocation();
  const { theme, toggle } = useTheme();
  const [mode, setMode] = useState<NavMode>(initialNavMode);
  const [open, setOpen] = useState(false);            // the phone menu; any navigation closes it
  const onWall = isWallPath(pathname);
  useEffect(() => { setOpen(false); }, [pathname]);
  // Neo 2026-11-19: opening the wall collapses the sidebar to its rail (the wall gets the room); leaving it restores
  // the remembered choice. Expanding on the wall is for that visit only — it is not stored.
  useEffect(() => { setMode(onWall ? 'rail' : initialNavMode()); }, [onWall]);
  const rail = mode === 'rail';
  const flip = () => { const next: NavMode = rail ? 'full' : 'rail'; setMode(next); if (!onWall) storeNavMode(next); };

  return (
    <div className={`app-shell${rail ? ' is-rail' : ''}`} data-nav={mode}>
      <nav aria-label="Main navigation" className={`app-nav${open ? ' is-open' : ''}`}>
        <div className="accent-stripe" />

        <div className="app-nav-brand">
          <button type="button" className="app-nav-btn app-nav-toggle" aria-expanded={open} aria-controls="app-nav-menu"
            aria-label={open ? '收起导航' : '展开导航'} onClick={() => setOpen(o => !o)}>
            <NavIcon name={open ? 'close' : 'menu'} />
          </button>
          <div className="app-nav-logo">
            <img src="./logo.svg" alt="" aria-hidden="true" width={36} height={36}
              onError={e => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }} style={{ flexShrink: 0 }} />
            <div>
              <div className="app-nav-word is-accent">Security</div>
              <div className="app-nav-word" style={{ color: 'var(--text-primary)' }}>Radar</div>
            </div>
          </div>
          <div className="app-nav-live">
            <span style={{ position: 'relative', display: 'inline-flex', width: 8, height: 8 }}>
              <span style={{ position: 'absolute', inset: 0, borderRadius: '50%', background: 'var(--status-ok)',
                animation: 'pulse-ring 1.8s ease-out infinite' }} aria-hidden="true" />
              <span style={{ position: 'relative', width: 8, height: 8, borderRadius: '50%', background: 'var(--status-ok)',
                display: 'block' }} aria-hidden="true" />
            </span>
            <span>live</span>
          </div>
        </div>

        <div id="app-nav-menu" className="app-nav-links">
          {navItems.map(item => (
            <NavLink key={item.to} to={item.to} end={item.exact} className="app-nav-link"
              aria-label={item.aria ?? item.label} title={rail ? item.label : undefined}>
              <NavIcon name={item.icon} />
              <span className="app-nav-label">{item.label}</span>
            </NavLink>
          ))}
        </div>

        <div className="app-nav-foot">
          <div className="app-nav-status"><SiteStatus /></div>
          <button type="button" className="app-nav-btn" onClick={toggle}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`} title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}>
            <NavIcon name={theme === 'light' ? 'moon' : 'sun'} size={15} />
            <span className="app-nav-btn-text">{theme === 'light' ? 'Dark' : 'Light'}</span>
          </button>
          <button type="button" className="app-nav-btn app-nav-collapse" onClick={flip} data-testid="nav-collapse"
            aria-label={rail ? '展开侧栏' : '收起侧栏'} title={rail ? '展开侧栏' : '收起侧栏'} aria-pressed={rail}>
            <NavIcon name={rail ? 'expand' : 'collapse'} size={16} />
          </button>
        </div>
      </nav>

      <main className="app-main">
        <PageBoundary resetKey={pathname}>
          {/* R3.6: lazy pages (App.tsx). Inside the boundary: a chunk that fails to load (an old tab after a deploy) shows
              the page error with its retry, not a blank page */}
          <Suspense fallback={<p className="page-loading" role="status">加载中…</p>}><Outlet /></Suspense>
        </PageBoundary>
      </main>
    </div>
  );
}
