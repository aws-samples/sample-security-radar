import { NavLink, Outlet } from 'react-router-dom';
import { useTheme } from '@/contexts/ThemeContext';

const navItems = [
  { to: '/',        label: 'Radar',   icon: '⬡', exact: true },
  { to: '/vuln',    label: 'Vulns',   icon: '◈' },
  { to: '/web3',    label: 'Web3',    icon: '◎' },
  { to: '/wall',    label: '大屏',    icon: '⊞' },
  { to: '/continuum', label: 'Continuum', icon: '⟲', aria: 'AWS Continuum 融入' },
  { to: '/sources', label: 'Sources', icon: '◉' },
  { to: '/ops',     label: 'Ops',     icon: '⚑', aria: '需要人处理的事' },
  { to: '/mitigate', label: '缓解',  icon: '⛨', aria: '缓解（WAF / DNS Firewall / Inspector）' },
];

export function Layout() {
  const { theme, toggle } = useTheme();

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar */}
      <nav
        aria-label="Main navigation"
        style={{
          width: 'var(--sidebar-w)',
          flexShrink: 0,
          background: 'var(--bg-surface)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          overflowY: 'auto',
          boxShadow: 'var(--shadow-sm)',
          zIndex: 10,
        }}
      >
        {/* Accent stripe */}
        <div className="accent-stripe" />

        {/* Wordmark */}
        <div style={{
          padding: '16px 16px 14px',
          borderBottom: '1px solid var(--border)',
        }}>
          {/* Logo: try image, fall back to text */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <img
              src="./logo.svg"
              alt=""
              aria-hidden="true"
              width={36}
              height={36}
              onError={e => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }}
              style={{ flexShrink: 0 }}
            />
            <div>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '15px',
                fontWeight: 700,
                background: 'var(--grad-accent)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
                letterSpacing: '-0.01em',
                lineHeight: 1.1,
              }}>
                Security
              </div>
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: '15px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '-0.01em',
                lineHeight: 1.1,
              }}>
                Radar
              </div>
            </div>
          </div>

          {/* Live indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ position: 'relative', display: 'inline-flex', width: '8px', height: '8px' }}>
              <span style={{
                position: 'absolute', inset: 0,
                borderRadius: '50%',
                background: 'var(--status-ok)',
                animation: 'pulse-ring 1.8s ease-out infinite',
              }} aria-hidden="true" />
              <span style={{
                position: 'relative',
                width: '8px', height: '8px', borderRadius: '50%',
                background: 'var(--status-ok)',
                display: 'block',
              }} aria-hidden="true" />
            </span>
            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              live
            </span>
          </div>
        </div>

        {/* Nav links */}
        <div style={{ padding: '8px 0', flex: 1 }}>
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.exact}
              aria-label={'aria' in item ? item.aria : item.label}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '9px 16px',
                fontFamily: 'var(--font-body)',
                fontSize: '13px',
                fontWeight: isActive ? 600 : 400,
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                background: isActive ? 'var(--bg-surface-2)' : 'transparent',
                borderLeft: `3px solid ${isActive ? 'var(--text-accent)' : 'transparent'}`,
                textDecoration: 'none',
                transition: 'color 0.15s, background 0.15s, border-color 0.15s',
              })}
              onMouseEnter={e => {
                const el = e.currentTarget as HTMLAnchorElement;
                if (!el.classList.contains('active') && el.style.borderLeftColor === 'transparent') {
                  el.style.background = 'var(--bg-surface-2)';
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLAnchorElement;
                if (!el.getAttribute('aria-current')) {
                  el.style.background = 'transparent';
                }
              }}
            >
              <span aria-hidden="true" style={{ fontSize: '14px', opacity: 0.75 }}>{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </div>

        {/* Theme toggle + footer */}
        <div style={{
          padding: '10px 12px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {import.meta.env.DEV ? 'mock' : 'live'}
          </span>
          <button
            onClick={toggle}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
            style={{
              background: 'var(--bg-surface-2)',
              border: '1px solid var(--border)',
              borderRadius: '20px',
              padding: '4px 10px',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '5px',
              transition: 'background 0.15s, color 0.15s',
              cursor: 'pointer',
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-surface-3)';
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-surface-2)';
            }}
          >
            <span aria-hidden="true">{theme === 'light' ? '🌙' : '☀️'}</span>
            <span>{theme === 'light' ? 'Dark' : 'Light'}</span>
          </button>
        </div>
      </nav>

      {/* Main content */}
      <main
        style={{
          flex: 1,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--bg-base)',
        }}
      >
        <Outlet />
      </main>
    </div>
  );
}
