/**
 * WallPage v3 — full-screen 1920×1080 situational-awareness dashboard.
 *
 * Layout (§3):
 *   Status bar 40px  — LIVE · sources · countdown ring · theme · fullscreen · back
 *   ┌────────────┬──────────────────────────────┬────────────────┐
 *   │ Left 340px │ Center: hero KPIs + RadarScope │ Right 340px   │
 *   │ Event stream│ (fills middle)               │ Loss / Chain / │
 *   │ ≥12 cards  │                              │ Vuln panels    │
 *   └────────────┴──────────────────────────────┴────────────────┘
 *   Bottom 180px — isometric block band (24h) + 5-row ticker
 *
 * Reading order (UI-IA §4, spec 01 §6.2): radar with the 3 NOW leader labels → right column NOW board (same ranks,
 * impact chip) → Web3 loss → vuln. Every object opens the L2 EventDrawer (`?event=<id>`), never leaves the wall.
 * Preserves: staleness logic, health.ts, 24h-loss calculation.
 */
import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useEvents } from '@/hooks/useEvents';
import { useSources } from '@/hooks/useSources';
import { useTheme } from '@/contexts/ThemeContext';
import { freshness } from '@/utils/staleness';
import { formatAmount, formatRelative } from '@/utils/formatters';
import { sortEvents } from '@/utils/filters';
import { computeHourBuckets, computeRadarLayout, clusterDots } from '@/utils/radarLayout';
import { radarDotsTo3D } from '@/utils/radar3dLayout';
import type { RadarDot } from '@/utils/radarLayout';
import { RadarScope } from '@/components/radar/RadarScope';
import { ScopeWithLabels } from '@/components/radar/ScopeWithLabels';
import { WallNowBoard } from '@/components/wall/WallNowBoard';
import { EventDrawer } from '@/components/wall/EventDrawer';
import { ImpactChip } from '@/components/ImpactChip';
import { resolveNow } from '@/utils/home';
import { nowLabels, drawerEventId, drawerHref } from '@/utils/wall';
import '@/styles/wall.css';
import { WallCenterStage } from '@/components/WallCenterStage';
import { LevelBadge } from '@/components/LevelBadge';
import { SeverityBadge } from '@/components/SeverityBadge';
import type { EventSummary, SourceHealth } from '@/types/site-data';

// ── Animated counter (count-up on mount) ──────────────────────────────────────
function useCountUp(target: number, duration = 700): number {
  const [val, setVal] = useState(0);
  const rafRef = useRef<number>(0);
  useEffect(() => {
    const start = performance.now();
    function step(now: number) {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - (1 - t) ** 3;
      setVal(Math.round(target * eased));
      if (t < 1) rafRef.current = requestAnimationFrame(step);
    }
    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);
  return val;
}

// ── Ring countdown SVG ────────────────────────────────────────────────────────
function CountdownRing({ seconds, total = 60 }: { seconds: number; total?: number }) {
  const r = 11;
  const circ = 2 * Math.PI * r;
  const progress = Math.max(0, seconds / total);
  const dash = circ * progress;
  const urgent = seconds <= 10;
  return (
    <svg width={28} height={28} viewBox="0 0 28 28" aria-hidden="true">
      <circle cx={14} cy={14} r={r} fill="none" stroke="var(--line)" strokeWidth={2} />
      <circle
        cx={14} cy={14} r={r}
        fill="none"
        stroke={urgent ? 'var(--p1)' : 'var(--accent)'}
        strokeWidth={2}
        strokeDasharray={`${dash.toFixed(2)} ${(circ - dash).toFixed(2)}`}
        strokeDashoffset={circ / 4} /* start from top */
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 1s linear' }}
      />
      <text
        x={14} y={14}
        textAnchor="middle" dominantBaseline="middle"
        fill={urgent ? 'var(--p1)' : 'var(--text-2)'}
        fontSize={7}
        fontFamily="var(--font-mono)"
        fontWeight="600"
      >
        {seconds}
      </text>
    </svg>
  );
}

// ── Hero KPI number (Space Grotesk 300) ───────────────────────────────────────
interface HeroKpiProps {
  label: string;
  sublabel?: string;
  value: number | string;
  color: string;
  pulse?: boolean;
}
function HeroKpi({ label, sublabel, value, color, pulse }: HeroKpiProps) {
  const numVal = typeof value === 'number' ? value : 0;
  const animated = useCountUp(numVal);
  const display = typeof value === 'number' ? animated : value;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
        {pulse && (
          <span aria-hidden="true" style={{
            width: 7, height: 7, borderRadius: '50%',
            background: color, flexShrink: 0, alignSelf: 'center',
            animation: 'pulse-dot 1.4s ease-in-out infinite',
          }} />
        )}
        <span
          className="tabular"
          style={{
            fontFamily: 'var(--font-display)',
            fontWeight: 300,
            fontSize: 40,
            lineHeight: 1,
            color,
            letterSpacing: '-0.03em',
          }}
        >
          {display}
        </span>
      </div>
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 9,
        fontWeight: 600,
        color: 'var(--text-3)',
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        marginTop: 3,
      }}>
        {label}
      </span>
      {sublabel && (
        <span aria-hidden="true" style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 8,
          color: 'var(--text-3)',
          letterSpacing: '0.06em',
        }}>
          {sublabel}
        </span>
      )}
    </div>
  );
}

// ── Compact 2-row event stream card ──────────────────────────────────────────
function StreamCard({ ev }: { ev: EventSummary }) {
  const domainColor = {
    vuln: 'var(--dom-vuln)',
    incident: 'var(--dom-incident)',
    web3: 'var(--dom-web3)',
  }[ev.domain] ?? 'var(--text-3)';

  const isRecentP0 = ev.severity === 'P0' &&
    (Date.now() - new Date(ev.first_seen).getTime()) < 60 * 60 * 1000;

  return (
    <Link
      to={drawerHref(ev.event_id)}
      style={{
        display: 'block',
        textDecoration: 'none',
        padding: '7px 10px',
        background: isRecentP0
          ? 'color-mix(in srgb, var(--p0) 8%, var(--bg-1))'
          : 'var(--bg-1)',
        borderLeft: `3px solid ${domainColor}`,
        borderBottom: '1px solid var(--line)',
        flexShrink: 0,
        transition: 'background 120ms',
        boxShadow: isRecentP0 ? 'inset 0 0 0 1px var(--p0), var(--shadow-sm)' : undefined,
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-2)'; }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLElement).style.background =
          isRecentP0 ? 'color-mix(in srgb, var(--p0) 8%, var(--bg-1))' : 'var(--bg-1)';
      }}
    >
      {/* Row 1: badges + time */}
      <div style={{ display: 'flex', gap: 5, alignItems: 'center', marginBottom: 4 }}>
        <SeverityBadge severity={ev.severity} pulse={isRecentP0} />
        <LevelBadge level={ev.level} size="sm" />
        {ev.amount_usd_latest !== null && (
          <span className="tabular" style={{
            fontSize: 9, fontFamily: 'var(--font-mono)',
            color: ev.amount_disputed ? 'var(--p1)' : 'var(--loss)',
            fontWeight: 600,
          }}>
            {formatAmount(ev.amount_usd_latest)}
          </span>
        )}
        <span style={{
          marginLeft: 'auto', fontSize: 9, fontFamily: 'var(--font-mono)',
          color: 'var(--text-3)',
        }}>
          {formatRelative(ev.last_updated)}
        </span>
      </div>
      {/* "does it hit us" — only when actually checked (not_eligible / absent ⇒ no chip, list rule) */}
      {ev.impact && ev.impact.status !== 'not_eligible' && (
        <div className="wall-stream-chip"><ImpactChip impact={ev.impact} withContext /></div>
      )}
      {/* Row 2: title (1 line truncated) */}
      <div style={{
        fontSize: 11, fontWeight: 600, color: 'var(--text-1)', lineHeight: 1.3,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {ev.title}
      </div>
    </Link>
  );
}

// ── Source status dot (for status bar) ───────────────────────────────────────
function SourceDot({ src }: { src: SourceHealth }) {
  const colors: Record<string, string> = {
    ok: 'var(--status-ok)',
    degraded: 'var(--status-degraded)',
    failing: 'var(--status-failing)',
    disabled: 'var(--status-disabled)',
    never_run: 'var(--status-never)',
  };
  const c = colors[src.status] ?? 'var(--text-3)';
  return (
    <span
      role="status"
      aria-label={`${src.name}: ${src.status}`}
      title={`${src.name} — ${src.status}${src.last_error ? ': ' + src.last_error : ''}`}
      style={{ position: 'relative', display: 'inline-flex', width: 8, height: 8 }}
    >
      {(src.status === 'degraded' || src.status === 'failing') && (
        <span aria-hidden="true" style={{
          position: 'absolute', inset: 0, borderRadius: '50%',
          background: c, animation: 'pulse-ring 2s ease-out infinite',
        }} />
      )}
      <span aria-hidden="true" style={{
        width: 8, height: 8, borderRadius: '50%', background: c,
        display: 'block', position: 'relative',
      }} />
    </span>
  );
}

// ── Web3 loss table row with inline background bar ────────────────────────────
function LossRow({ ev, maxAmount, rank }: { ev: EventSummary; maxAmount: number; rank: number }) {
  const pct = maxAmount > 0 ? ((ev.amount_usd_latest ?? 0) / maxAmount) * 100 : 0;
  return (
    <Link
      to={drawerHref(ev.event_id)}
      style={{
        display: 'flex', alignItems: 'center',
        padding: '5px 8px',
        gap: 8,
        position: 'relative',
        textDecoration: 'none',
        borderRadius: 4,
        overflow: 'hidden',
        background: 'transparent',
        transition: 'background 120ms',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-2)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
    >
      {/* Inline progress bar (background layer) */}
      <span aria-hidden="true" style={{
        position: 'absolute', left: 0, top: 0, bottom: 0,
        width: `${pct}%`,
        background: 'color-mix(in srgb, var(--loss) 12%, transparent)',
        transition: 'width 0.6s ease-out',
        pointerEvents: 'none',
      }} />
      <span style={{
        fontFamily: 'var(--font-mono)', fontSize: 9,
        color: 'var(--text-3)', flexShrink: 0, width: 14, zIndex: 1,
      }}>#{rank}</span>
      <span style={{
        fontSize: 11, color: 'var(--text-1)', flex: 1,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', zIndex: 1,
      }}>
        {ev.entities[0] ?? ev.title.split(' ')[0]}
      </span>
      <span className="tabular" style={{
        fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
        color: ev.amount_disputed ? 'var(--p1)' : 'var(--loss)',
        fontWeight: 600, zIndex: 1,
      }}>
        {formatAmount(ev.amount_usd_latest!)}
      </span>
    </Link>
  );
}

// ── Chain LED dot-matrix distribution ────────────────────────────────────────
function ChainLedDots({ events }: { events: EventSummary[] }) {
  const counts: Record<string, number> = {};
  for (const ev of events) {
    for (const c of ev.chains) counts[c] = (counts[c] ?? 0) + 1;
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const maxCount = sorted[0]?.[1] ?? 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      {sorted.map(([chain, count]) => {
        const activeDots = Math.round((count / maxCount) * 8);
        return (
          <div key={chain} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 9,
              color: 'var(--text-2)', width: 60, flexShrink: 0,
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>
              {chain}
            </span>
            {/* LED dot array */}
            <div style={{ display: 'flex', gap: 3, flex: 1 }}>
              {Array.from({ length: 8 }, (_, i) => (
                <span key={i} style={{
                  width: 6, height: 6,
                  borderRadius: 1,
                  background: i < activeDots ? 'var(--dom-web3)' : 'var(--bg-2)',
                  border: `1px solid ${i < activeDots ? 'var(--dom-web3)' : 'var(--line)'}`,
                  opacity: i < activeDots ? 0.85 : 0.4,
                  transition: 'background 0.3s',
                }} aria-hidden="true" />
              ))}
            </div>
            <span className="tabular" style={{
              fontFamily: 'var(--font-mono)', fontSize: 9,
              color: 'var(--dom-web3)', width: 16, textAlign: 'right', flexShrink: 0,
            }}>
              {count}
            </span>
          </div>
        );
      })}
      {sorted.length === 0 && (
        <span style={{ fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>
          无链数据
        </span>
      )}
    </div>
  );
}

// ── Vuln top (CVE chip + EPSS) ────────────────────────────────────────────────
// EPSS used to be read here from a field EventSummary does not have (always undefined ⇒ dead branch); removed.
function VulnTopRow({ ev }: { ev: EventSummary }) {
  return (
    <Link
      to={drawerHref(ev.event_id)}
      style={{
        display: 'flex', flexDirection: 'column', gap: 3,
        padding: '6px 8px',
        background: 'var(--bg-2)',
        borderRadius: 4,
        borderLeft: '2px solid var(--dom-vuln)',
        textDecoration: 'none',
        transition: 'background 120ms',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-0)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-2)'; }}
    >
      <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
        <SeverityBadge severity={ev.severity} />
        {ev.cves.slice(0, 2).map(cve => (
          <code key={cve} style={{
            fontFamily: 'var(--font-mono)', fontSize: 8,
            color: 'var(--accent)', background: 'var(--bg-1)',
            padding: '1px 5px', borderRadius: 3,
            border: '1px solid var(--accent)',
          }}>{cve}</code>
        ))}
      </div>
      <div style={{
        fontSize: 10, fontWeight: 600, color: 'var(--text-1)',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {ev.title}
      </div>
    </Link>
  );
}

// ── Isometric block band (mempool-style, 24 hourly cubes) ────────────────────
const SEVERITY_COLORS: Record<string, { front: string; top: string; side: string }> = {
  P0: { front: '#FF5C74', top: '#FF8A9A', side: '#CC3045' },
  P1: { front: '#FFB547', top: '#FFCF7A', side: '#CC8A2A' },
  P2: { front: '#5CC8F5', top: '#88DCF7', side: '#3A98C5' },
};
const EMPTY_COLORS = { front: 'var(--bg-2)', top: 'var(--line)', side: 'var(--bg-2)' };

function BlockBand({ events }: { events: EventSummary[] }) {
  const now = useMemo(() => Date.now(), []);
  const buckets = useMemo(() => computeHourBuckets(events, now), [events, now]);
  const maxCount = Math.max(...buckets.map(b => b.count), 1);

  const MAX_H = 60;
  const BLOCK_W = 36;
  const SIDE_W = 7;
  const TOP_H = 6;
  const GAP = 3;

  // Dashed divider position: between confirmed and pending
  // Place at 2/3 of the band width (approximate "8 hours ago" = V2+ confirmed vs V0/V1 pending)
  const dividerIdx = 16; // show dashed line between bucket 16 and 17

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-end',
        justifyContent: 'space-between',
        gap: 0,
        height: MAX_H + TOP_H + SIDE_W + 24,
        width: '100%',
        overflow: 'hidden',
      }}
      role="img"
      aria-label="Hourly security event block band, last 24 hours"
    >
      {buckets.map((bucket, i) => {
        const blockH = bucket.count > 0
          ? Math.max(8, Math.round((bucket.count / maxCount) * MAX_H))
          : 3;
        const colors = bucket.maxSeverity
          ? (SEVERITY_COLORS[bucket.maxSeverity] ?? EMPTY_COLORS)
          : EMPTY_COLORS;
        const isLatest = i === buckets.length - 1;
        const showLabel = i === 0 || i % 6 === 0 || isLatest;

        return (
          <div
            key={i}
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'flex-start',
              flexShrink: 0,
              position: 'relative',
              animation: isLatest ? 'iso-slide-in 400ms cubic-bezier(.16,1,.3,1)' : undefined,
            }}
            title={`${bucket.hourLabel}: ${bucket.count} events${bucket.maxSeverity ? ` · ${bucket.maxSeverity}` : ''} · ${bucket.confirmedCount} confirmed / ${bucket.pendingCount} pending`}
          >
            {/* Count label above block — aria-hidden: inside role="img", decorative */}
            <div style={{
              height: 12, display: 'flex', alignItems: 'flex-end',
              justifyContent: 'center', width: BLOCK_W,
            }}>
              {bucket.count > 0 && (
                <span aria-hidden="true" style={{
                  fontSize: 7, fontFamily: 'var(--font-mono)',
                  color: colors.front, lineHeight: 1,
                }}>
                  {bucket.count}
                </span>
              )}
            </div>

            {/* The cube */}
            <svg
              width={BLOCK_W + SIDE_W}
              height={blockH + TOP_H + SIDE_W}
              style={{ overflow: 'visible' }}
              aria-hidden="true"
            >
              {/* Front face */}
              <rect
                x={0} y={TOP_H}
                width={BLOCK_W} height={blockH}
                fill={colors.front}
                opacity={bucket.count > 0 ? 0.82 : 0.25}
              />
              {/* Top face (parallelogram) */}
              <polygon
                points={`0,${TOP_H} ${SIDE_W},0 ${BLOCK_W + SIDE_W},0 ${BLOCK_W},${TOP_H}`}
                fill={colors.top}
                opacity={bucket.count > 0 ? 0.65 : 0.18}
              />
              {/* Right side face */}
              <polygon
                points={`${BLOCK_W},${TOP_H} ${BLOCK_W + SIDE_W},0 ${BLOCK_W + SIDE_W},${blockH} ${BLOCK_W},${blockH + TOP_H}`}
                fill={colors.side}
                opacity={bucket.count > 0 ? 0.95 : 0.2}
              />
            </svg>

            {/* Hour label — non-shown use visibility:hidden (axe skips), shown at full opacity */}
            <div
              aria-hidden="true"
              style={{
                fontSize: 7, fontFamily: 'var(--font-mono)',
                color: 'var(--text-3)', textAlign: 'center', width: BLOCK_W,
                marginTop: 2,
                visibility: showLabel ? 'visible' : 'hidden',
              }}
            >
              {bucket.hourLabel}
            </div>

            {/* Dashed vertical divider */}
            {i === dividerIdx && (
              <div style={{
                position: 'absolute',
                right: -(GAP / 2 + 1),
                top: 0,
                bottom: 0,
                width: 1,
                background: 'repeating-linear-gradient(to bottom, var(--accent) 0, var(--accent) 4px, transparent 4px, transparent 8px)',
                opacity: 0.4,
              }} />
            )}
          </div>
        );
      })}

      {/* Band labels */}
      <div style={{
        position: 'absolute',
        bottom: 4, left: 4,
        display: 'flex', gap: 12,
        alignItems: 'center',
        pointerEvents: 'none',
      }}>
        <span aria-hidden="true" style={{
          fontSize: 7, fontFamily: 'var(--font-mono)',
          color: 'var(--text-3)', letterSpacing: '0.1em', textTransform: 'uppercase',
        }}>
          分析中 V0–V1
        </span>
        <span aria-hidden="true" style={{ borderLeft: '1px dashed var(--accent)', height: 10, opacity: 0.4 }} />
        <span aria-hidden="true" style={{
          fontSize: 7, fontFamily: 'var(--font-mono)',
          color: 'var(--text-3)', letterSpacing: '0.1em', textTransform: 'uppercase',
        }}>
          已确认 V2+
        </span>
      </div>
    </div>
  );
}

// ── Ticker (5-row auto-scroll) ────────────────────────────────────────────────
function Ticker({ events }: { events: EventSummary[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || isPaused) return;
    const maxScroll = el.scrollHeight - el.clientHeight;
    if (maxScroll <= 0) return;
    let raf: number;
    function tick() {
      if (!el) return;
      el.scrollTop += 0.5;
      if (el.scrollTop >= maxScroll) el.scrollTop = 0;
      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [isPaused, events.length]);

  const recent = events.slice(0, 20);

  return (
    <div
      ref={containerRef}
      style={{
        overflowY: 'hidden',
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
      }}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      aria-label="Event ticker"
      role="marquee"
    >
      {recent.map(ev => {
        const color = {
          vuln: 'var(--dom-vuln)', incident: 'var(--dom-incident)', web3: 'var(--dom-web3)',
        }[ev.domain] ?? 'var(--text-3)';
        return (
          <Link
            key={ev.event_id}
            to={drawerHref(ev.event_id)}
            style={{
              display: 'flex', gap: 8, alignItems: 'center',
              padding: '3px 8px',
              fontSize: 10, fontFamily: 'var(--font-mono)',
              color: 'var(--text-2)', textDecoration: 'none',
              borderLeft: `2px solid ${color}`,
              flexShrink: 0,
              transition: 'background 100ms',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'var(--bg-1)'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
          >
            <span style={{ color: 'var(--text-3)', flexShrink: 0, width: 28 }}>
              {formatRelative(ev.first_seen)}
            </span>
            <SeverityBadge severity={ev.severity} />
            <span style={{
              flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              color: 'var(--text-1)', fontFamily: 'var(--font-body)',
            }}>
              {ev.title}
            </span>
            {ev.amount_usd_latest !== null && (
              <span className="tabular" style={{ color: 'var(--loss)', flexShrink: 0 }}>
                {formatAmount(ev.amount_usd_latest)}
              </span>
            )}
          </Link>
        );
      })}
    </div>
  );
}

// ── Panel wrapper with HUD bracket styling ────────────────────────────────────
function HudPanel({
  heading,
  children,
  style: extraStyle,
}: {
  heading?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <div
      className="hud-panel"
      style={{
        padding: '10px 12px',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        overflow: 'hidden',
        ...extraStyle,
      }}
    >
      {heading && <div className="panel-heading">{heading}</div>}
      {children}
    </div>
  );
}

// ── Main WallPage ─────────────────────────────────────────────────────────────
export function WallPage() {
  const navigate = useNavigate();
  const { events, now, loading: evLoading, error: evError, staleSecs, generatedAt } = useEvents();
  const [params] = useSearchParams();
  const drawerId = drawerEventId(params);
  const { sources, loading: srcLoading } = useSources();
  const { theme, toggle: toggleTheme } = useTheme();

  const containerRef = useRef<HTMLDivElement>(null);
  const streamRef    = useRef<HTMLDivElement>(null);
  const radarContainerRef = useRef<HTMLDivElement>(null);

  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [countdown, setCountdown] = useState(60);
  const [radarSize, setRadarSize] = useState(400);

  // Track fullscreen state
  useEffect(() => {
    const h = () => setIsFullscreen(!!document.fullscreenElement);
    document.addEventListener('fullscreenchange', h);
    return () => document.removeEventListener('fullscreenchange', h);
  }, []);

  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      containerRef.current?.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  }, []);

  // Responsive radar sizing
  useEffect(() => {
    const el = radarContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect;
      setRadarSize(Math.max(200, Math.floor(Math.min(width - 20, height - 100) * 0.88)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Countdown from staleSecs
  useEffect(() => {
    if (staleSecs !== null) setCountdown(Math.max(0, 60 - staleSecs));
  }, [staleSecs]);

  // Auto-scroll stream (paused while the L2 drawer is open — the reader is reading)
  useEffect(() => {
    const el = streamRef.current;
    if (!el || isPaused || drawerId) return;
    const max = el.scrollHeight - el.clientHeight;
    if (max <= 0) return;
    let raf: number;
    function tick() {
      if (!el) return;
      el.scrollTop += 0.4;
      if (el.scrollTop >= max) el.scrollTop = 0;
      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [isPaused, events.length, drawerId]);

  // Derived state
  const sorted = useMemo(() => sortEvents(events), [events]);
  const streamEvents = useMemo(() => {
    const p0 = sorted.filter(e => e.severity === 'P0').slice(0, 8);
    const p1 = sorted.filter(e => e.severity === 'P1').slice(0, 8);
    return [...p0, ...p1];
  }, [sorted]);

  const web3Events = useMemo(() => events.filter(e => e.domain === 'web3'), [events]);
  const web3ByAmount = useMemo(() =>
    [...web3Events]
      .filter(e => e.amount_usd_latest !== null)
      .sort((a, b) => (b.amount_usd_latest ?? 0) - (a.amount_usd_latest ?? 0))
      .slice(0, 6),
    [web3Events],
  );
  const maxLoss = web3ByAmount[0]?.amount_usd_latest ?? 1;

  const vulnEvents = useMemo(() =>
    events.filter(e => e.domain === 'vuln' && (e.severity === 'P0' || e.severity === 'P1')).slice(0, 4),
    [events],
  );

  // Pre-compute radar layout outside RadarScope so the 3D scene and the 2D labels reuse the same data.
  const radarDots = useMemo(() => computeRadarLayout(events), [events]);
  const radarPoints = useMemo(() => clusterDots(radarDots), [radarDots]);
  const nowCards = useMemo(() => resolveNow(now, events), [now, events]);
  const labels = useMemo(() => nowLabels(now, events), [now, events]);

  // 3D layout — up to 2000 raw dots (no clustering; 3D InstancedMesh handles density).
  const dots3d = useMemo(() =>
    radarDotsTo3D(
      computeRadarLayout(events, Date.now(), 2000)
        .filter((d): d is RadarDot => !('kind' in d)),
    ),
    [events],
  );

  // Radar blip / leader label ⇒ L2 drawer (URL-driven, so refresh restores it and Back closes it).
  const handleRadarSelect = useCallback((eventId: string) => {
    navigate(drawerHref(eventId));
  }, [navigate]);
  const closeDrawer = useCallback(() => navigate('/wall'), [navigate]);
  const drawerSummary = useMemo(() => events.find(e => e.event_id === drawerId) ?? null, [events, drawerId]);

  const unhealthy = useMemo(() => sources.filter(s => s.status === 'degraded' || s.status === 'failing'), [sources]);
  const enabledSources = useMemo(() => sources.filter(s => s.enabled), [sources]);

  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const new24h    = events.filter(e => new Date(e.first_seen).getTime() >= dayAgo).length;
  const p0Count   = events.filter(e => e.severity === 'P0').length;
  const v3plus    = events.filter(e => e.level === 'V3' || e.level === 'V4').length;
  const web3Total = web3Events
    .filter(e => new Date(e.first_seen).getTime() >= dayAgo)
    .reduce((s, e) => s + (e.amount_usd_latest ?? 0), 0);

  const fresh = freshness(generatedAt, staleSecs, Date.now());
  const isStale = fresh.kind === 'publish_stale' || fresh.kind === 'fetch_failing';
  const staleMins = fresh.kind === 'publish_stale' ? Math.floor(fresh.dataAgeSecs / 60)
    : fresh.kind === 'fetch_failing' ? Math.floor(fresh.sinceFetchSecs / 60) : 0;

  const lastSyncStr = generatedAt
    ? new Date(generatedAt).toISOString().substring(11, 16)
    : '--:--';

  return (
    <div
      ref={containerRef}
      data-theme={theme}
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        background: 'var(--bg-0)',
        overflow: 'hidden',
        fontFamily: 'var(--font-body)',
        position: 'fixed',
        inset: 0,
        zIndex: 0,
      }}
    >
      {/* ── Background depth texture ── */}
      <div aria-hidden="true" style={{
        position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 0,
        background: `
          radial-gradient(ellipse 60% 60% at 50% 45%,
            color-mix(in srgb, var(--accent) 6%, transparent) 0%,
            transparent 70%),
          radial-gradient(circle, rgb(255 255 255 / .04) 1px, transparent 1px) 0 0 / 24px 24px
        `,
      }} />

      {/* ── Stale warning ── */}
      {isStale && (
        <div
          role="alert" aria-live="assertive"
          style={{
            padding: '6px 16px',
            background: 'color-mix(in srgb, var(--p0) 15%, var(--bg-0))',
            borderBottom: '1px solid var(--p0)',
            fontSize: 11, color: 'var(--p0)',
            fontFamily: 'var(--font-mono)',
            display: 'flex', alignItems: 'center', gap: 8,
            flexShrink: 0, position: 'relative', zIndex: 10,
          }}
        >
          <span aria-hidden="true">⚠</span>
          {fresh.kind === 'publish_stale'
            ? `数据已 ${staleMins}m 未更新 — 后端采集流水线可能停止`
            : `数据拉取失败已 ${staleMins}m — 请检查网络连接`}
        </div>
      )}

      {/* ── Status bar (40px) ── */}
      <header
        role="banner"
        style={{
          height: 40,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '0 16px',
          borderBottom: '1px solid var(--line)',
          background: 'var(--bg-1)',
          boxShadow: 'var(--shadow-panel)',
          flexShrink: 0,
          zIndex: 10,
          position: 'relative',
        }}
      >
        {/* Live indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span aria-hidden="true" style={{ position: 'relative', display: 'inline-flex', width: 8, height: 8 }}>
            <span style={{
              position: 'absolute', inset: 0, borderRadius: '50%',
              background: isStale ? 'var(--p0)' : 'var(--status-ok)',
              animation: 'pulse-ring 1.8s ease-out infinite',
            }} />
            <span style={{
              position: 'relative', width: 8, height: 8, borderRadius: '50%',
              background: isStale ? 'var(--p0)' : 'var(--status-ok)',
              display: 'block',
            }} />
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
            color: 'var(--text-2)', letterSpacing: '0.10em',
          }}>
            {isStale ? 'STALE' : 'LIVE'}
          </span>
        </div>

        <span style={{ color: 'var(--line)', fontSize: 10 }}>·</span>

        {/* Source health summary */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          {!srcLoading && (
            <>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-3)' }}>
                {enabledSources.length - unhealthy.length}/{enabledSources.length} OK
              </span>
              <div style={{ display: 'flex', gap: 3, flexWrap: 'nowrap' }}>
                {enabledSources.slice(0, 15).map(src => (
                  <SourceDot key={src.source_id} src={src} />
                ))}
              </div>
            </>
          )}
          {unhealthy.length > 0 && (
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: 9,
              color: 'var(--p1)',
              padding: '1px 6px', borderRadius: 3,
              border: '1px solid var(--p1)',
              background: 'color-mix(in srgb, var(--p1) 10%, transparent)',
            }}>
              {unhealthy.length} 异常
            </span>
          )}
        </div>

        <span style={{ color: 'var(--line)', fontSize: 10 }}>·</span>

        {/* Last sync time */}
        {generatedAt && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-3)' }}>
            刷新 <span style={{ color: 'var(--text-2)' }}>{lastSyncStr} UTC</span>
          </span>
        )}

        {/* Countdown ring */}
        <CountdownRing seconds={countdown} />

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* Controls */}
        <button
          onClick={toggleTheme}
          aria-label={`切换到${theme === 'light' ? '深色' : '浅色'}主题`}
          style={{
            background: 'var(--bg-2)', border: '1px solid var(--line)',
            borderRadius: 'var(--r-sm)', padding: '4px 10px',
            fontSize: 11, color: 'var(--text-2)', cursor: 'pointer',
          }}
        >
          {theme === 'light' ? '🌙' : '☀️'}
        </button>
        <button
          onClick={toggleFullscreen}
          aria-label={isFullscreen ? '退出全屏' : '进入全屏'}
          title={isFullscreen ? 'Exit fullscreen (Esc)' : 'Enter fullscreen'}
          style={{
            background: 'var(--bg-2)', border: '1px solid var(--line)',
            borderRadius: 'var(--r-sm)', padding: '4px 10px',
            fontSize: 14, color: 'var(--text-2)', cursor: 'pointer', lineHeight: 1,
          }}
        >
          {isFullscreen ? '⊡' : '⛶'}
        </button>
        <Link
          to="/"
          style={{
            background: 'var(--bg-2)', border: '1px solid var(--line)',
            borderRadius: 'var(--r-sm)', padding: '4px 12px',
            fontSize: 11, color: 'var(--text-2)', textDecoration: 'none',
            display: 'flex', alignItems: 'center',
          }}
        >
          ← 返回
        </Link>
      </header>

      {/* ── Main 3-column grid ── */}
      <div
        style={{
          flex: 1,
          display: 'grid',
          gridTemplateColumns: '340px 1fr 340px',
          gap: 8,
          padding: '8px 12px 4px',
          overflow: 'hidden',
          minHeight: 0,
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* ── Left: event stream ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0, minHeight: 0, overflow: 'hidden' }}>
          <HudPanel
            style={{ flex: 1, padding: 0 }}
          >
            <div className="panel-heading" style={{ padding: '8px 12px 6px', borderBottom: '1px solid var(--line)' }}>
              实时事件流 · LIVE FEED
              <span style={{ marginLeft: 8, color: 'var(--p0)', fontWeight: 700 }}>
                {streamEvents.length}
              </span>
            </div>
            {evLoading ? (
              <div style={{ padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="skeleton" style={{ height: 52 }} />
                ))}
              </div>
            ) : (
              <div
                ref={streamRef}
                style={{ flex: 1, overflowY: 'hidden', display: 'flex', flexDirection: 'column' }}
                onMouseEnter={() => setIsPaused(true)}
                onMouseLeave={() => setIsPaused(false)}
                aria-live="polite"
                aria-label="P0 和 P1 事件流"
              >
                {streamEvents.length === 0 ? (
                  <div style={{ fontSize: 11, color: 'var(--text-3)', padding: '20px 12px', textAlign: 'center' }}>
                    无高危事件
                  </div>
                ) : (
                  streamEvents.map(ev => <StreamCard key={ev.event_id} ev={ev} />)
                )}
              </div>
            )}
          </HudPanel>
        </div>

        {/* ── Center: hero KPIs + radar ── */}
        <div
          ref={radarContainerRef}
          style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}
        >
          <div
            className="hud-panel"
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              padding: '12px 16px 8px',
              overflow: 'hidden',
            }}
          >
            {/* Hero KPI row */}
            <div
              style={{
                display: 'flex',
                gap: 32,
                justifyContent: 'center',
                alignItems: 'flex-end',
                flexShrink: 0,
                marginBottom: 8,
              }}
              aria-label="Key performance indicators"
            >
              <HeroKpi
                label="今日新事件"
                sublabel="NEW 24H"
                value={new24h}
                color="var(--accent)"
              />
              <HeroKpi
                label="P0 活跃"
                sublabel="CRITICAL"
                value={p0Count}
                color="var(--p0)"
                pulse={p0Count > 0}
              />
              <HeroKpi
                label="V3+ 确认"
                sublabel="CONFIRMED"
                value={v3plus}
                color="var(--v3)"
              />
              <HeroKpi
                label="Web3 24h 损失"
                sublabel="USD LOST"
                value={web3Total > 0 ? formatAmount(web3Total) : '—'}
                color="var(--loss)"
              />
            </div>

            {/* Radar — WallCenterStage routes to 3D or SVG based on capability */}
            {evLoading ? (
              <div className="skeleton" style={{
                width: radarSize, height: radarSize, borderRadius: '50%',
              }} />
            ) : (
              <WallCenterStage
                svgScene={
                  <ScopeWithLabels
                    scope={
                      <RadarScope
                        points={radarPoints}
                        onSelect={handleRadarSelect}
                        size={radarSize}
                        lastSync={lastSyncStr}
                        countdown={countdown}
                      />
                    }
                    dots={radarDots}
                    size={radarSize}
                    labels={labels}
                    onSelect={handleRadarSelect}
                  />
                }
                dots3d={dots3d}
                labels={labels}
                selectedEventId={drawerId}
                onSelect={handleRadarSelect}
              />
            )}
            {evError && (
              <div style={{ fontSize: 12, color: 'var(--p0)', padding: 16 }}>
                数据加载失败: {evError}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: NOW (first) → Web3 loss → chain → vuln ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, overflow: 'hidden', minHeight: 0 }}>
          <HudPanel heading="必须处理 · NOW" style={{ flexShrink: 0 }}>
            {evLoading ? <div className="skeleton" style={{ height: 120 }} /> : <WallNowBoard cards={nowCards} />}
          </HudPanel>

          {/* Web3 loss */}
          <HudPanel heading="Web3 损失排行 · USD LOST" style={{ flexShrink: 0 }}>
            {evLoading ? (
              <div className="skeleton" style={{ height: 80 }} />
            ) : web3ByAmount.length === 0 ? (
              <span className="no-data">无数据 · NO DATA</span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {web3ByAmount.map((ev, i) => (
                  <LossRow key={ev.event_id} ev={ev} maxAmount={maxLoss} rank={i + 1} />
                ))}
              </div>
            )}
          </HudPanel>

          {/* Chain LED distribution */}
          <HudPanel heading="按链分布 · CHAIN DIST" style={{ flexShrink: 0 }}>
            {evLoading ? (
              <div className="skeleton" style={{ height: 60 }} />
            ) : (
              <ChainLedDots events={web3Events} />
            )}
          </HudPanel>

          {/* Vuln top */}
          <HudPanel heading="漏洞优先级 · VULN TOP P0/P1" style={{ flex: 1, overflow: 'hidden' }}>
            {evLoading ? (
              <div className="skeleton" style={{ height: 80 }} />
            ) : vulnEvents.length === 0 ? (
              <span className="no-data">无高危漏洞 · NO DATA</span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, overflow: 'hidden' }}>
                {vulnEvents.map(ev => (
                  <VulnTopRow key={ev.event_id} ev={ev} />
                ))}
              </div>
            )}
          </HudPanel>
        </div>
      </div>

      {/* ── Bottom: block band + ticker ── */}
      <footer
        style={{
          height: 180,
          borderTop: '1px solid var(--line)',
          background: 'var(--bg-1)',
          display: 'flex',
          gap: 0,
          flexShrink: 0,
          overflow: 'hidden',
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* Block band (takes ~75%) */}
        <div
          style={{
            flex: 3,
            padding: '10px 12px 8px',
            display: 'flex',
            flexDirection: 'column',
            borderRight: '1px solid var(--line)',
            overflow: 'hidden',
          }}
        >
          <div className="panel-heading" style={{ marginBottom: 6 }}>
            事件密度区块带 · 24H BLOCK BAND
          </div>
          {evLoading ? (
            <div className="skeleton" style={{ flex: 1 }} />
          ) : (
            <div style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
              <BlockBand events={events} />
            </div>
          )}
        </div>

        {/* Ticker (takes ~25%) */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            minWidth: 0,
          }}
        >
          <div className="panel-heading" style={{ padding: '10px 12px 6px', borderBottom: '1px solid var(--line)' }}>
            事件跑马 · EVENT TICKER
          </div>
          {evLoading ? (
            <div style={{ padding: 8 }}>
              {[...Array(5)].map((_, i) => (
                <div key={i} className="skeleton" style={{ height: 20, marginBottom: 4 }} />
              ))}
            </div>
          ) : (
            <Ticker events={sorted} />
          )}
        </div>
      </footer>

      {drawerId && <EventDrawer key={drawerId} eventId={drawerId} summary={drawerSummary} onClose={closeDrawer} />}
    </div>
  );
}
