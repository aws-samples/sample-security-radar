/**
 * RadarScope — production radar display component.
 *
 * Visual features (§2):
 * - 5 concentric distance rings, radial line every 30°, main-axis minor ticks
 * - Outer bearing scale 0–350° (long tick every 30°, short every 10°)
 * - Time-log radius: center = most recent, outer = 7d
 * - Domain sectors: 4px arc at outer rim + external capsule labels
 * - Scan sweep: JS-driven sector path + bright front arm (6s/rev)
 * - Hit detection: RAF passes dot angles → .pinging class → ripple + P0 crosshair
 * - Dot shapes: hollow-circle (V0), filled circle (V1–V3), diamond (V4)
 * - Dot size: 3 + 2·√independent_sources, capped at 12px
 * - Outer ring textPath: "SECURITY RADAR · LIVE · …" slow counter-rotation
 * - Keyboard navigation: Tab → dot, Enter → navigate to detail
 * - prefers-reduced-motion: static sector, no rotation, no ripples
 */
import { useRef, useState, useEffect, useMemo, useCallback } from 'react';
import {
  ageMsToRadiusFrac,
  TIME_RINGS,
  DOMAIN_SECTORS,
  SCOPE,
  type RadarDot,
  type RadarCluster,
  type RadarItem,
} from '@/utils/radarLayout';

// ── Coordinate constants ───────────────────────────────────────────────────────
const CX = SCOPE.cx;
const CY = SCOPE.cy;
const R_MAX = SCOPE.rMax; // outer data circle
const R_RIM = 200;    // sector arc rim
const R_TICK = 208;   // outer edge of short bearing tick
const R_LONG_TICK = 213; // outer edge of long bearing tick (every 30°)
const R_LABEL = 225;  // bearing number placement
const R_TEXT = 242;   // outer ring text path radius
const R_SECTOR_LABEL = 226; // sector capsule center radius
const VIEWBOX = SCOPE.viewBox;

// ── Domain config ──────────────────────────────────────────────────────────────
const DOMAIN_COLOR: Record<string, string> = {
  vuln:     'var(--dom-vuln)',
  incident: 'var(--dom-incident)',
  web3:     'var(--dom-web3)',
};

const SEV_COLOR: Record<string, string> = {
  P0: 'var(--p0)',
  P1: 'var(--p1)',
  P2: 'var(--p2)',
};

// ── Polar / geometry helpers ───────────────────────────────────────────────────
function toXY(angleDeg: number, r: number): { x: number; y: number } {
  const rad = (angleDeg - 90) * (Math.PI / 180);
  return { x: CX + r * Math.cos(rad), y: CY + r * Math.sin(rad) };
}

function arcPath(startDeg: number, endDeg: number, r: number): string {
  const s = toXY(startDeg, r);
  const e = toXY(endDeg, r);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M${s.x.toFixed(2)},${s.y.toFixed(2)} A${r},${r} 0 ${large},1 ${e.x.toFixed(2)},${e.y.toFixed(2)}`;
}

function sweepSectorPath(angleDeg: number, sweepBack: number, r: number): string {
  const startDeg = angleDeg - sweepBack;
  const s = toXY(startDeg, r);
  const e = toXY(angleDeg, r);
  const large = sweepBack > 180 ? 1 : 0;
  return `M${CX},${CY} L${s.x.toFixed(2)},${s.y.toFixed(2)} A${r},${r} 0 ${large},1 ${e.x.toFixed(2)},${e.y.toFixed(2)} Z`;
}

function diamondPath(cx: number, cy: number, r: number): string {
  return `M${cx},${cy - r} L${cx + r * 0.7},${cy} L${cx},${cy + r} L${cx - r * 0.7},${cy} Z`;
}

// ── Hook: prefer-reduced-motion ────────────────────────────────────────────────
function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    typeof window !== 'undefined'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false,
  );
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return reduced;
}

// ── Static geometry: bearing scale ────────────────────────────────────────────
function BearingScale() {
  const ticks = [];
  for (let deg = 0; deg < 360; deg += 10) {
    const isLong = deg % 30 === 0;
    const inner = toXY(deg, R_MAX + 2);
    const outer = toXY(deg, isLong ? R_LONG_TICK : R_TICK);
    const lp    = toXY(deg, R_LABEL);
    const label = String(deg).padStart(3, '0');
    ticks.push(
      <g key={deg}>
        <line
          x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
          stroke="var(--text-3)" strokeWidth={isLong ? 1 : 0.5}
          opacity={isLong ? 0.6 : 0.3}
        />
        {isLong && deg !== 0 && (
          <text
            x={lp.x} y={lp.y}
            textAnchor="middle" dominantBaseline="middle"
            fill="var(--text-3)"
            fontSize={7} fontFamily="var(--font-mono)"
            opacity={0.55}
          >
            {label}
          </text>
        )}
      </g>,
    );
  }
  return <g aria-hidden="true">{ticks}</g>;
}

// ── Static: 5 concentric rings + radial lines ──────────────────────────────────
function GridRings() {
  const rings = [0.2, 0.4, 0.6, 0.8, 1.0];
  const radials = Array.from({ length: 12 }, (_, i) => i * 30); // every 30°
  const mainAxis = [0, 90, 180, 270]; // major axis: minor tick marks

  return (
    <g aria-hidden="true">
      {/* Concentric rings */}
      {rings.map((f, i) => (
        <circle
          key={f}
          cx={CX} cy={CY}
          r={f * R_MAX}
          fill="none"
          stroke="var(--line)"
          strokeWidth={i === rings.length - 1 ? 0.75 : 0.5}
          opacity={i === rings.length - 1 ? 0.5 : 0.25}
        />
      ))}

      {/* Radial lines every 30° */}
      {radials.map(deg => {
        const p = toXY(deg, R_MAX);
        return (
          <line
            key={deg}
            x1={CX} y1={CY} x2={p.x} y2={p.y}
            stroke="var(--line)"
            strokeWidth={mainAxis.includes(deg) ? 0.75 : 0.4}
            opacity={mainAxis.includes(deg) ? 0.4 : 0.2}
          />
        );
      })}

      {/* Main axis minor tick marks every 2% radius */}
      {mainAxis.flatMap(deg =>
        Array.from({ length: 20 }, (_, i) => {
          const rFrac = (i + 1) / 20;
          const inner = toXY(deg, rFrac * R_MAX - 3);
          const outer = toXY(deg, rFrac * R_MAX + 3);
          return (
            <line
              key={`${deg}-${i}`}
              x1={inner.x} y1={inner.y} x2={outer.x} y2={outer.y}
              stroke="var(--text-3)"
              strokeWidth={0.5}
              opacity={0.3}
            />
          );
        }),
      )}
    </g>
  );
}

// ── Static: time-ring labels 1h / 24h / 7d ─────────────────────────────────────
function TimeRingLabels() {
  return (
    <g aria-hidden="true">
      {TIME_RINGS.map(({ label, ageMsMax }) => {
        const rFrac = ageMsToRadiusFrac(ageMsMax);
        const r = rFrac * R_MAX;
        const lp = toXY(45, r); // place label at 45° (NE)
        return (
          <text
            key={label}
            x={lp.x} y={lp.y}
            textAnchor="middle" dominantBaseline="middle"
            fill="var(--text-3)"
            fontSize={7.5} fontFamily="var(--font-mono)"
            opacity={0.6}
          >
            {label}
          </text>
        );
      })}
    </g>
  );
}

// ── Static: sector arc color strips + external capsule labels ──────────────────
function SectorRims() {
  return (
    <g aria-hidden="true">
      {Object.entries(DOMAIN_SECTORS).map(([domain, sector]) => {
        const midDeg = sector.start + sector.span / 2;
        const lp = toXY(midDeg, R_SECTOR_LABEL);
        const color = DOMAIN_COLOR[domain] ?? 'var(--text-3)';

        return (
          <g key={domain}>
            {/* 4px arc strip at outer rim */}
            <path
              d={arcPath(sector.start + 2, sector.start + sector.span - 2, R_RIM)}
              fill="none"
              stroke={color}
              strokeWidth={4}
              opacity={0.75}
            />
            {/* External capsule label */}
            <g transform={`translate(${lp.x},${lp.y})`}>
              <rect
                x={-18} y={-7} width={36} height={14}
                rx={7}
                fill={color}
                opacity={0.15}
                stroke={color}
                strokeWidth={0.75}
                strokeOpacity={0.5}
              />
              <text
                x={0} y={0}
                textAnchor="middle" dominantBaseline="middle"
                fill={color}
                fontSize={7.5}
                fontFamily="var(--font-mono)"
                fontWeight="700"
                letterSpacing="0.1em"
                opacity={0.9}
              >
                {sector.label}
              </text>
            </g>
          </g>
        );
      })}
    </g>
  );
}

// ── Outer ring orbiting text ───────────────────────────────────────────────────
function OuterRingText({ lastSync, countdown }: { lastSync: string; countdown: number }) {
  const text = `SECURITY RADAR · LIVE · LAST SYNC ${lastSync} UTC · NEXT ${countdown}s · `;
  const _circumference = 2 * Math.PI * R_TEXT; void _circumference;
  const pathId = 'radar-ring-text-path';

  return (
    <g aria-hidden="true">
      <defs>
        <path
          id={pathId}
          d={`M${CX},${CY - R_TEXT} A${R_TEXT},${R_TEXT} 0 1,1 ${CX - 0.001},${CY - R_TEXT}`}
        />
      </defs>
      <text
        fill="var(--text-3)"
        fontSize={7}
        fontFamily="var(--font-mono)"
        letterSpacing="0.08em"
        opacity={0.5}
      >
        <textPath href={`#${pathId}`} startOffset="0%">
          {text.repeat(3)}
        </textPath>
      </text>
    </g>
  );
}

// ── Rim glow ───────────────────────────────────────────────────────────────────
function RimGlow() {
  return (
    <radialGradient id="rim-glow" cx="50%" cy="50%" r="50%">
      <stop offset="80%" stopColor="var(--accent)" stopOpacity="0" />
      <stop offset="92%" stopColor="var(--accent)" stopOpacity="0.12" />
      <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
    </radialGradient>
  );
}

// ── Dot component ──────────────────────────────────────────────────────────────
interface DotProps {
  item: RadarDot;
  pixelX: number;
  pixelY: number;
  onHover: (item: RadarDot | null, x: number, y: number) => void;
  onActivate: (item: RadarDot) => void;
  groupRef: (el: SVGGElement | null) => void;
}

function DotMarker({ item, pixelX, pixelY, onHover, onActivate, groupRef }: DotProps) {
  const x = pixelX;
  const y = pixelY;
  const r = item.dotR;
  const color = SEV_COLOR[item.severity] ?? 'var(--text-3)';
  const isP0 = item.severity === 'P0';

  return (
    <g
      ref={groupRef}
      className={`radar-dot-group${isP0 ? ' radar-dot-p0' : ''}`}
      style={{ cursor: 'pointer' }}
      role="button"
      tabIndex={0}
      aria-label={`${item.title} [${item.severity} ${item.level}]`}
      onMouseEnter={() => onHover(item, x, y)}
      onMouseLeave={() => onHover(null, 0, 0)}
      onFocus={() => onHover(item, x, y)}
      onBlur={() => onHover(null, 0, 0)}
      onClick={() => onActivate(item)}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onActivate(item); } }}
    >
      {/* Ping ripple rings (activated by JS adding .radar-dot-pinging class) */}
      <circle
        className="ping-ring ping-ring-1"
        cx={x} cy={y} r={r}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        opacity={0}
        style={{ transformOrigin: `${x}px ${y}px`, pointerEvents: 'none' }}
        aria-hidden="true"
      />
      <circle
        className="ping-ring ping-ring-2"
        cx={x} cy={y} r={r}
        fill="none"
        stroke={color}
        strokeWidth={1}
        opacity={0}
        style={{ transformOrigin: `${x}px ${y}px`, pointerEvents: 'none' }}
        aria-hidden="true"
      />

      {/* P0 lockout crosshair arms (4 L-brackets, animated when .locked class added) */}
      {isP0 && (
        <g className="lockout-crosshair" opacity={0} aria-hidden="true">
          {/* TL */}
          <path d={`M${x - 8},${y - 4} L${x - 8},${y - 8} L${x - 4},${y - 8}`}
            stroke={color} strokeWidth={1.5} fill="none" />
          {/* TR */}
          <path d={`M${x + 4},${y - 8} L${x + 8},${y - 8} L${x + 8},${y - 4}`}
            stroke={color} strokeWidth={1.5} fill="none" />
          {/* BL */}
          <path d={`M${x - 8},${y + 4} L${x - 8},${y + 8} L${x - 4},${y + 8}`}
            stroke={color} strokeWidth={1.5} fill="none" />
          {/* BR */}
          <path d={`M${x + 4},${y + 8} L${x + 8},${y + 8} L${x + 8},${y + 4}`}
            stroke={color} strokeWidth={1.5} fill="none" />
        </g>
      )}

      {/* The dot itself */}
      {item.shape === 'hollow-circle' && (
        <circle cx={x} cy={y} r={r}
          fill="none"
          stroke={color}
          strokeWidth={1.5}
          opacity={0.8}
        />
      )}
      {item.shape === 'circle' && (
        <circle cx={x} cy={y} r={r}
          fill={color}
          opacity={isP0 ? 1 : 0.75}
          filter={isP0 ? 'url(#dot-glow)' : undefined}
        />
      )}
      {item.shape === 'diamond' && (
        <path
          d={diamondPath(x, y, r)}
          fill={color}
          opacity={0.9}
          filter={isP0 ? 'url(#dot-glow)' : undefined}
        />
      )}

      {/* P0 ambient halo */}
      {isP0 && (
        <circle cx={x} cy={y} r={r + 5}
          fill={color} opacity={0.12}
          style={{ animation: 'pulse-ring 2.2s ease-out infinite' }}
          aria-hidden="true"
        />
      )}
    </g>
  );
}

// ── Cluster marker ─────────────────────────────────────────────────────────────
function ClusterMarker({ item, pixelX, pixelY }: {
  item: RadarCluster; pixelX: number; pixelY: number;
}) {
  const color = SEV_COLOR[item.topSeverity] ?? 'var(--text-3)';
  return (
    <g aria-label={`Cluster of ${item.count} events`}>
      <circle cx={pixelX} cy={pixelY} r={10}
        fill={color} opacity={0.18}
        stroke={color} strokeWidth={1}
      />
      <text
        x={pixelX} y={pixelY}
        textAnchor="middle" dominantBaseline="middle"
        fill={color}
        fontSize={8} fontFamily="var(--font-mono)"
        fontWeight="700"
      >
        {item.count}
      </text>
    </g>
  );
}

// ── Tooltip ────────────────────────────────────────────────────────────────────
function RadarTooltip({ dot, px, py }: { dot: RadarDot; px: number; py: number }) {
  const isRight = px > CX;
  const foX = isRight ? px - 148 : px + 10;
  const foY = py - 28;
  const relHours = (Date.now() - new Date(dot.firstSeen).getTime()) / (60 * 60 * 1000);
  const age = relHours < 1 ? `${Math.round(relHours * 60)}m` :
    relHours < 24 ? `${relHours.toFixed(0)}h` : `${(relHours / 24).toFixed(0)}d`;

  return (
    <foreignObject
      x={foX} y={foY} width={140} height={60}
      style={{ overflow: 'visible', pointerEvents: 'none' }}
      aria-hidden="true"
    >
      <div style={{
        background: 'var(--bg-1)',
        border: '1px solid var(--line-strong)',
        borderRadius: '6px',
        padding: '5px 8px',
        fontSize: '10px',
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-1)',
        lineHeight: 1.4,
        boxShadow: '0 4px 16px rgb(0 0 0 / .4)',
        backdropFilter: 'blur(8px)',
        maxWidth: '140px',
      }}>
        <div style={{
          fontFamily: 'var(--font-body)',
          fontSize: '11px',
          fontWeight: 600,
          marginBottom: 3,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {dot.title}
        </div>
        <div style={{ color: 'var(--text-3)', fontSize: '9px' }}>
          {dot.severity} · {dot.level} · {dot.sourcesCount} src · {age} ago
        </div>
      </div>
    </foreignObject>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export interface RadarScopeProps {
  /** Pre-computed radar items (dots + clusters) from computeRadarLayout + clusterDots. */
  points: RadarItem[];
  /** Called when a dot is activated via click or keyboard. Callers decide navigation. */
  onSelect: (eventId: string) => void;
  selectedId?: string;
  sweepPeriodS?: number;
  size?: number;
  lastSync?: string;
  countdown?: number;
}

export function RadarScope({
  points,
  onSelect,
  selectedId: _selectedId,
  sweepPeriodS: _sweepPeriodS = 6,
  size = 440,
  lastSync = '--:--',
  countdown = 60,
}: RadarScopeProps) {
  const reducedMotion = useReducedMotion();

  const sweepPathRef  = useRef<SVGPathElement>(null);
  const sweepArmRef   = useRef<SVGLineElement>(null);
  const sweepGlowRef  = useRef<SVGLineElement>(null);
  const _sweepCenterRef = useRef<SVGCircleElement>(null); void _sweepCenterRef;
  const ringTextGroupRef = useRef<SVGGElement>(null);
  const dotGroupsRef  = useRef<Map<string, SVGGElement>>(new Map());
  const scanAngleRef  = useRef(0);
  const prevAngleRef  = useRef(0);

  const [hovered, setHovered] = useState<{ dot: RadarDot; px: number; py: number } | null>(null);

  // Caller provides pre-computed layout items (dots + clusters) via `points` prop.
  // Geometry computation lives in radarLayout.ts so 3D scene can reuse it.
  const items: RadarItem[] = points;

  // Pre-compute pixel positions for all items
  const itemPositions = useMemo(() =>
    items.map(item => {
      const r = item.radiusFrac * R_MAX;
      const a = item.angleDeg;
      return toXY(a, r);
    }),
    [items],
  );

  const handleActivate = useCallback((dot: RadarDot) => {
    onSelect(dot.eventId);
  }, [onSelect]);

  const handleHover = useCallback((dot: RadarDot | null, x: number, y: number) => {
    setHovered(dot ? { dot, px: x, py: y } : null);
  }, []);

  // ── RAF scan animation ───────────────────────────────────────────────────────
  useEffect(() => {
    if (reducedMotion) return;

    let lastTime = performance.now();
    let raf: number;

    function triggerPing(item: RadarDot) {
      const el = dotGroupsRef.current.get(item.eventId);
      if (!el) return;
      el.classList.add('radar-dot-pinging');
      if (item.severity === 'P0') {
        el.classList.add('radar-dot-locked');
        setTimeout(() => el.classList.remove('radar-dot-locked'), 500);
      }
      setTimeout(() => el.classList.remove('radar-dot-pinging'), 750);
    }

    function checkHits(prev: number, next: number) {
      const wraps = next < prev; // crossed 360→0
      for (const item of items) {
        if ('kind' in item) continue; // cluster
        const a = item.angleDeg;
        const hit = wraps
          ? (a >= prev || a <= next)
          : (a > prev && a <= next);
        if (hit) triggerPing(item as RadarDot);
      }
    }

    function tick(now: number) {
      if (!document.hidden) {
        const dt = Math.min(now - lastTime, 100); // clamp to avoid jump after tab switch
        const DEG_PER_MS = 360 / 6000;
        const newAngle = (scanAngleRef.current + dt * DEG_PER_MS) % 360;

        checkHits(prevAngleRef.current, newAngle);
        prevAngleRef.current = scanAngleRef.current;
        scanAngleRef.current = newAngle;

        // Update sweep sector path
        if (sweepPathRef.current) {
          sweepPathRef.current.setAttribute('d', sweepSectorPath(newAngle, 42, R_MAX));
        }
        // Update sweep arm
        const armEnd = toXY(newAngle, R_MAX);
        if (sweepArmRef.current) {
          sweepArmRef.current.setAttribute('x2', armEnd.x.toFixed(2));
          sweepArmRef.current.setAttribute('y2', armEnd.y.toFixed(2));
        }
        if (sweepGlowRef.current) {
          sweepGlowRef.current.setAttribute('x2', armEnd.x.toFixed(2));
          sweepGlowRef.current.setAttribute('y2', armEnd.y.toFixed(2));
        }
        // Counter-rotate outer text
        if (ringTextGroupRef.current) {
          const a = (-(newAngle * 0.12)) % 360;
          (ringTextGroupRef.current as SVGGElement).setAttribute(
            'transform',
            `rotate(${a.toFixed(2)},${CX},${CY})`,
          );
        }
      }
      lastTime = now;
      raf = requestAnimationFrame(tick);
    }

    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [reducedMotion, items]);

  // ── CSS injected for pinging / locked states ─────────────────────────────────
  // (Appended once, doesn't re-render)
  useEffect(() => {
    const id = 'radar-scope-styles';
    if (document.getElementById(id)) return;
    const style = document.createElement('style');
    style.id = id;
    style.textContent = `
      .radar-dot-pinging .ping-ring-1 {
        animation: radar-ping-scale 600ms ease-out forwards !important;
      }
      .radar-dot-pinging .ping-ring-2 {
        animation: radar-ping-scale 600ms ease-out 150ms forwards !important;
      }
      .radar-dot-locked .lockout-crosshair {
        animation: lockout-appear 500ms cubic-bezier(.34,1.56,.64,1) forwards !important;
      }
      @keyframes radar-ping-scale {
        0%   { opacity: 0.8; transform: scale(1); }
        100% { opacity: 0; transform: scale(3.5); }
      }
      @keyframes lockout-appear {
        0%   { opacity: 0; transform: scale(1.6); }
        60%  { opacity: 1; transform: scale(1); }
        80%  { transform: scale(1.04); }
        100% { opacity: 1; transform: scale(1); }
      }
      .radar-dot-group:focus-visible circle,
      .radar-dot-group:focus-visible path {
        outline: none;
        filter: brightness(1.5);
      }
      .radar-dot-group:focus-visible {
        outline: 2px solid var(--accent);
        outline-offset: 4px;
      }
      @media (prefers-reduced-motion: reduce) {
        .radar-dot-pinging .ping-ring-1,
        .radar-dot-pinging .ping-ring-2,
        .radar-dot-locked .lockout-crosshair { animation: none !important; }
      }
    `;
    document.head.appendChild(style);
  }, []);

  // Initial static sweep position (for reduced-motion or before first tick)
  const staticSweepD = sweepSectorPath(0, 42, R_MAX);
  const staticArmEnd = toXY(0, R_MAX);

  return (
    <svg
      viewBox={`0 0 ${VIEWBOX} ${VIEWBOX}`}
      width={size}
      height={size}
      role="group"
      aria-label={`Security radar showing ${points.length} events across vulnerability, incident, and Web3 sectors. Use Tab to navigate individual events.`}
      style={{ display: 'block', flexShrink: 0, overflow: 'visible' }}
    >
      <defs>
        <filter id="dot-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="sweep-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <clipPath id="radar-clip">
          <circle cx={CX} cy={CY} r={R_MAX} />
        </clipPath>
        <RimGlow />
      </defs>

      {/* ── Background + rim glow ── */}
      <circle cx={CX} cy={CY} r={R_MAX + 30}
        fill="url(#rim-glow)" aria-hidden="true"
      />
      <circle cx={CX} cy={CY} r={R_MAX}
        fill="var(--bg-1)"
        stroke="var(--line)"
        strokeWidth={1}
        aria-hidden="true"
      />

      {/* ── Grid (clipped) ── */}
      <g clipPath="url(#radar-clip)">
        <GridRings />
      </g>

      {/* ── Scan sweep (clipped) ── */}
      <g clipPath="url(#radar-clip)" aria-hidden="true">
        {!reducedMotion ? (
          <>
            {/* Afterglow sector */}
            <path
              ref={sweepPathRef}
              d={staticSweepD}
              fill="var(--accent)"
              opacity={0.07}
            />
            {/* Front arm glow */}
            <line
              ref={sweepGlowRef}
              x1={CX} y1={CY}
              x2={staticArmEnd.x} y2={staticArmEnd.y}
              stroke="var(--accent)"
              strokeWidth={6}
              opacity={0.25}
              filter="url(#sweep-glow)"
            />
            {/* Front arm */}
            <line
              ref={sweepArmRef}
              x1={CX} y1={CY}
              x2={staticArmEnd.x} y2={staticArmEnd.y}
              stroke="var(--accent)"
              strokeWidth={1.5}
              opacity={0.9}
            />
          </>
        ) : (
          /* Reduced motion: static 42° sector at 0° */
          <path
            d={staticSweepD}
            fill="var(--accent)"
            opacity={0.12}
          />
        )}
      </g>

      {/* ── Event dots (clipped) ── */}
      <g clipPath="url(#radar-clip)">
        {items.map((item, i) => {
          const pos = itemPositions[i];
          if ('kind' in item) {
            return (
              <ClusterMarker
                key={`cluster-${i}`}
                item={item as RadarCluster}
                pixelX={pos.x}
                pixelY={pos.y}
              />
            );
          }
          const dot = item as RadarDot;
          return (
            <DotMarker
              key={dot.eventId}
              item={dot}
              pixelX={pos.x}
              pixelY={pos.y}
              onHover={handleHover}
              onActivate={handleActivate}
              groupRef={el => {
                if (el) dotGroupsRef.current.set(dot.eventId, el);
                else dotGroupsRef.current.delete(dot.eventId);
              }}
            />
          );
        })}
      </g>

      {/* ── Center crosshair ── */}
      <g aria-hidden="true">
        <line x1={CX - 8} y1={CY} x2={CX + 8} y2={CY}
          stroke="var(--text-3)" strokeWidth={0.8} opacity={0.4} />
        <line x1={CX} y1={CY - 8} x2={CX} y2={CY + 8}
          stroke="var(--text-3)" strokeWidth={0.8} opacity={0.4} />
        <circle cx={CX} cy={CY} r={2.5}
          fill="var(--accent)" opacity={0.8} />
      </g>

      {/* ── Outer rim (above grid) ── */}
      <circle cx={CX} cy={CY} r={R_MAX}
        fill="none"
        stroke="var(--accent)"
        strokeWidth={0.75}
        opacity={0.35}
        aria-hidden="true"
      />

      {/* ── Sector rims + labels ── */}
      <SectorRims />

      {/* ── Bearing scale ── */}
      <BearingScale />

      {/* ── Time ring labels ── */}
      <TimeRingLabels />

      {/* ── Outer ring text (counter-rotates in RAF) ── */}
      <g ref={ringTextGroupRef} aria-hidden="true">
        <OuterRingText lastSync={lastSync} countdown={countdown} />
      </g>

      {/* ── Tooltip ── */}
      {hovered && (
        <RadarTooltip
          dot={hovered.dot}
          px={hovered.px}
          py={hovered.py}
        />
      )}
    </svg>
  );
}
