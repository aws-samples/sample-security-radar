/**
 * RadarScan — SVG radar with rotating sweep arm.
 * Events appear as dots in domain sectors, radius by severity.
 * Pure SVG + CSS animation — no canvas or external library.
 *
 * Fix (2026-10-23): dots are now clipped to the radar circle; radius is clamped
 * so no dot visually overflows; events are sampled ≤150 by severity priority.
 * Size prop drives viewBox scaling; pass responsive size from parent.
 */
import { useRef, useState } from 'react';
import type { EventSummary } from '@/types/site-data';

interface Props {
  events: EventSummary[];
  /** Rendered size in px. Should fill the available panel. */
  size?: number;
}

const CX = 200;
const CY = 200;
const R_MAX = 170;

// Domain → sector (start angle in degrees, 0=top, clockwise)
const DOMAIN_SECTOR: Record<string, { start: number; end: number; label: string; color: string }> = {
  vuln:     { start: 0,   end: 120, label: 'VULN',     color: 'var(--domain-vuln)' },
  incident: { start: 120, end: 240, label: 'INCIDENT', color: 'var(--domain-incident)' },
  web3:     { start: 240, end: 360, label: 'WEB3',     color: 'var(--domain-web3)' },
};

// Severity → radius band [min%, max%] — kept well inside R_MAX
const SEV_RADIUS: Record<string, [number, number]> = {
  P0: [0.65, 0.88],   // outer band, clearly inside circle
  P1: [0.38, 0.60],
  P2: [0.15, 0.33],
};

const DOT_R: Record<string, number> = { P0: 5, P1: 3.5, P2: 2.5 };

const MAX_DOTS = 150;

/** FNV1a-style deterministic hash → 0..1 */
function strHash(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return (h >>> 0) / 0xffffffff;
}

/** Polar (angle degrees from top, clockwise) → SVG Cartesian */
function polar(angleDeg: number, r: number): { x: number; y: number } {
  const rad = (angleDeg - 90) * (Math.PI / 180);
  return { x: CX + r * Math.cos(rad), y: CY + r * Math.sin(rad) };
}

/** Build SVG sector path (pie slice) */
function sectorPath(startDeg: number, endDeg: number, outerR: number): string {
  const s = polar(startDeg, outerR);
  const e = polar(endDeg, outerR);
  const large = endDeg - startDeg > 180 ? 1 : 0;
  return `M${CX},${CY} L${s.x},${s.y} A${outerR},${outerR} 0 ${large},1 ${e.x},${e.y} Z`;
}

/** Tooltip that follows the mouse */
function RadarTooltip({ x, y, text }: { x: number; y: number; text: string }) {
  const anchor = x > CX ? 'right' : 'left';
  return (
    <g>
      <foreignObject
        x={anchor === 'right' ? x - 130 : x + 8}
        y={y - 16}
        width={122}
        height={32}
        style={{ overflow: 'visible', pointerEvents: 'none' }}
        aria-hidden="true"
      >
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '4px',
          padding: '3px 6px',
          fontSize: '9px',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-primary)',
          lineHeight: 1.3,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
          maxWidth: '120px',
        }}>
          {text}
        </div>
      </foreignObject>
    </g>
  );
}

interface DotInfo {
  x: number;
  y: number;
  color: string;
  isP0: boolean;
  dotR: number;
  ev: EventSummary;
}

export function RadarScan({ events, size = 400 }: Props) {
  const [hovered, setHovered] = useState<{ x: number; y: number; text: string } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  // Sample max MAX_DOTS events, priority: P0 → P1 → P2
  const sampled = (() => {
    const p0 = events.filter(e => e.severity === 'P0');
    const p1 = events.filter(e => e.severity === 'P1');
    const p2 = events.filter(e => e.severity === 'P2');
    const budget0 = Math.min(p0.length, Math.ceil(MAX_DOTS * 0.5));
    const budget1 = Math.min(p1.length, Math.ceil(MAX_DOTS * 0.35));
    const budget2 = Math.min(p2.length, MAX_DOTS - budget0 - budget1);
    return [...p0.slice(0, budget0), ...p1.slice(0, budget1), ...p2.slice(0, budget2)];
  })();

  // Place each event as a dot — radius clamped strictly inside circle
  const dots: DotInfo[] = sampled.flatMap(ev => {
    const sector = DOMAIN_SECTOR[ev.domain];
    if (!sector) return [];

    const radBand = SEV_RADIUS[ev.severity] ?? SEV_RADIUS.P2;
    const dotR = DOT_R[ev.severity] ?? 2.5;
    const h1 = strHash(ev.event_id);
    const h2 = strHash(ev.event_id + 'r');

    const sectorSpan = sector.end - sector.start;
    const margin = sectorSpan * 0.10;
    const angle = sector.start + margin + h1 * (sectorSpan - margin * 2);

    // Clamp radius so dot never overflows: max r = R_MAX - dotR - 2 (2px safety margin)
    const rawRadius = (radBand[0] + h2 * (radBand[1] - radBand[0])) * R_MAX;
    const radius = Math.min(rawRadius, R_MAX - dotR - 2);
    const pt = polar(angle, radius);

    const isP0 = ev.severity === 'P0';
    return [{ ...pt, color: sector.color, isP0, dotR, ev }];
  });

  return (
    <svg
      ref={svgRef}
      viewBox="0 0 400 400"
      width={size}
      height={size}
      role="img"
      aria-label={`Radar scan showing ${events.length} security events across vulnerability, incident, and Web3 sectors`}
      style={{ overflow: 'hidden', display: 'block', flexShrink: 0 }}
    >
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <filter id="dot-glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
        <clipPath id="radar-circle">
          <circle cx={CX} cy={CY} r={R_MAX} />
        </clipPath>
      </defs>

      {/* Background circle */}
      <circle cx={CX} cy={CY} r={R_MAX + 4}
        fill="var(--bg-surface-3)"
        stroke="var(--border)"
        strokeWidth="1.5"
      />

      {/* Grid — concentric rings */}
      {[0.25, 0.5, 0.75, 1.0].map(f => (
        <circle key={f} cx={CX} cy={CY} r={f * R_MAX}
          fill="none"
          stroke="var(--border)"
          strokeWidth={f === 1 ? 1 : 0.5}
          opacity={f === 1 ? 0.7 : 0.35}
          clipPath="url(#radar-circle)"
        />
      ))}

      {/* Sector divider lines */}
      {[0, 120, 240].map(angle => {
        const p = polar(angle, R_MAX);
        return (
          <line key={angle}
            x1={CX} y1={CY} x2={p.x} y2={p.y}
            stroke="var(--border)"
            strokeWidth="0.75"
            opacity="0.5"
          />
        );
      })}

      {/* Sector fills (very subtle) */}
      {Object.entries(DOMAIN_SECTOR).map(([, s]) => (
        <path
          key={s.label}
          d={sectorPath(s.start, s.end, R_MAX)}
          fill={s.color}
          opacity="0.04"
          clipPath="url(#radar-circle)"
        />
      ))}

      {/* Sector labels — placed at 70% radius inside the sector */}
      {Object.entries(DOMAIN_SECTOR).map(([, s]) => {
        const mid = (s.start + s.end) / 2;
        const labelPt = polar(mid, R_MAX * 0.62);
        return (
          <text key={s.label}
            x={labelPt.x} y={labelPt.y}
            textAnchor="middle"
            dominantBaseline="middle"
            fill={s.color}
            fontSize="9"
            fontFamily="var(--font-mono)"
            fontWeight="700"
            letterSpacing="0.08em"
            opacity="0.75"
          >
            {s.label}
          </text>
        );
      })}

      {/* Severity ring labels */}
      {[
        { r: 0.24, label: 'P2' },
        { r: 0.49, label: 'P1' },
        { r: 0.76, label: 'P0' },
      ].map(({ r, label }) => (
        <text key={label}
          x={CX + 3} y={CY - r * R_MAX - 2}
          fill="var(--text-muted)"
          fontSize="6.5"
          fontFamily="var(--font-mono)"
          opacity="0.5"
        >
          {label}
        </text>
      ))}

      {/* Sweep arm — clipped inside the radar circle */}
      <g
        className="radar-sweep-arm"
        style={{
          transformOrigin: `${CX}px ${CY}px`,
          animation: 'radar-sweep 5s linear infinite',
        }}
        clipPath="url(#radar-circle)"
      >
        {/* Trail sector — 90° behind the arm */}
        <path
          d={`M${CX},${CY} L${CX},${CY - R_MAX} A${R_MAX},${R_MAX} 0 0,0 ${CX - R_MAX},${CY} Z`}
          fill="rgba(6,182,212,0.07)"
        />
        <path
          d={`M${CX},${CY} L${CX},${CY - R_MAX} A${R_MAX},${R_MAX} 0 0,0 ${CX - R_MAX * 0.707},${CY - R_MAX * 0.707} Z`}
          fill="rgba(6,182,212,0.06)"
        />
        {/* Arm glow */}
        <line x1={CX} y1={CY} x2={CX} y2={CY - R_MAX}
          stroke="rgba(6,182,212,0.35)" strokeWidth="4" filter="url(#glow)"
        />
        {/* Arm line */}
        <line x1={CX} y1={CY} x2={CX} y2={CY - R_MAX}
          stroke="rgba(6,182,212,0.80)" strokeWidth="1.5"
        />
        <circle cx={CX} cy={CY} r={3} fill="rgba(6,182,212,0.85)" />
      </g>

      {/* Event dots — clipped strictly inside radar-circle */}
      <g clipPath="url(#radar-circle)">
        {dots.map((d, i) => (
          <g key={i}
            style={{ cursor: 'pointer' }}
            onMouseEnter={() => setHovered({ x: d.x, y: d.y, text: `${d.ev.title} [${d.ev.severity}]` })}
            onMouseLeave={() => setHovered(null)}
          >
            {/* P0 halo pulse */}
            {d.isP0 && (
              <circle cx={d.x} cy={d.y} r={d.dotR + 5}
                fill={d.color} opacity="0.18"
                style={{ animation: 'pulse-ring 2.2s ease-out infinite' }}
              />
            )}
            {/* Main dot */}
            <circle
              cx={d.x} cy={d.y} r={d.dotR}
              fill={d.color}
              opacity={d.isP0 ? 1 : 0.75}
              filter={d.isP0 ? 'url(#dot-glow)' : undefined}
            >
              <title>{d.ev.title} [{d.ev.severity}]</title>
            </circle>
          </g>
        ))}
      </g>

      {/* Center crosshair */}
      <line x1={CX - 6} y1={CY} x2={CX + 6} y2={CY} stroke="var(--text-muted)" strokeWidth="0.8" opacity="0.3" />
      <line x1={CX} y1={CY - 6} x2={CX} y2={CY + 6} stroke="var(--text-muted)" strokeWidth="0.8" opacity="0.3" />

      {/* Hover tooltip */}
      {hovered && (
        <RadarTooltip x={hovered.x} y={hovered.y} text={hovered.text} />
      )}
    </svg>
  );
}
