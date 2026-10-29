/**
 * WallScene3D — React.lazy target for the three.js 3D radar dome.
 *
 * Fills its parent container (WallCenterStage sets position:relative on the
 * wrapping div; this component is position:absolute inset:0 to fill it).
 */
import { useRef, useEffect, useCallback, useMemo, useState } from 'react';
import { createEngine } from './engine/createEngine';
import type { EngineHandle } from './engine/createEngine';
import type { ScreenPoint } from './engine/project';
import type { Dot3D } from '@/utils/radar3dLayout';
import { R_WORLD, polarToXZ } from '@/utils/radar3dLayout';
import { ageMsToRadiusFrac } from '@/utils/radarLayout';
import { LeaderLabels } from '@/components/radar/LeaderLabels';
import type { LeaderLabelItem } from '@/components/radar/LeaderLabels';
import type { QualityTier } from './engine/quality';

export interface WallScene3DProps {
  dots: Dot3D[];
  /** NOW events (backend order) — the only pillars that get a leader label (UI-IA §4). */
  labels: LeaderLabelItem[];
  selectedEventId?: string | null;
  onSelect: (eventId: string) => void;
  onFallback: (reason: string) => void;
  width: number;
  height: number;
}

export default function WallScene3D({
  dots,
  labels,
  selectedEventId,
  onSelect,
  onFallback,
  width,
  height,
}: WallScene3DProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const engineRef = useRef<EngineHandle | null>(null);

  // Create engine once on mount
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    let engine;
    try {
      engine = createEngine(
        canvas,
        undefined,
        (tier: QualityTier, reason: string) => {
          if (tier === 4) onFallback(reason);
        },
      );
    } catch (err) {
      console.warn('[WallScene3D] engine init failed, triggering SVG fallback:', err);
      onFallback('已降级为 2D（WebGL 初始化失败）');
      return;
    }

    engineRef.current = engine;
    engine.onPick(onSelect);

    return () => {
      engine.dispose();
      engineRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { engineRef.current?.resize(width, height); }, [width, height]);
  useEffect(() => { engineRef.current?.setDots(dots); }, [dots]);
  useEffect(() => { engineRef.current?.setSelected(selectedEventId ?? null); }, [selectedEventId]);

  // World points that need a screen position: NOW pillar tops, then the static sector / time-ring labels.
  const worldPoints = useMemo(() => {
    const byId = new Map(dots.map(d => [d.eventId, d]));
    const now = labels.map(l => {
      const d = byId.get(l.id);
      return d ? { key: l.id, x: d.x, y: d.height + 0.15, z: d.z } : null;
    }).filter((p): p is { key: string; x: number; y: number; z: number } => p !== null);
    const statics = [
      ...SECTOR_LABELS.map(s => ({ key: s.label, ...xz(s.angleDeg, 1.18), y: 0 })),
      ...TIME_LABELS.map(t => ({ key: t.label, ...xz(42, ageMsToRadiusFrac(t.ageMs)), y: 0 })),
    ];
    return [...now, ...statics];
  }, [dots, labels]);

  // Projected with the engine's own (orbiting) camera — B2. Re-projected every 250 ms while the camera moves;
  // state only changes when a point moved ≥0.5 px, so a static camera costs one projection.
  const [screen, setScreen] = useState<Record<string, ScreenPoint>>({});
  useEffect(() => {
    let last: Record<string, ScreenPoint> = {};
    const run = () => {
      const eng = engineRef.current;
      if (!eng) return;
      const pts = eng.project(worldPoints);
      const next: Record<string, ScreenPoint> = {};
      let changed = Object.keys(last).length !== pts.length;
      worldPoints.forEach((w, i) => {
        next[w.key] = pts[i];
        const o = last[w.key];
        if (!o || Math.abs(o.x - pts[i].x) >= 0.5 || Math.abs(o.y - pts[i].y) >= 0.5 || o.visible !== pts[i].visible) changed = true;
      });
      if (changed) { last = next; setScreen(next); }
    };
    run();
    const t = window.setInterval(() => { if (engineRef.current?.isCameraMoving()) run(); }, 250);
    return () => window.clearInterval(t);
  }, [worldPoints, width, height]);

  // Hidden a11y table
  const tableRows = useMemo(() =>
    dots.slice(0, 50).map(d => ({
      id: d.eventId, domain: d.domain, severity: d.severity,
      level: d.level, sources: d.sourcesCount, title: d.title, firstSeen: d.firstSeen,
    })),
    [dots],
  );

  const handleTableClick = useCallback((e: React.MouseEvent<HTMLTableElement>) => {
    const row = (e.target as HTMLElement).closest('tr[data-id]') as HTMLElement | null;
    if (row?.dataset.id) onSelect(row.dataset.id);
  }, [onSelect]);

  return (
    // position:absolute + inset:0 so the canvas fills WallCenterStage's ref div
    <div
      style={{ position: 'absolute', inset: 0 }}
      data-testid="wall-scene-3d"
    >
      <canvas
        ref={canvasRef}
        aria-hidden="true"
        tabIndex={-1}
        width={width}
        height={height}
        style={{ display: 'block', width: '100%', height: '100%' }}
      />

      <DomLabels screen={screen} />

      {labels.length > 0 && (
        <LeaderLabels items={labels} anchors={screen} width={width} height={height} onSelect={onSelect} />
      )}

      <table
        aria-label="雷达事件列表"
        onClick={handleTableClick}
        style={{
          position: 'absolute', left: '-9999px', width: 1, height: 1,
          overflow: 'hidden', clip: 'rect(0,0,0,0)', whiteSpace: 'nowrap', border: 0,
        }}
      >
        <caption style={{ clip: 'rect(0,0,0,0)', position: 'absolute' }}>
          安全雷达事件（领域 · 严重度 · 等级 · 信源数 · 首见时间）
        </caption>
        <thead>
          <tr>
            <th scope="col">领域</th><th scope="col">严重度</th><th scope="col">等级</th>
            <th scope="col">信源数</th><th scope="col">标题</th><th scope="col">首见时间</th>
          </tr>
        </thead>
        <tbody>
          {tableRows.map(r => (
            <tr key={r.id} data-id={r.id} style={{ cursor: 'pointer' }}>
              <td>{r.domain}</td><td>{r.severity}</td><td>{r.level}</td>
              <td>{r.sources}</td><td>{r.title}</td>
              <td>{new Date(r.firstSeen).toISOString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── DOM Labels overlay (sector + time-ring names, positioned by the engine camera) ─────────────────

const SECTOR_LABELS = [
  { label: 'VULN',     angleDeg: 60  },
  { label: 'INCIDENT', angleDeg: 180 },
  { label: 'WEB3',     angleDeg: 300 },
];

const DOMAIN_COLORS: Record<string, string> = {
  VULN:     'var(--dom-vuln)',
  INCIDENT: 'var(--dom-incident)',
  WEB3:     'var(--dom-web3)',
};

const TIME_LABELS = [
  { label: '1h',  ageMs: 60 * 60 * 1000 },
  { label: '24h', ageMs: 24 * 60 * 60 * 1000 },
  { label: '7d',  ageMs: 7 * 24 * 60 * 60 * 1000 },
];

function xz(angleDeg: number, radiusFrac: number) {
  return polarToXZ(angleDeg, radiusFrac, R_WORLD);
}

function DomLabels({ screen }: { screen: Record<string, ScreenPoint> }) {
  return (
    <div aria-hidden="true" style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
      {SECTOR_LABELS.map(({ label }) => {
        const pos = screen[label];
        if (!pos?.visible) return null;
        return (
          <div key={label} style={{
            position: 'absolute', left: pos.x, top: pos.y,
            transform: 'translate(-50%, -50%)',
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
            letterSpacing: '0.12em',
            color: DOMAIN_COLORS[label] ?? 'var(--text-3)',
            background: 'color-mix(in srgb, #05070D 70%, transparent)',
            padding: '2px 6px', borderRadius: 3,
            border: `1px solid ${DOMAIN_COLORS[label] ?? 'var(--line)'}`,
          }}>{label}</div>
        );
      })}
      {TIME_LABELS.map(({ label }) => {
        const pos = screen[label];
        if (!pos?.visible) return null;
        return (
          <div key={label} style={{
            position: 'absolute', left: pos.x, top: pos.y,
            transform: 'translate(-50%, -50%)',
            fontFamily: 'var(--font-mono)', fontSize: 10,
            color: '#8291AB',
          }}>{label}</div>
        );
      })}
    </div>
  );
}
