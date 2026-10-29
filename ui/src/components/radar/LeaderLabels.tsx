/**
 * LeaderLabels — the three NOW labels on the wall radar (2D scope and 3D dome share this; spec 01 §6.4, B2).
 * Placement is utils/labelLayout.layoutLeaderLabels (pure, tested); this file only draws it.
 * three-free: imported by the lazy 3D chunk and by the main-bundle 2D scope alike.
 */
import { useMemo } from 'react';
import type { ImpactSummary, Severity } from '@/types/site-data';
import { layoutLeaderLabels } from '@/utils/labelLayout';
import type { LabelAnchor } from '@/utils/labelLayout';
import { ImpactChip } from '@/components/ImpactChip';
import '@/styles/wall.css';

export interface LeaderLabelItem {
  id: string;
  /** 1-based NOW rank (backend order). */
  rank: number;
  title: string;
  severity: Severity;
  impact: ImpactSummary | null | undefined;
}

/** Fixed box so the layout and the render agree; 2 lines at ≥11 px (the old 8.5 px was unreadable at 1080p). */
export const LABEL_BOX = { w: 236, h: 46 } as const;
const TITLE_MAX = 28;

interface Props {
  items: LeaderLabelItem[];
  /** Screen anchor per item id; missing ⇒ not on the radar (older than 7 d). */
  anchors: Record<string, { x: number; y: number; visible: boolean } | undefined>;
  width: number;
  height: number;
  onSelect: (eventId: string) => void;
}

export function LeaderLabels({ items, anchors, width, height, onSelect }: Props) {
  const placements = useMemo(() => {
    const input: LabelAnchor[] = items.map(it => {
      const a = anchors[it.id];
      return a && Number.isFinite(a.x) && Number.isFinite(a.y)
        ? { id: it.id, x: a.x, y: a.y, visible: a.visible }
        : { id: it.id, x: 0, y: 0, visible: false };
    });
    return layoutLeaderLabels(input, LABEL_BOX, { w: width, h: height });
  }, [items, anchors, width, height]);

  if (placements.length === 0) return null;
  const byId = new Map(items.map(it => [it.id, it]));

  return (
    <div className="ll-layer" data-testid="now-labels">
      <svg className="ll-lines" width={width} height={height} aria-hidden="true">
        {placements.filter(p => p.mode !== 'offscreen').map(p => {
          const sev = byId.get(p.id)?.severity ?? 'P2';
          return (
            <g key={p.id} className={`ll-line sev-${sev}`}>
              <line x1={p.ax} y1={p.ay} x2={p.lx} y2={p.ly} />
              <circle cx={p.ax} cy={p.ay} r={4} />
            </g>
          );
        })}
      </svg>
      {placements.map(p => {
        const it = byId.get(p.id)!;
        const short = it.title.length > TITLE_MAX ? `${it.title.slice(0, TITLE_MAX)}…` : it.title;
        return (
          <button
            key={p.id}
            type="button"
            className={`ll-label sev-${it.severity} mode-${p.mode}`}
            style={{ left: p.x, top: p.y, width: p.w, height: p.h }}
            data-anchor-x={Math.round(p.ax)}
            data-anchor-y={Math.round(p.ay)}
            data-sev={it.severity}
            data-mode={p.mode}
            aria-label={`必须处理第 ${it.rank} 件：${it.title}${p.mode === 'offscreen' ? '（不在雷达范围，超过 7 天）' : ''} · 打开判定抽屉`}
            onClick={() => onSelect(it.id)}
          >
            <span className="ll-meta" aria-hidden="true">
              <b>#{it.rank}</b> · {it.severity}
              {p.mode === 'offscreen'
                ? <span className="ll-off">不在雷达范围（&gt;7d）</span>
                : <ImpactChip impact={it.impact} />}
            </span>
            <span className="ll-title" aria-hidden="true">{short}</span>
          </button>
        );
      })}
    </div>
  );
}
