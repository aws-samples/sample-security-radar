/**
 * AmountSparkline — hand-drawn SVG step chart for amount_history.
 * No external chart library. Pure SVG.
 */
import type { AmountPoint } from '@/types/site-data';
import { formatAmount } from '@/utils/formatters';

interface Props {
  data: AmountPoint[];
  disputed?: boolean;
  width?: number;
  height?: number;
}

export function AmountSparkline({ data, disputed = false, width = 200, height = 50 }: Props) {
  if (data.length === 0) return null;
  if (data.length === 1) {
    return (
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--text-secondary)' }}>
        {formatAmount(data[0].value)}
        {disputed && <span style={{ color: 'var(--sev-p1)', marginLeft: '4px' }}>⚠ disputed</span>}
      </div>
    );
  }

  const sorted = [...data].sort((a, b) => new Date(a.observed_at).getTime() - new Date(b.observed_at).getTime());
  const values = sorted.map(d => d.value);
  const minV = Math.min(...values);
  const maxV = Math.max(...values);
  const range = maxV - minV || 1;
  const pad = 4;

  // Build step-chart path
  const points = sorted.map((d, i) => {
    const x = pad + (i / (sorted.length - 1)) * (width - pad * 2);
    const y = pad + (1 - (d.value - minV) / range) * (height - pad * 2);
    return { x, y, d };
  });

  let pathD = `M ${points[0].x} ${points[0].y}`;
  for (let i = 1; i < points.length; i++) {
    pathD += ` H ${points[i].x} V ${points[i].y}`;
  }

  const color = disputed ? 'var(--sev-p1)' : 'var(--text-accent)';

  return (
    <div>
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        aria-label={`Amount history: ${values.map(v => formatAmount(v)).join(' → ')}`}
        role="img"
        style={{ display: 'block', overflow: 'visible' }}
      >
        {/* Area fill */}
        <path
          d={pathD + ` V ${height - pad} H ${points[0].x} Z`}
          fill={color}
          fillOpacity={0.08}
        />
        {/* Line */}
        <path
          d={pathD}
          fill="none"
          stroke={color}
          strokeWidth={1.5}
          strokeLinejoin="round"
        />
        {/* Points */}
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={2.5} fill={color} />
        ))}
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2px' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)' }}>
          {formatAmount(values[0])}
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: disputed ? 'var(--sev-p1)' : 'var(--text-accent)' }}>
          {formatAmount(values[values.length - 1])}
          {disputed && ' ⚠'}
        </span>
      </div>
    </div>
  );
}
