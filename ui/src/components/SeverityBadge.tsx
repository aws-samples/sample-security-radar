import type { Severity } from '@/types/site-data';

interface Props {
  severity: Severity;
  pulse?: boolean;
}

const SEV_META: Record<Severity, { color: string; label: string; title: string }> = {
  P0: { color: 'var(--sev-p0)', label: 'P0', title: 'Critical — immediate action required' },
  P1: { color: 'var(--sev-p1)', label: 'P1', title: 'High — action within 24h' },
  P2: { color: 'var(--sev-p2)', label: 'P2', title: 'Medium — monitor, daily brief' },
};

export function SeverityBadge({ severity, pulse = false }: Props) {
  const meta = SEV_META[severity];
  return (
    <abbr
      title={meta.title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        padding: '3px 8px',
        background: `${meta.color}18`,
        border: `1px solid ${meta.color}60`,
        borderRadius: '6px',
        color: meta.color,
        fontFamily: 'var(--font-mono)',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.06em',
        textDecoration: 'none',
        whiteSpace: 'nowrap',
        cursor: 'help',
      }}
      aria-label={`Severity ${meta.label}: ${meta.title}`}
    >
      {pulse && severity === 'P0' && (
        <span
          aria-hidden="true"
          style={{
            display: 'inline-block',
            width: '6px',
            height: '6px',
            borderRadius: '50%',
            background: meta.color,
            animation: 'pulse-dot 1.4s ease-in-out infinite',
            flexShrink: 0,
          }}
        />
      )}
      {meta.label}
    </abbr>
  );
}

export { SEV_META };
