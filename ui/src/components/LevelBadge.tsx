import type { Level } from '@/types/site-data';

interface Props {
  level: Level;
  size?: 'sm' | 'md';
}

const LEVEL_META: Record<Level, { label: string; color: string; shape: string; title: string }> = {
  V0: { label: 'V0', color: 'var(--level-v0)', shape: '◇', title: 'Rumor — single unverified source' },
  V1: { label: 'V1', color: 'var(--level-v1)', shape: '△', title: 'Reported — one credible source' },
  V2: { label: 'V2', color: 'var(--level-v2)', shape: '▲', title: 'Corroborated — ≥2 independent sources' },
  V3: { label: 'V3', color: 'var(--level-v3)', shape: '●', title: 'Confirmed — KEV / vendor PSIRT / official statement' },
  V4: { label: 'V4', color: 'var(--level-v4)', shape: '■', title: 'Finalized — patched, 7d no new activity' },
  X:  { label: 'X',  color: 'var(--level-x)',  shape: '✕', title: 'Disputed / Retracted / Rolled Back' },
};

export function LevelBadge({ level, size = 'md' }: Props) {
  const meta = LEVEL_META[level];
  const fs = size === 'sm' ? '10px' : '11px';
  const pad = size === 'sm' ? '2px 6px' : '3px 8px';
  return (
    <abbr
      title={meta.title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: pad,
        background: `${meta.color}1a`,
        border: `1px solid ${meta.color}55`,
        borderRadius: '6px',
        color: meta.color,
        fontFamily: 'var(--font-mono)',
        fontSize: fs,
        fontWeight: 600,
        letterSpacing: '0.04em',
        textDecoration: 'none',
        whiteSpace: 'nowrap',
        cursor: 'help',
      }}
      aria-label={`Verification level ${meta.label}: ${meta.title}`}
    >
      <span aria-hidden="true">{meta.shape}</span>
      {meta.label}
    </abbr>
  );
}

export { LEVEL_META };
