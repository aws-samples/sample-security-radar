import type { Level } from '@/types/site-data';
import { LEVEL_META } from './LevelBadge';
import { signalCells } from '@/utils/home';

const LEVEL_WORD: Record<Level, string> = {
  V0: '传闻', V1: '已报道', V2: '已互证', V3: '已确认', V4: '定稿', X: '有争议',
};

/**
 * 5-cell verification signal + "V3 已确认" text (replaces VerificationRail on rows: the rail was mostly empty
 * circles that did not say what the current level means). Double-encoded: filled cells + text + colour.
 */
export function SignalBar({ level }: { level: Level }) {
  const { filled, disputed } = signalCells(level);
  const color = LEVEL_META[level].color;
  return (
    <span className="sig" role="img" aria-label={`核验等级 ${level}：${LEVEL_WORD[level]}`} title={LEVEL_META[level].title}
      style={{ ['--sig' as string]: color }}>
      <span className="sig-cells" aria-hidden="true">
        {[0, 1, 2, 3, 4].map(i => <i key={i} className={i < filled ? 'on' : disputed ? 'x' : ''} />)}
      </span>
      <span className="sig-txt" aria-hidden="true"><b>{level}</b> {LEVEL_WORD[level]}</span>
    </span>
  );
}
