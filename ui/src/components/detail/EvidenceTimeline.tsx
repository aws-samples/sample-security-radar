import type { ItemRef, TimelineEntry } from '@/types/site-data';
import type { EvidenceGroup } from '@/utils/evidence';
import { formatAmount } from '@/utils/formatters';
import { utcShort } from '@/utils/timeZh';
import { safeHref } from '@/utils/safeHref';

const TIER: Record<ItemRef['tier'], { shape: string; word: string; tone: string }> = {
  T1: { shape: '◆', word: 'T1 一手/官方', tone: 'ok' },
  T2: { shape: '▲', word: 'T2 媒体/研究', tone: 'info' },
  T3: { shape: '●', word: 'T3 社区', tone: 'muted' },
};

function Item({ it, n, flash, echo }: { it: ItemRef; n: number; flash: boolean; echo?: boolean }) {
  const t = TIER[it.tier];
  return (
    <article id={`item-${it.item_id}`} tabIndex={-1} className={`ev-item${echo ? ' ev-echo' : ''}${flash ? ' is-flash' : ''}`} aria-label={`证据 ${n}：${it.source_name}`}>
      <span className="ev-num">[{n}]</span>
      <div>
        <div className="ev-src">
          <span className={`ev-tier tone-${t.tone}`}><span aria-hidden="true">{t.shape} </span>{t.word}</span>
          <span>{it.source_name}</span>
          <time className="dt-mono dt-muted" dateTime={it.published_at}>{utcShort(it.published_at)} UTC</time>
        </div>
        <div className="ev-title">{it.title}</div>
        {!echo && <div className="ev-excerpt">{it.excerpt}</div>}
        <div className="ev-sig">
          {it.signals.kev && <span className="chip" style={{ color: 'var(--p0)' }}>KEV</span>}
          {it.signals.poc && <span className="chip" style={{ color: 'var(--p1)' }}>PoC</span>}
          {it.signals.exploited === 'yes' && <span className="chip" style={{ color: 'var(--p0)' }}>在野利用</span>}
          {it.signals.amount_usd !== null && <span className="chip" style={{ color: 'var(--loss)' }}>{formatAmount(it.signals.amount_usd)}</span>}
        </div>
      </div>
      <a href={safeHref(it.url)} target="_blank" rel="noopener noreferrer" aria-label={`打开原文：${it.title}`} style={{ fontSize: 12 }}>原文 ↗</a>
    </article>
  );
}

interface Props {
  groups: EvidenceGroup[];
  numbers: Map<string, number>;
  expanded: Set<number>;
  onToggle: (group: number) => void;
  flashId: string | null;
}

/** L3: one node per independent source (shape = tier), echoes folded behind "+N 转载". */
export function EvidenceTimeline({ groups, numbers, expanded, onToggle, flashId }: Props) {
  return (
    <ol className="ev-groups" aria-label={`证据：${groups.length} 个独立来源`}>
      {groups.map(g => {
        const t = TIER[g.lead.tier];
        const open = expanded.has(g.group);
        const panel = `ev-echoes-${g.group}`;
        return (
          <li key={g.group} className={`ev-group tone-${t.tone}`} data-shape={t.shape}>
            <Item it={g.lead} n={numbers.get(g.lead.item_id)!} flash={flashId === g.lead.item_id} />
            {g.echoes.length > 0 && (
              <>
                <div className="ev-fold">
                  <button type="button" className="btn-ghost" aria-expanded={open} aria-controls={panel} onClick={() => onToggle(g.group)}>
                    {open ? '收起转载' : `+${g.echoes.length} 转载`}
                    <span className="dt-muted dt-small">（同源：{[...new Set(g.echoes.map(e => e.source_name))].join('、')}）</span>
                  </button>
                </div>
                <div id={panel} hidden={!open}>
                  {open && g.echoes.map(e => <Item key={e.item_id} it={e} n={numbers.get(e.item_id)!} flash={flashId === e.item_id} echo />)}
                </div>
              </>
            )}
          </li>
        );
      })}
    </ol>
  );
}

const KIND_WORD: Record<TimelineEntry['kind'], string> = {
  created: '事件创建', item_added: '加入证据', merged: '合并', level_change: '等级变化',
  severity_change: '严重度变化', exploitation_change: '利用状态变化', amount_change: '金额修订', repaired: '人工修复',
};

/** 变化记录 — collapsed by default (it is the audit trail, not the story). */
export function ChangeLog({ timeline }: { timeline: TimelineEntry[] }) {
  return (
    <details className="dt-section dt-details">
      <summary>变化记录 <span className="dt-mono dt-muted" style={{ fontSize: 12, fontWeight: 400 }}>（{timeline.length} 条）</span></summary>
      <ol className="cl">
        {timeline.map((e, i) => (
          <li key={i}>
            <time dateTime={e.at}>{utcShort(e.at)} UTC</time>
            <span>{KIND_WORD[e.kind] ?? e.kind}{(e.from !== null || e.to !== null) && <span className="dt-mono dt-muted"> {e.from ?? '—'} → {e.to ?? '—'}</span>}</span>
          </li>
        ))}
      </ol>
    </details>
  );
}
