/** Attack flow on the event page: stages in attack order (radar.stages via ui/src/generated/stages.ts), each anchored on
 *  its earliest report or on the chain rows that confirm it; one-stage advisories hide it. */
import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { AttackFlow } from '@/components/detail/AttackFlow';
import { STAGES, STAGE_ALIASES } from '@/generated/stages';
import { attackFlow, canonicalStage, missingPhases, showFlow } from '@/utils/attackFlow';
import type { ChainStage, EventSummary, ItemRef } from '@/types/site-data';

const it_ = (id: string, phase: ItemRef['phase'], at: string) => ({ item_id: id, phase, published_at: at } as ItemRef);
const schema = JSON.parse(readFileSync(resolve(__dirname, '../../../schemas/site-data.schema.json'), 'utf-8'));

describe('the stage table is the schema enum (one source: radar.stages)', () => {
  it('every schema value is a stage or a legacy alias, in order', () => {
    expect(schema.$defs.AttackStage.enum).toEqual([...STAGES.map(s => s.id), ...Object.keys(STAGE_ALIASES)]);
  });
  it('legacy M4 values read as their stage; unknown values as other', () => {
    expect(canonicalStage('drain')).toBe('asset_transfer');
    expect(canonicalStage('statement')).toBe('disclosure');
    expect(canonicalStage('freeze')).toBe('freeze');
    expect(canonicalStage('nope')).toBe('other');
    expect(canonicalStage(undefined)).toBe('other');
  });
});

describe('attackFlow', () => {
  const items = [it_('f2', 'freeze', '2026-10-29T21:29:00Z'), it_('d1', 'asset_transfer', '2026-10-29T20:51:00Z'),
    it_('f1', 'freeze', '2026-10-29T21:14:00Z'), it_('o', 'other', '2026-10-29T20:00:00Z'), it_('s', 'disclosure', '2026-10-29T22:23:00Z')];
  it('orders by attack stage, anchors each on its earliest report, drops "other"', () => {
    expect(attackFlow(items).map(s => [s.phase, s.count, s.firstItemId]))
      .toEqual([['asset_transfer', 1, 'd1'], ['freeze', 2, 'f1'], ['disclosure', 1, 's']]);
  });
  it('a document published before the rename (drain / statement) draws the same flow', () => {
    const old = [it_('d1', 'drain', '2026-10-29T20:51:00Z'), it_('s', 'statement', '2026-10-29T22:23:00Z')];
    expect(attackFlow(old).map(s => [s.phase, s.label])).toEqual([['asset_transfer', '资产转出'], ['disclosure', '官方披露']]);
  });
  it('a cloud stage sits before the transfer (how they got in comes first)', () => {
    const cloud = [it_('d1', 'asset_transfer', '2026-10-29T20:51:00Z'), it_('k', 'credential_access', '2026-10-30T09:00:00Z')];
    expect(attackFlow(cloud).map(s => s.phase)).toEqual(['credential_access', 'asset_transfer']);
  });
  it('anchors on the published evidence time, not a date-only midnight (live 2026-10-30: 转出 at 10-29 00:00)', () => {
    const db = { ...it_('db', 'asset_transfer', '2026-10-29T00:00:00Z'), evidence_at: '2026-10-29T20:51:00Z' } as ItemRef;
    const flash = { ...it_('d1', 'asset_transfer', '2026-10-29T20:51:00Z'), evidence_at: '2026-10-29T20:51:00Z' } as ItemRef;
    const [drain] = attackFlow([db, flash]);
    expect(drain.firstAt).toBe('2026-10-29T20:51:00Z');
  });
  it('a single-stage story has no flow', () => {
    expect(showFlow(attackFlow([it_('d1', 'asset_transfer', '2026-10-29T20:51:00Z')]))).toBe(false);
    expect(showFlow(attackFlow(items))).toBe(true);
  });
});

describe('web3 incidents keep the same format with one stage', () => {
  const one = attackFlow([it_('db', 'asset_transfer', '2026-10-20T00:00:00Z')]);
  it('a web3 incident shows its flow from one stage (live 2026-10-30: 136 of 141 had none), an advisory still needs two', () => {
    expect(showFlow(one, true)).toBe(true);
    expect(showFlow(one)).toBe(false);
  });
  it('lists the expected stages nothing evidences yet, in attack order — never the cloud stages', () => {
    expect(missingPhases(one)).toEqual(['洗钱', '冻结', '官方披露', '归因', '追回']);
  });
});

// ── B8: a stage the chain proves is not "no reports" ──────────────────────────────────────────────────────────────────
const chain: ChainStage[] = [
  { stage: 'asset_transfer', kind: 'outflow', clock: 'chain', count: 3, first_at: '2026-10-29T20:24:23Z', first_tx: '0x53bd38b8' },
  { stage: 'asset_transfer', kind: 'attack_tx', clock: 'chain', count: 1, first_at: '2026-10-29T20:30:00Z', first_tx: '0xatk' },
  { stage: 'freeze', kind: 'freeze', clock: 'chain', count: 10, first_at: '2026-10-29T21:01:35Z', first_tx: '0xf' },
];

describe('chain rows are stage evidence (04-reconstruction B8)', () => {
  const steps = attackFlow([it_('d1', 'asset_transfer', '2026-10-29T20:53:33Z')], chain);
  it('a freeze only the chain shows is a step, anchored on the chain, not on a report', () => {
    const fr = steps.find(s => s.phase === 'freeze')!;
    expect([fr.count, fr.chain, fr.firstItemId, fr.firstAt]).toEqual([0, 10, null, '2026-10-29T21:01:35Z']);
  });
  it('and is no longer listed as missing', () => {
    expect(missingPhases(steps)).toEqual(['洗钱', '官方披露', '归因', '追回']);
  });
  it('keeps both clocks: on chain 20:24:23, first report 20:53:33', () => {
    const tr = steps.find(s => s.phase === 'asset_transfer')!;
    expect([tr.chain, tr.chainAt, tr.reportAt, tr.firstAt, tr.firstItemId])
      .toEqual([4, '2026-10-29T20:24:23Z', '2026-10-29T20:53:33Z', '2026-10-29T20:24:23Z', 'd1']);
  });
});

describe('AttackFlow renders chain-proven stages and the AWS controls', () => {
  const ev = { domain: 'web3', attribution: null } as unknown as EventSummary;
  const html = renderToStaticMarkup(<AttackFlow event={ev} items={[it_('d1', 'asset_transfer', '2026-10-29T20:53:33Z')]}
    chain={chain} onCite={() => {}}><p>tables</p></AttackFlow>);
  it('a freeze proven on chain is drawn and not listed as having no evidence', () => {
    expect(html).toContain('冻结：0 条报道，链上 10 笔');
    expect(html).toContain('跳到链上记录');
    expect(html).toMatch(/尚无证据的阶段：洗钱 · 官方披露/);
    expect(html).not.toMatch(/尚无证据的阶段：[^<]*冻结/);
  });
  it('the chain tables are the anchor of chain-only steps', () => {
    expect(html).toContain('id="af-chain"');
  });
  it('lists the AWS controls of the evidenced stages from the generated table', () => {
    expect(html).toContain('AWS Nitro Enclaves');
    expect(html).toContain('本可阻断 / 检测这些阶段的 AWS 控制（1 个阶段）');
  });
});

// ── a delegation is read at check time: never shown as when the key access happened (review of p1/stages) ─────────────
describe('a check time is not an event time', () => {
  const deleg: ChainStage = { stage: 'key_access', kind: 'delegation', clock: 'checked', count: 1,
    first_at: '2026-10-30T00:00:00Z', first_tx: null };
  const items = [it_('d1', 'asset_transfer', '2026-10-29T20:53:33Z')];
  const [key] = attackFlow(items, [deleg, ...chain]);
  it('the delegation is evidence of key access but not its chain clock nor its earliest time', () => {
    expect([key.phase, key.chain, key.chainAt, key.firstAt, key.checked, key.checkedAt])
      .toEqual(['key_access', 0, null, null, 1, '2026-10-30T00:00:00Z']);
  });
  const ev = { domain: 'web3', attribution: null } as unknown as EventSummary;
  const html = renderToStaticMarkup(<AttackFlow event={ev} items={items} chain={[deleg, ...chain]} onCite={() => {}} />);
  it('is labelled as a check, not as 「链上 … 笔」 hours after the theft', () => {
    expect(html).toContain('核查时仍委托 10-30 00:00 · 1 个钱包（发生时间未查询）');
    expect(html).not.toMatch(/链上 10-30 00:00/);
    expect(html).toContain('发生时间未知');
  });
});
