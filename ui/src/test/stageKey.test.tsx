/**
 * R9.4 (Neo 2026-11-19: 「中间这个圆球到底是啥意思…表意让大家觉得不是特别清晰」): every glyph on the wall's stage is
 * named in words; the sphere's caption says what is known (an empty state says so); a ring says its channel and state.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { renderToStaticMarkup } from 'react-dom/server';
import { coreCaption, legendItems, ringLabel, stageKeyRows } from '@/utils/stageKey';
import { StageKey } from '@/components/wall/StageKey';
import { StageLegend } from '@/components/wall/StageLegend';

const SCENE = readFileSync(resolve(__dirname, '../components/wall3d/WallScene3D.tsx'), 'utf8');
const STAGE = readFileSync(resolve(__dirname, '../components/WallCenterStage.tsx'), 'utf8');
const WALL = readFileSync(resolve(__dirname, '../pages/WallPage.tsx'), 'utf8');

describe('stage key', () => {
  it('the key names what only 3D draws; colour, size, distance and shape are in the strip', () => {
    expect(stageKeyRows('3d').map(r => r.glyph)).toEqual(['core', 'link', 'ring']);
    expect(stageKeyRows('2d')).toEqual([]);
    expect(legendItems().map(i => i.label)).toEqual(['颜色', '大小', '距离', '形状']);
    expect(legendItems().find(i => i.key === 'color')!.text).toBe('红 P0 · 橙 P1 · 蓝 P2');
    expect(legendItems().find(i => i.key === 'size')!.text).toMatch(/独立来源越多越大/);
    expect(legendItems().find(i => i.key === 'distance')!.text).toMatch(/越靠中心越新/);
    const core = stageKeyRows('3d').find(r => r.glyph === 'core')!;
    expect(core.text).toMatch(/你的代码/);
    expect(stageKeyRows('3d').find(r => r.glyph === 'ring')!.text).toMatch(/WAF · DNS Firewall · Inspector/);
  });

  it('renders every row with its glyph, and folds', () => {
    const open = renderToStaticMarkup(<StageKey mode="3d" />);
    expect((open.match(/class="stage-key-row"/g) ?? []).length).toBe(3);
    expect((open.match(/<svg/g) ?? []).length).toBe(3);
    expect(renderToStaticMarkup(<StageKey mode="2d" />)).toBe('');
    const strip = renderToStaticMarkup(<StageLegend />);
    expect((strip.match(/<li>/g) ?? []).length).toBe(4);
    const folded = renderToStaticMarkup(<StageKey mode="3d" defaultOpen={false} />);
    expect(folded).toMatch(/aria-expanded="false"/);
    expect(folded).not.toMatch(/stage-key-row/);
  });

  it('the wall stage shows the key in both modes', () => {
    expect(STAGE).toMatch(/<StageKey key=\{useWebGL \? '3d' : '2d'\} mode=\{useWebGL \? '3d' : '2d'\}/);
    // the strip is in the page flow under the stage — never an overlay on the dots
    expect(WALL).toMatch(/\{!evLoading && <StageLegend \/>\}/);
    expect(STAGE).not.toMatch(/<StageLegend/);
  });
});

describe('the sphere and the rings say what they are', () => {
  it('the caption is a state, never just a name; the empty state says empty', () => {
    expect(coreCaption(2, 5)).toEqual({ text: '2 个事件命中你的代码', tone: 'hit' });
    expect(coreCaption(0, 3)).toEqual({ text: '3 个事件正在核查你的代码', tone: 'checking' });
    expect(coreCaption(0, 0).text).toBe('近 7 天没有事件指向你的代码');
    expect(SCENE).toMatch(/const cap = coreCaption\(hits, links\.length - hits\);/);
    expect(SCENE).not.toMatch(/未见命中/);
  });

  it('a ring label is the full channel name and its state', () => {
    expect(ringLabel({ key: 'DNS', state: 'off', detail: '' })).toBe('DNS Firewall · 未生效');
    expect(ringLabel({ key: 'INSPECTOR', state: 'on', detail: '' })).toBe('Inspector · 生效');
    expect(ringLabel({ key: 'WAF', state: 'error', detail: '' })).toBe('WAF · 失败');
    expect(SCENE).toMatch(/\{ringLabel\(c\)\}/);
  });
});
