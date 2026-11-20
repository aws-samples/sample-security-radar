/**
 * R9.4 (Neo 2026-11-19: 「中间这个圆球到底是啥意思…表意让大家觉得不是特别清晰」): what every glyph on the wall's centre
 * stage means, said in words — one definition for the 2D scope and the 3D scene. Pure (tested), the UI only renders it.
 */
import type { ShieldChannel } from '@/utils/mitigate';

export type StageMode = '3d' | '2d';
export interface KeyRow { glyph: 'position' | 'mark' | 'core' | 'link' | 'ring'; title: string; text: string }

export function stageKeyRows(mode: StageMode): KeyRow[] {
  // colour · size · distance · shape are in the always-visible strip (legendItems); the key explains what only the 3D
  // scene draws — 2D has nothing more to say, so its key is empty and not rendered
  if (mode === '2d') return [];
  return [
    { glyph: 'core', title: '中心球', text: '你的代码（Security Agent / Continuum 核查的目标）' },
    { glyph: 'link', title: '连线', text: '红实线 = 事件已命中你的代码 · 青虚线 = 核查中' },
    { glyph: 'ring', title: '环', text: '边缘防护 WAF · DNS Firewall · Inspector：绿 生效 · 灰 未生效 · 橙 失败' }];
}

/** The centre sphere's caption: never just a name — what is known about the code right now (an empty state says so). */
export function coreCaption(hits: number, checking: number): { text: string; tone: 'hit' | 'checking' | 'quiet' } {
  if (hits > 0) return { text: `${hits} 个事件命中你的代码`, tone: 'hit' };
  if (checking > 0) return { text: `${checking} 个事件正在核查你的代码`, tone: 'checking' };
  return { text: '近 7 天没有事件指向你的代码', tone: 'quiet' };
}

const CHANNEL_NAME: Record<ShieldChannel['key'], string> = { WAF: 'WAF', DNS: 'DNS Firewall', INSPECTOR: 'Inspector' };
const STATE_WORD: Record<ShieldChannel['state'], string> = { on: '生效', off: '未生效', error: '失败', unknown: '未读取' };

/** A ring's label: the full channel name and its state in a word (it was 「DNS」 alone, coloured). */
export function ringLabel(c: ShieldChannel): string {
  return `${CHANNEL_NAME[c.key]} · ${STATE_WORD[c.state]}`;
}

/** The always-visible legend strip under the scope (Neo 2026-11-19: 「这个颜色跟大小跟原先的距离，你要给人解释清楚，否则
 *  看起来会比较懵逼」): the three encodings every dot carries, plus its shape — one line, never folded. */
export interface LegendItem { key: 'color' | 'size' | 'distance' | 'shape'; label: string; text: string }
export function legendItems(): LegendItem[] {
  return [
    { key: 'color', label: '颜色', text: '红 P0 · 橙 P1 · 蓝 P2' },
    { key: 'size', label: '大小', text: '独立来源越多越大（3D 为柱高）' },
    { key: 'distance', label: '距离', text: '越靠中心越新（1h · 24h · 7d）' },
    { key: 'shape', label: '形状', text: '空心 未证实 · 实心 已证实 · 菱形 定论' },
  ];
}
