import { describe, expect, it } from 'vitest';
import type { EventSummary } from '@/types/site-data';
import { lossBoard, lossLabel } from '@/utils/lossBoard';

const ev = (id: string, title: string, amount: number | null, level: string, entities: string[] = []): EventSummary =>
  ({ event_id: id, title, domain: 'web3', amount_usd_latest: amount, level, entities } as unknown as EventSummary);

// the board as it read live on 2026-11-16 (level, entities and figures from data/events.json)
const LIVE = [
  ev('ev_e52a', 'Is Ethereum the “worst asset of all time,” amid estimated $8.83 billion BitMine loss ?', 8.83e9, 'V1'),
  ev('ev_0a4e', 'Binance CEX — Hot Wallets Drained via Compromised DevOps Laptop', 6.34e9, 'V4', ['Binance', 'Binance CEX']),
  ev('ev_2481', 'Whale 0xc8b5 has finally given up, closing his long on 190,952 $NVDA', 6.3e9, 'V1'),
  ev('ev_9ff9', 'https://t.co/agOq56biUi > We are actively investigating a security incident', 1.55e7, 'V2'),
  ev('ev_55f8', 'Upbit Operator Dunamu Swings to $13.8 Million Q3 Net Loss', 1.5e9, 'V1'),
  ev('ev_a57e', 'Kava Lend — Arithmetic Error', 3.8e6, 'V2', ['Kava Lend']),
];

describe('Web3 loss board', () => {
  it('ranks corroborated incidents only, so a single article cannot top it', () => {
    expect(lossBoard(LIVE).map(e => e.event_id)).toEqual(['ev_0a4e', 'ev_9ff9', 'ev_a57e']);
  });
  it('names the victim, or the headline without its link, quote marker and tags — never a first word', () => {
    expect(lossLabel(LIVE[1])).toBe('Binance');
    expect(lossLabel(LIVE[3])).toBe('We are actively…');
    expect(lossLabel(ev('x', '#PeckShieldAlert #Lighter drained', 1, 'V2'))).toBe('Lighter drained');
    expect(lossLabel(ev('y', 'https://t.co/x', 1, 'V2'))).toBe('未命名事件');
  });
});
