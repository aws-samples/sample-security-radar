/** On-chain table on the event page: explorer links only for known chains and real hashes; freeze / outflow wording. */
import { describe as d, it, expect } from 'vitest';
import { describe, summary, txUrl } from '@/utils/onchainView';
import type { Onchain, OnchainRow } from '@/types/site-data';

const TX = '0x53bd38b816c23e74134786c29a8c18d792777998a3b9326047b583100e88e2f3';

d('onchain view', () => {
  it('links a real hash on a known chain, nothing else', () => {
    expect(txUrl('ethereum', TX)).toBe(`https://etherscan.io/tx/${TX}`);
    expect(txUrl('tron', TX)).toBeNull();
    expect(txUrl('ethereum', 'javascript:alert(1)')).toBeNull();
  });
  it('says who froze whom and names the short form a report used', () => {
    const f = { kind: 'freeze', issuer: 'Tether', label: '接收方 0x5227…2f8c', address_evidence: '0x5227…cb2f8c' } as OnchainRow;
    expect(describe(f)).toEqual({ kind: 'Tether 冻结', who: '接收方 0x5227…2f8c（报道写作 0x5227…cb2f8c）' });
    const o = { kind: 'outflow', from_label: 'Binance 14', to_label: '接收方 0x5227…2f8c' } as OnchainRow;
    expect(describe(o).who).toBe('Binance 14 → 接收方 0x5227…2f8c');
  });
  it('summarises outflow by token, freezes by issuer, delegations found', () => {
    const o = { totals: { victim_outflow_by_token: { USDC: 8.23e8, USDT: 1.87e9 }, freezes_by_issuer: { Tether: 4, Circle: 3 }, receivers: 3 },
      delegation: [{ delegate: null }, { delegate: '0x63e8' }] } as unknown as Onchain;
    expect(summary(o)).toEqual({ outflow: [['USDT', 1.87e9], ['USDC', 8.23e8]], freezes: [['Tether', 4], ['Circle', 3]], delegated: 1, checked: 2 });
  });
});
