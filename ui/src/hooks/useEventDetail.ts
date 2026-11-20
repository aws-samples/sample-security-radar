import { useState, useEffect } from 'react';
import type { AmountPoint, Analysis, AttackPath, AwsFix, CveDetail, Disclosure, Sighting, EventSummary, ItemRef, Mitigation, RulePack, AttackTxs, ChainStage, Onchain, PipelineStep, PossibleDuplicate, ProgressStage, Response, ResponseDecision, TimelineEntry, TxRef } from '@/types/site-data';

export interface EventDetailState {
  event: EventSummary | null;
  items: ItemRef[];
  timeline: TimelineEntry[];
  amountHistory: AmountPoint[];
  cveDetails: CveDetail[];
  /** AWS's own fix status for the event's CVE (radar.awsfix); null = none known / older publisher. */
  awsFix: AwsFix | null;
  attackPath: AttackPath | null;    // R9.5
  /** CVE published vs radar first seen (radar.cvemeta); null = no CVE record known / older publisher. */
  disclosure: Disclosure | null;
  /** first report published vs radar first capture (radar.pipeline.sighting); null = older publisher. */
  sighting: Sighting | null;
  tx: TxRef[];
  /** M4 D6 on-chain reconstruction (web3 P0); null when not traced / not web3 / older backend. */
  onchain: Onchain | null;
  attackTxs: AttackTxs | null;
  /** P1b: attack stages the chain rows confirm (radar.stages.chain_evidence); [] for documents published before it. */
  chainStages: ChainStage[];
  /** C4: events the model judged to be the same incident (advisory, not merged). */
  possibleDuplicates: PossibleDuplicate[];
  /** when this page was written — its lifecycle / decisions are as of then, not now (audit 03 4.8) */
  generatedAt: string | null;
  /** undefined = key absent (older publisher); null = not generated for this event. */
  analysis: Analysis | null | undefined;
  progress: ProgressStage[] | undefined;
  pipelineSteps: PipelineStep[] | undefined;
  /**
   * Tri-state on purpose (spec §2.1): undefined = backend did not emit the key; null = this event did not
   * trigger an environment check; object = what Continuum / Security Agent did. Read with `'response' in data`,
   * never `data.response ?? null` (that would merge "not wired" into "not triggered").
   */
  response: Response | null | undefined;
  /** M3 mitigate station. undefined = key absent (older publisher); null = nothing for this event. Both ⇒ no block. */
  mitigation: Mitigation | null | undefined;
  /** 「响应决策」 (radar.decisions), on every event document. undefined = older publisher ⇒ no block. */
  decisions: ResponseDecision[] | undefined;
  /** P2 WAF rule pack. undefined = key absent (older publisher); null = no pack for this event. Both ⇒ no block. */
  rulePack: RulePack | null | undefined;
  loading: boolean;
  /** 'not_found' for a missing event file; any other string = transport/parse error (shown verbatim). */
  error: string | null;
}

const EMPTY: Omit<EventDetailState, 'loading' | 'error'> = {
  event: null, items: [], timeline: [], amountHistory: [], cveDetails: [], awsFix: null, attackPath: null, disclosure: null, sighting: null, tx: [], onchain: null, attackTxs: null, chainStages: [], possibleDuplicates: [], generatedAt: null,
  analysis: undefined, progress: undefined, pipelineSteps: undefined, response: undefined, mitigation: undefined, rulePack: undefined,
  decisions: undefined,
};

export function useEventDetail(eventId: string): EventDetailState {
  const [state, setState] = useState<EventDetailState>({ ...EMPTY, loading: true, error: null });

  useEffect(() => {
    if (!eventId) return;
    let cancelled = false;
    setState({ ...EMPTY, loading: true, error: null });
    fetch(`./data/events/${encodeURIComponent(eventId)}.json`)
      .then(async r => {
        // A missing file falls through the dev/preview server (and CloudFront's SPA error page) to index.html
        // with 200/403/404 — treat "not JSON" as not found instead of surfacing "Unexpected token '<'".
        const ct = r.headers.get('content-type') ?? '';
        if (r.status === 404 || r.status === 403 || ct.includes('text/html')) return { notFound: true as const };
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return { data: await r.json() };
      })
      .then(res => {
        if (cancelled) return;
        if ('notFound' in res) { setState({ ...EMPTY, loading: false, error: 'not_found' }); return; }
        const data = res.data;
        if (data?.kind !== 'event') throw new Error(`Unexpected data kind: ${String(data?.kind)}`);
        setState({
          event: data.event,
          items: data.items ?? [],
          timeline: data.timeline ?? [],
          amountHistory: data.amount_history ?? [],
          cveDetails: data.cve_details ?? [],
          awsFix: data.aws_fix ?? null,
          attackPath: data.attack_path ?? null,
          disclosure: data.disclosure ?? null,
          sighting: data.sighting ?? null,
          tx: data.tx ?? [],
          onchain: data.onchain ?? null,
          attackTxs: data.attack_txs ?? null,
          chainStages: data.chain_stages ?? [],
          possibleDuplicates: data.possible_duplicates ?? [],
          generatedAt: typeof data.generated_at === 'string' ? data.generated_at : null,
          analysis: 'analysis' in data ? data.analysis : undefined,
          progress: data.progress,
          pipelineSteps: data.pipeline_steps,
          response: 'response' in data ? data.response : undefined,
          mitigation: 'mitigation' in data ? data.mitigation : undefined,
          decisions: data.decisions,
          rulePack: 'rule_pack' in data ? data.rule_pack : undefined,
          loading: false,
          error: null,
        });
      })
      .catch((err: unknown) => {
        if (!cancelled) setState(s => ({ ...s, loading: false, error: String(err) }));
      });
    return () => { cancelled = true; };
  }, [eventId]);

  return state;
}
