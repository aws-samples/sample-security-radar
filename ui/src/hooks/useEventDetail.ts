import { useState, useEffect } from 'react';
import type {
  EventSummary, ItemRef, TimelineEntry, AmountPoint, CveDetail, TxRef, Analysis, ProgressStage, PipelineStep, Response, PossibleDuplicate, Mitigation } from '@/types/site-data';

export interface EventDetailState {
  event: EventSummary | null;
  items: ItemRef[];
  timeline: TimelineEntry[];
  amountHistory: AmountPoint[];
  cveDetails: CveDetail[];
  tx: TxRef[];
  /** C4: events the model judged to be the same incident (advisory, not merged). */
  possibleDuplicates: PossibleDuplicate[];
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
  loading: boolean;
  /** 'not_found' for a missing event file; any other string = transport/parse error (shown verbatim). */
  error: string | null;
}

const EMPTY: Omit<EventDetailState, 'loading' | 'error'> = {
  event: null, items: [], timeline: [], amountHistory: [], cveDetails: [], tx: [], possibleDuplicates: [],
  analysis: undefined, progress: undefined, pipelineSteps: undefined, response: undefined, mitigation: undefined,
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
          tx: data.tx ?? [],
          possibleDuplicates: data.possible_duplicates ?? [],
          analysis: 'analysis' in data ? data.analysis : undefined,
          progress: data.progress,
          pipelineSteps: data.pipeline_steps,
          response: 'response' in data ? data.response : undefined,
          mitigation: 'mitigation' in data ? data.mitigation : undefined,
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
