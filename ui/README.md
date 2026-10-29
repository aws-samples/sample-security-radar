# Security Radar — UI

Static SPA for the Security Radar event feed. Reads JSON published to S3 by the backend `publish` Lambda; served from the same CloudFront distribution.

## Structure

```
ui/
├── public/
│   ├── data/               # Mock data for local dev (backend publishes here in prod)
│   │   ├── events.json     # {kind:"events"} — event list
│   │   ├── sources.json    # {kind:"sources"} — source health
│   │   └── events/         # {kind:"event"} — one file per event_id
│   └── favicon.svg
├── src/
│   ├── types/
│   │   └── site-data.ts    # Generated from schema — DO NOT EDIT BY HAND
│   ├── components/         # Reusable UI components
│   ├── pages/              # Route-level components
│   ├── hooks/              # Data fetching (useEvents, useSources)
│   ├── utils/
│   │   ├── filters.ts      # Pure filter/sort logic (unit tested)
│   │   └── formatters.ts   # Amount/date/hash formatting
│   └── test/               # Vitest tests
└── dist/                   # Build output (gitignored)
```

Screenshots: `docs/screenshots/` (`mock-*` = `npm run screenshot` / `scripts/screenshot-3d.mjs` on mock data, `live-*` = `scripts/live-shots.sh`).

## Commands

```bash
npm install          # install dependencies
npm run gen:types    # regenerate src/types/site-data.ts from ../schemas/site-data.schema.json
npm run dev          # dev server with HMR (binds 127.0.0.1:5173 by default)
npm test             # run all vitest tests
npm run build        # tsc + vite production build → dist/
npm run preview      # serve dist/ on 127.0.0.1:4173 (for screenshots/verification)
```

## Data contract

**Single source of truth**: `/schemas/site-data.schema.json` (JSON Schema draft-2020-12).

TypeScript types in `src/types/site-data.ts` are **generated** from that schema via `npm run gen:types` (json-schema-to-typescript). Never edit the types file by hand; run `gen:types` after any schema change.

Three endpoint shapes:

| File | kind | Contents |
|---|---|---|
| `data/events.json` | `"events"` | Array of `EventSummary` (list view) |
| `data/events/<event_id>.json` | `"event"` | Full event: `EventSummary` + `ItemRef[]` + `TimelineEntry[]` + `AmountPoint[]` + `CveDetail[]` + `TxRef[]` |
| `data/sources.json` | `"sources"` | Array of `SourceHealth` |

All paths are relative (`./data/...`) so they resolve correctly under any CloudFront base path.

## Verification levels (§6 of DESIGN.md)

| Level | Meaning | Badge color |
|---|---|---|
| V0 | Rumor — single unverified source | Gray |
| V1 | Reported — one credible source | Blue |
| V2 | Corroborated — ≥2 independent sources | Amber |
| V3 | Confirmed — KEV / vendor PSIRT / victim statement | Red |
| V4 | Finalized — patched, 7d quiet | Green |
| X | Disputed / retracted / rolled back | Purple |

## Pages

- `/` — Radar: all events, P0 pinned, filterable by domain/level/severity/exploitation/text
- `/vuln` — Vulnerabilities view (domain=vuln pre-filtered)
- `/web3` — Web3 events with amount leaderboard and chain distribution
- `/sources` — Source health table (status, last success, last error, items 24h)
- `/events/:eventId` — Event detail: timeline, evidence chain grouped by independent_group, amount sparkline, CVE card, on-chain tx

## Design

Tactical intelligence terminal aesthetic:
- Near-black background (`#090c0f`), information-dense layout
- **Syne** (display font) for headings; **JetBrains Mono** for CVEs, hashes, amounts
- Level and severity encoded as color + shape + text label (color-blind safe)
- **Verification Rail** (signature element): horizontal V0→V4/X track showing current level position on every event card
- P0 events pulse red; disputed amounts show amber ⚠
- All external strings rendered as plain text (`dangerouslySetInnerHTML` never used)

## Tests

Three test suites under `src/test/`:

1. **schema.test.ts** — validates all `public/data/` JSON files against the schema using `ajv/dist/2020`. Asserts coverage: ≥12 events, all 3 domains, all levels V0-V4+X, all severities, `amount_disputed=true` entries, `summary=null` entries.
2. **filters.test.ts** — unit tests for `applyFilters`, `sortEvents`, `countLast24h` (pure functions, no DOM).
3. **badges.test.ts** — asserts `LEVEL_META` and `SEV_META` have complete mappings for all enum values.
