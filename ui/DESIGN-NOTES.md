# Security Radar UI — Design Notes v3

Last updated: 2026-10-23. Phase 1 complete (§0–§3).

---

## Aesthetic Direction: Night Ops / Day Ops

**Tone:** Precision military dashboard. Not a marketing site. Every color and spacing decision serves information density.

**Differentiator:** The radar is the identity. All other UI elements defer to it — the HUD bracket panels, monospace labels, and sector grammar reinforce the same military-ops vernacular.

**Anti-goals:** No purple gradients on white. No Inter + card shadows. No generic status pages.

---

## § 0  Constraints Met

- Zero external font requests (`@fontsource` CDN-free subsets)
- No `dangerouslySetInnerHTML` anywhere
- External links get `rel="noopener noreferrer"` via global CSS / component convention
- Mock data stays in `ui/mock-data/`; nothing in `public/`
- No three.js / echarts / d3 / mapbox added
- No copied code from react-bits / mempool / iDataV
- All animations gated on `prefers-reduced-motion`; disabled state shows static sector
- `src/utils/staleness.ts`, `src/utils/health.ts`, WallPage 24h-loss calculation all preserved

---

## § 1  Design Language Tokens

### Fonts

| Role | Family | Weights | Rationale |
|------|--------|---------|-----------|
| Display / KPI headings | **Space Grotesk** | 300, 400, 500, 700 | Geometric but with personality; 300 weight makes large numbers feel austere |
| Body / UI text | **Inter** | 400, 500, 600 | Neutral workhorse for dense label copy |
| Mono / CVE IDs / amounts | **JetBrains Mono** | 400, 500 | Designed for code; tabular numbers are razor-sharp |
| Chinese labels | **Noto Sans SC** | 400, 500 | unicode-range subsetting; only needed CJK subsets load |

### Color Palette

#### Night Ops (dark, default for wall)

| Token | Value | Role |
|-------|-------|------|
| `--bg-0` | `#05070D` | Canvas |
| `--bg-1` | `#0B1020` | Panel surface |
| `--bg-2` | `#121A2E` | Hover / secondary |
| `--accent` | `#22D3EE` | Brand cyan — scan arm, links, focus rings |
| `--p0` | `#FF5C74` | Critical severity **only** — may glow |
| `--p1` | `#FFB547` | High severity |
| `--p2` | `#5CC8F5` | Medium severity |
| `--dom-web3` | `#A78BFA` | Web3 domain — **purple, NOT green** |
| `--dom-vuln` | `#60A5FA` | Vulnerability domain |
| `--dom-incident` | `#FB923C` | Incident domain |
| `--loss` | `#FF7A8A` | Financial loss figures |
| `--recovered` | `#34D399` | Recovered / frozen (green = good) |

#### Day Ops (light)

| Token | Value | Notes |
|-------|-------|-------|
| `--bg-0` | `#F4F6FB` | Cool neutral, not warm cream |
| `--accent` | `#0B6B85` | Muted teal — 5.6:1 on bg-0 |
| `--p0` | `#C1121F` | 5.8:1 on white |
| `--dom-web3` | `#6D28D9` | 6.6:1 on white |

### Semantic Color Rule

Green (`--recovered: #34D399`) means **only** "recovered / OK / frozen". Web3 domain is **purple** — this was the key semantic fix that makes the dashboard readable: "green = good news", not "green = blockchain".

### Legacy Aliases

All old token names (`--domain-web3`, `--sev-p0`, `--bg-base`, etc.) remain as CSS `var()` aliases pointing to new values, so non-Phase-1 components keep working with zero edits. The alias for `--domain-web3` now maps to purple.

---

## § 2  RadarScope Component

**File:** `src/components/radar/RadarScope.tsx`

### Architecture

RadarScope is a **pure renderer**. All geometry lives in `src/utils/radarLayout.ts` pure functions. The component receives pre-computed layout via props — designed so a future three.js 3D scene can reuse the same layout functions without touching the SVG renderer.

**Props:**
```typescript
interface RadarScopeProps {
  points: RadarItem[];          // pre-computed from computeRadarLayout + clusterDots
  onSelect: (eventId: string) => void;  // caller decides navigation
  selectedId?: string;
  sweepPeriodS?: number;        // default 6s/revolution
  size?: number;
  lastSync?: string;
  countdown?: number;
}
```

### Visual Features

- **5 concentric rings** at log-scale time boundaries (1h / 24h / 7d)
- **Bearing scale** 0–350° with tick marks every 10°
- **Sector rims**: 4px colored arcs at outer ring edge; capsule labels outside
- **Scan sweep**: JS RAF loop (no setState per frame) with conic-gradient fill; 6s/revolution
- **Hit detection**: scan arm crossing a dot → `radar-dot-pinging` class → ripple; P0 hit → `radar-dot-locked` → 4-bracket crosshair
- **Dot shapes**: hollow-circle (V0), filled circle (V1–V3), diamond (V4)
- **Dot radius**: `clamp(3 + 2√n, 3, 12)` where n = `independent_sources`
- **Outer ring text**: "SECURITY RADAR · LIVE ·…" slow counter-rotation via `textPath`
- **Reduced motion**: static 42° sector at 0°, no rotation, no ripples; full information preserved

### Layout Mathematics (`radarLayout.ts`)

```
radius = log(ageHours + 1) / log(169)
   → center = most recent (0)
   → outer ring = 7 days old (1)

Domain sectors: VULN 0–120°, INCIDENT 120–240°, WEB3 240–360°
Angle jitter: FNV-1a hash(event_id) → [0, 1) → deterministic placement
```

---

## § 3  Wall Page (`#/wall`)

**File:** `src/pages/WallPage.tsx`

**Viewport:** 1920×1080 reference; scales proportionally via CSS grid + ResizeObserver.

### Layout

```
┌─────────────────────────────────────────────────────┐  ← 40px status bar
│ ● LIVE · 14/15 OK · LED dots · countdown ring · ↑ ↓ │
├──────────────┬────────────────────────┬──────────────┤
│ Left 340px   │ Center (flex: 1)       │ Right 340px  │
│              │                        │              │
│  Live Feed   │  KPI row (40px)        │  Web3 loss   │
│  ≥12 cards   │  ┌──────────────────┐  │  inline bars │
│  P0 glow     │  │  WallCenterStage │  │              │
│  auto-scroll │  │  (RadarScope)    │  │  Chain LEDs  │
│              │  └──────────────────┘  │              │
│              │                        │  Vuln top    │
│              │                        │  CVE chips   │
├──────────────┴────────────────────────┴──────────────┤  ← 180px bottom
│  Block Band (isometric 24h cubes) │  Event Ticker   │
└─────────────────────────────────────────────────────┘
```

### Key Components

**`WallCenterStage`** (`src/components/WallCenterStage.tsx`): Thin layout slot wrapper. Phase 2 will add `<Suspense>` + lazy three.js 3D scene here. SVG radar is the permanent fallback.

**Hero KPIs**: `useCountUp()` animation (cubic-ease count-up on mount); Space Grotesk 300 at 40px.

**`BlockBand`**: SVG isometric cubes (3-face parallelogram construction) for each of 24 hourly buckets. Height = log-normalised event count. Color = max severity in bucket. All text inside is `aria-hidden` within `role="img"` container; visible labels use `visibility: hidden` / full opacity (never opacity < 1) to satisfy axe color-contrast.

**`SourceDot`**: 8×8 LED status dots with `role="status"` and `aria-label`; pulse ring for degraded/failing sources.

**`CountdownRing`**: SVG circle with `stroke-dasharray` animated fill showing seconds until next refresh.

**`Ticker`**: RAF-driven auto-scroll (0.4px/frame), pauses on hover.

### 3D Readiness

The wall page computes `radarPoints = clusterDots(computeRadarLayout(events))` BEFORE passing to `RadarScope`. Phase 2 can pass the same `radarPoints` to a three.js renderer and use `WallCenterStage` as the Suspense boundary.

---

## Verification Record (Phase 1)

| Gate | Result |
|------|--------|
| `npm test` | **85/85 pass** (7 test files) |
| `npm run build` | **0 TS errors** · dist/assets/index.js 252KB gzip 75KB |
| `npm run a11y` | **12/12 pass** · 0 violations · all pages × both themes |
| Screenshots | **10 captured** (`docs/screenshots/mock-*`) |

---

## Files Modified / Created (Phase 1)

| File | Change |
|------|--------|
| `src/styles/global.css` | Full token system rewrite — Night Ops + Day Ops + legacy aliases |
| `src/utils/radarLayout.ts` | New — pure layout functions (log-radius, FNV-1a, clustering, hour buckets) |
| `src/test/radarLayout.test.ts` | New — 35 tests covering all pure functions |
| `src/components/radar/RadarScope.tsx` | New — full SVG radar with RAF scan, hit detection, a11y |
| `src/components/WallCenterStage.tsx` | New — 3D swap slot for future phase |
| `src/pages/WallPage.tsx` | Rewrite — §3 wall layout (status bar, 3-column, block band, ticker) |
| `src/App.tsx` | `/wall` moved outside Layout (fullscreen, no sidebar) |

---

## 3D 雷达穹顶（Phase 2）

### 技术选型

Method A：native three.js 0.168 + EffectComposer（UnrealBloomPass + OutputPass），React.lazy 单独 chunk，Vite manualChunks 隔离 `node_modules/three`。

### 架构

```
WallPage  ──props──►  WallCenterStage
                          │
                          ├─ useRenderMode()  ──►  detect()  ──►  能力检测
                          │                         (hash query: ?force3d=1 仅 DEV)
                          │
                          ├─ [mode=webgl]  ──►  <Suspense fallback={svgScene}>
                          │                         <WallScene3D>  (lazy chunk)
                          │                             └─ createEngine(canvas)
                          │
                          └─ [mode=svg / T4 fallback]  ──►  svgScene
```

### 降级层级

1. `prefers-reduced-motion` → SVG
2. WebGL2 上下文创建失败（含驱动报错）→ SVG（try-catch 覆盖，不静默）
3. `WEBGL_debug_renderer_info` 匹配 SwiftShader / llvmpipe → SVG
4. `?gl=off` 手动关闭 → SVG
5. FPS 卫兵 T4（50 帧滚动窗口 < 55.5fps × 4 tier 降级）→ SVG
6. 所有降级状态均显示可见 status tag（不静默）

### 渲染特征

- **扫描 shader**：PlaneGeometry 旋转 −π/2，`atan(x,y)` 从北顺时针，AdditiveBlending，uSweep uniform 每帧递增
- **事件柱体**：3 类 InstancedMesh（TorusGeometry V0 / CylinderGeometry V1-V3 / CylinderGeometry+OctahedronGeometry V4），`MeshBasicMaterial.toneMapped=false`
- **P0 HDR bloom**：`severityColorHDR('P0')` 返回 channels × 4（>1.0），UnrealBloomPass threshold=1.0，HalfFloat render target 传递 HDR 值；LDR 环境（无 EXT_color_buffer_half_float）自动降级为 UnsignedByteType + bloom disabled
- **相机轨道**：PerspectiveCamera(40) at (0,9,11)，±12° 方位角 120s 周期正弦摆动
- **坐标约定**：`polarToXZ(angleDeg, radiusFrac)` 与 SVG RadarScope 完全一致（北=0°顺时针，x=R·r·sin θ，z=−R·r·cos θ）

### chunk 隔离

| 产物 | gzip |
|------|------|
| `index-*.js`（主 bundle，不含 WebGLRenderer） | ~75 KB |
| `three-*.js`（lazy chunk） | **119.1 KB ≤ 160 KB 门禁** |

`scripts/check-chunks.mjs` 在构建后自动校验：主 bundle 不含 `WebGLRenderer`，three chunk ≤ 160 KB。

### StrictMode 兼容

React 18 StrictMode 会双调用 effect（mount → cleanup → remount）。`dispose()` 故意不调用 `renderer.forceContextLoss()`，避免 canvas WebGL 上下文被永久销毁导致第二次 mount 失败（`gl.getSupportedExtensions() === null`）。

### 无障碍

- `<canvas aria-hidden="true" tabIndex={-1}>`
- DOM overlay 提供 sector 标签 + 时间环标签（pointer-events: none）
- 隐藏 `<table aria-label="雷达事件列表">` 提供完整事件列表（screen reader 可访问，视觉不可见）
- `role="status" aria-live="polite"` 状态 tag 朗读降级原因

### 验证记录（Phase 2）

| Gate | 结果 |
|------|------|
| `npm test` | **129/129 通过**（8 个测试文件，含 radar3dLayout + quality + capability） |
| `npm run build` | **0 TS 错误**，3D chunks 125.5 KB gzip ≤ 150 KB 门禁 |
| `npm run a11y` | **12/12 通过**，0 violations，全页面 × 双主题 |
| 截图 | **4 张**（wall-3d-dark / wall-3d-light / wall-2d-fallback / wall-2d-reduced，1920×1080） |
| canvas 实测尺寸 | **1166×749 px**（61% 宽 × 69% 高，viewport 1920×1080） |
| 非背景像素占比 | **89.3%**（dark / light 均等，阈值 R+G+B > 30，`preserveDrawingBuffer` DEV-only） |
| 降级断言 | `data-render-mode=svg` ✓ · no canvas[aria-hidden] ✓ · SVG present ✓ · `data-render-reason` 含"已降级为 2D" ✓ |
| 手动切换 | `localStorage 'sr-render-mode-override'` 持久化，`canToggle` 门控（3D 不可用时禁止切回） |
