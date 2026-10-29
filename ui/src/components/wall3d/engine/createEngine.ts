/**
 * createEngine.ts — imperative three.js engine for the 3D radar dome.
 *
 * Manages: scene setup, grid, scan shader, stars, pillar InstancedMeshes,
 * EffectComposer (UnrealBloom), Raycaster picking, RAF loop, FPS guardian,
 * visibility pause, and full dispose.
 *
 * React wrapper (WallScene3D.tsx) calls createEngine() on mount and
 * engine.dispose() on unmount. Everything else goes through the handle.
 */

import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';

import { ageMsToRadiusFrac } from '@/utils/radarLayout';
import type { Dot3D } from '@/utils/radar3dLayout';
import { R_WORLD, BLOOM_THRESHOLD } from '@/utils/radar3dLayout';
import { orbitPosition, projectToScreen } from './project';
import type { ScreenPoint } from './project';
import {
  initialQualityState, advanceQuality, tierSettings, tierReason,
  TIER_SETTINGS,
} from './quality';
import type { QualityTier } from './quality';

// ── GLSL shaders ──────────────────────────────────────────────────────────────

const SCAN_VERT = /* glsl */`
  varying vec2 vLocalXY;
  void main() {
    vLocalXY = position.xy;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const SCAN_FRAG = /* glsl */`
  uniform float uSweep;
  varying vec2 vLocalXY;
  void main() {
    float r = length(vLocalXY);
    if (r > 6.05) discard;

    // atan(x, y) gives angle from +Y axis CW, matching north=0 convention
    float theta = atan(vLocalXY.x, vLocalXY.y);

    // Sweep trail: fade over 42° (0.7330 rad, UI-BRIEF §2), capped at 0.07 so it tints instead of hiding the
    // pillars behind it (was 0.35 additive ⇒ an opaque cyan wedge over ~1/6 of the Web3 sector, spec 01 §6.1;
    // spec cap is ≤0.18, but additive + linear→sRGB output lifts 0.18 to a ~45% teal on the near-black disk).
    float diff = mod(uSweep - theta + 6.28318530, 6.28318530);
    float FADE_RAD = 0.73304; // 42° in radians
    // (1 - smoothstep(0, F, x)): smoothstep with edge0 > edge1 is undefined in GLSL — drivers rendered it flat.
    float sweepAlpha = (1.0 - smoothstep(0.0, FADE_RAD, diff)) * 0.07;
    // Bright leading edge ≈1.5 px wide: the arc length r·diff in world units, ~0.03 at the dome's framing.
    if (diff * max(r, 0.3) < 0.03) sweepAlpha = 0.45;

    // Domain sector tint: kept at 3% additive so it barely tints the
    // near-black background without dominating the scene.
    float normT = mod(theta + 6.28318530, 6.28318530);
    vec3 domainColor;
    if (normT < 2.09440) {
      domainColor = vec3(0.11, 0.31, 0.85);  // vuln #1D4ED8
    } else if (normT < 4.18879) {
      domainColor = vec3(0.55, 0.22, 0.04);  // incident warm amber
    } else {
      domainColor = vec3(0.40, 0.15, 0.80);  // web3 #6D28D9
    }
    // 1.5% additive — barely perceptible tint against the near-black bg
    float domAlpha = 0.015;

    float totalAlpha = max(sweepAlpha, domAlpha);
    if (totalAlpha < 0.005) discard;

    vec3 sweepColor = vec3(0.09, 0.85, 0.93);  // cyan accent
    float t = sweepAlpha / (totalAlpha + 0.001);
    vec3 finalColor = mix(domainColor, sweepColor, t);
    gl_FragColor = vec4(finalColor, totalAlpha);
  }
`;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface EngineHandle {
  /** Update the event dots displayed on the radar. */
  setDots(dots: Dot3D[]): void;
  /** Highlight a selected event (shows crosshair). */
  setSelected(eventId: string | null): void;
  /** Register a callback for when the user picks an event. */
  onPick(cb: (eventId: string) => void): void;
  /** Manually set quality tier (called by FPS guardian or parent). */
  setTier(tier: QualityTier): void;
  /** Resize the renderer to match the current container size. */
  resize(width: number, height: number): void;
  /** Clean up all GPU resources. */
  dispose(): void;
  /** Get current quality tier reason string for status bar. */
  getReason(): string;
  /** Project world points to CSS px with the engine's own camera (the one on screen). */
  project(points: ReadonlyArray<{ x: number; y: number; z: number }>): ScreenPoint[];
  /** true while the camera orbits (caller re-projects periodically); false ⇒ one projection is enough. */
  isCameraMoving(): boolean;
}

// ── Geometry helpers ──────────────────────────────────────────────────────────

function buildGridGeometry(): THREE.BufferGeometry {
  const verts: number[] = [];

  // Helper: push a line segment
  const seg = (x0: number, z0: number, x1: number, z1: number, y = 0.001) => {
    verts.push(x0, y, z0, x1, y, z1);
  };

  // 3 time rings at 1h / 24h / 7d
  const ringRadii = [
    ageMsToRadiusFrac(1 * 60 * 60 * 1000) * R_WORLD,
    ageMsToRadiusFrac(24 * 60 * 60 * 1000) * R_WORLD,
    ageMsToRadiusFrac(7 * 24 * 60 * 60 * 1000) * R_WORLD,
  ];
  const N_RING = 96;
  for (const rr of ringRadii) {
    for (let i = 0; i < N_RING; i++) {
      const a0 = (i / N_RING) * Math.PI * 2;
      const a1 = ((i + 1) / N_RING) * Math.PI * 2;
      seg(rr * Math.sin(a0), -rr * Math.cos(a0),
          rr * Math.sin(a1), -rr * Math.cos(a1));
    }
  }

  // 3 sector dividers (0°, 120°, 240°)
  for (const deg of [0, 120, 240]) {
    const rad = deg * (Math.PI / 180);
    seg(0, 0, R_WORLD * Math.sin(rad), -R_WORLD * Math.cos(rad));
  }

  // Radial ticks at the outer edge (every 5°, long every 30°)
  for (let deg = 0; deg < 360; deg += 5) {
    const rad = deg * (Math.PI / 180);
    const isLong = deg % 30 === 0;
    const inner = R_WORLD + 0.05;
    const outer = R_WORLD + (isLong ? 0.22 : 0.12);
    seg(inner * Math.sin(rad), -inner * Math.cos(rad),
        outer * Math.sin(rad), -outer * Math.cos(rad));
  }

  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3));
  return geo;
}

function buildStarGeometry(count: number): THREE.BufferGeometry {
  const pos = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    // Uniform distribution on sphere shell radius 28-32
    const theta = Math.acos(2 * (i / count) - 1);
    const phi = (i * 2.399963) % (Math.PI * 2); // golden angle
    const r = 28 + ((i * 7919) % 400) / 100; // 28–32 world units
    pos[i * 3]     = r * Math.sin(theta) * Math.cos(phi);
    pos[i * 3 + 1] = r * Math.cos(theta);
    pos[i * 3 + 2] = r * Math.sin(theta) * Math.sin(phi);
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(pos, 3));
  return geo;
}

// ── Main factory ──────────────────────────────────────────────────────────────

export function createEngine(
  canvas: HTMLCanvasElement,
  onFpsUpdate?: (fps: number) => void,
  onTierChange?: (tier: QualityTier, reason: string) => void,
): EngineHandle {
  // ── Renderer ──
  // Pre-acquire the WebGL2 context and guard getShaderPrecisionFormat from
  // returning null.  The WebGL spec allows null when precision is unsupported,
  // but three.js WebGLCapabilities doesn't handle that case and throws.
  // A canvas can only hold one WebGL2 context: three.js reuses the one we
  // create here, so the patch is active when three.js reads precision formats.
  // Must match the preserveDrawingBuffer flag used by three.js below; the browser
  // reuses the same context object for all subsequent getContext('webgl2') calls
  // on the same canvas (per spec), so the attributes from the *first* call win.
  const _preCtx = canvas.getContext('webgl2', {
    preserveDrawingBuffer: import.meta.env.DEV,
  }) as WebGL2RenderingContext | null;
  if (_preCtx) {
    const _orig = _preCtx.getShaderPrecisionFormat.bind(_preCtx);
    _preCtx.getShaderPrecisionFormat = (shaderType: number, precisionType: number) =>
      _orig(shaderType, precisionType)
        // Return mediump-equivalent values as a safe fallback when the driver
        // doesn't report a precision format (headless/sandboxed environments).
        ?? ({ rangeMin: 8, rangeMax: 8, precision: 23 } as WebGLShaderPrecisionFormat);
  }

  // Do NOT pass `context:` here — let three.js call canvas.getContext('webgl2')
  // itself.  The browser returns the *same* context object we just patched
  // (spec: only one WebGL2 context per canvas; subsequent getContext calls
  // return the existing one regardless of new attributes).
  const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: false,
    powerPreference: 'high-performance',
    // Allow canvas.toDataURL() in DEV for screenshot pixel-ratio assertions.
    // Vite replaces import.meta.env.DEV with false at production build time.
    preserveDrawingBuffer: import.meta.env.DEV,
  });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));
  // No tone mapping on purpose (B1 option chosen, spec 01 §6.3 step 3): ACES would darken the P1/P2 tokens
  // (1.0 → ≈0.8). Exposure is capped at the source instead — only P0's R channel exceeds 1.0
  // (radar3dLayout.severityColorHDR) and OutputPass clamps the 8-bit output, so the on-screen body is the token.
  renderer.toneMapping = THREE.NoToneMapping;
  renderer.outputColorSpace = THREE.SRGBColorSpace;

  const { width, height } = canvas.getBoundingClientRect();
  renderer.setSize(width || 800, height || 600, false);

  // ── Scene ──
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x05070D);

  // ── Camera ──
  // FOV 46°, orbit pose (project.ts orbitPosition — single source; the initial pose used to be (0, 8.5, 10.5)
  // while the orbit ran at (0, 11, 9), and the DOM labels projected with the former).
  const camera = new THREE.PerspectiveCamera(46, (width || 800) / (height || 600), 0.1, 100);
  {
    const p = orbitPosition(0);
    camera.position.set(p.x, p.y, p.z);
    camera.lookAt(0, 0, 0);
  }
  let cssW = width || 800;
  let cssH = height || 600;

  // ── Grid ──
  const gridGeo = buildGridGeometry();
  const gridMat = new THREE.LineBasicMaterial({ color: 0x26324D, opacity: 0.8, transparent: true });
  const grid = new THREE.LineSegments(gridGeo, gridMat);
  scene.add(grid);

  // ── Stars ──
  const starGeo = buildStarGeometry(3000);
  const starMat = new THREE.PointsMaterial({
    color: 0x8291AB,
    size: 0.04,
    sizeAttenuation: true,
    opacity: 0.5,
    transparent: true,
  });
  const stars = new THREE.Points(starGeo, starMat);
  scene.add(stars);

  // ── Scan plane ──
  const scanGeo = new THREE.PlaneGeometry(R_WORLD * 2 + 2, R_WORLD * 2 + 2, 1, 1);
  const scanMat = new THREE.ShaderMaterial({
    vertexShader: SCAN_VERT,
    fragmentShader: SCAN_FRAG,
    uniforms: { uSweep: { value: 0.0 } },
    transparent: true,
    depthWrite: false,
    side: THREE.DoubleSide,
    blending: THREE.AdditiveBlending,
  });
  const scanMesh = new THREE.Mesh(scanGeo, scanMat);
  scanMesh.rotation.x = -Math.PI / 2;
  scanMesh.position.y = 0.005;
  scene.add(scanMesh);

  // ── Pillar InstancedMesh (pre-allocated with 0 instances, updated on setDots) ──
  const MAX_INSTANCES = 2000;

  // Bucket 0: V0 torus (flat ring) — wider tube so it's ≥3px on screen
  const torusGeo = new THREE.TorusGeometry(0.06, 0.018, 6, 18);
  torusGeo.rotateX(Math.PI / 2); // lay flat on XZ
  const pillarsV0 = new THREE.InstancedMesh(
    torusGeo,
    new THREE.MeshBasicMaterial({ toneMapped: false }),
    MAX_INSTANCES,
  );
  pillarsV0.count = 0;
  scene.add(pillarsV0);

  // Bucket 1: V1–V3 cylinder (unit height, scaled per instance).
  // Base radius 0.04 → at typical camera distance gives ~5px screen width.
  // Per-instance X/Z scale adjusts for severity: P0 ×2.0, P1 ×1.2, P2 ×0.5.
  const cylGeo = new THREE.CylinderGeometry(0.04, 0.04, 1, 7);
  const pillarsV1 = new THREE.InstancedMesh(
    cylGeo,
    new THREE.MeshBasicMaterial({ toneMapped: false }),
    MAX_INSTANCES,
  );
  pillarsV1.count = 0;
  scene.add(pillarsV1);

  // Bucket 2: V4 cylinder (same geometry)
  const pillarsV4 = new THREE.InstancedMesh(
    cylGeo,
    new THREE.MeshBasicMaterial({ toneMapped: false }),
    MAX_INSTANCES,
  );
  pillarsV4.count = 0;
  scene.add(pillarsV4);

  // Bucket 2 cap: octahedron top
  const octGeo = new THREE.OctahedronGeometry(0.07);
  const capsMat = new THREE.MeshBasicMaterial({ toneMapped: false });
  const pillarsV4cap = new THREE.InstancedMesh(octGeo, capsMat, MAX_INSTANCES);
  pillarsV4cap.count = 0;
  scene.add(pillarsV4cap);

  // Event ID ↔ instance index maps (rebuilt on setDots)
  const dotsByBucket: [Dot3D[], Dot3D[], Dot3D[]] = [[], [], []];

  // Reusable objects for matrix math
  const _mat = new THREE.Matrix4();
  const _pos = new THREE.Vector3();
  const _scale = new THREE.Vector3();
  const _quat = new THREE.Quaternion();
  const _color = new THREE.Color();

  // ── EffectComposer (bloom) ──
  // EffectComposer defaults to HalfFloatType render targets which aren't
  // reliably supported in headless Chrome (SwiftShader) — the output is black.
  // Probe AFTER renderer creation: if the extension is absent, provide an
  // explicit UnsignedByteType render target so the scene is always visible.
  // (P0 HDR bloom won't fire with UnsignedByteType, but the scene renders.)
  const halfFloatOk =
    renderer.extensions.has('EXT_color_buffer_half_float') ||
    renderer.extensions.has('OES_texture_half_float');

  const w0 = width || 800;
  const h0 = height || 600;
  const composerRt = halfFloatOk
    ? undefined  // let EffectComposer create its default HalfFloat RT
    : new THREE.WebGLRenderTarget(w0, h0, {
        minFilter: THREE.LinearFilter,
        magFilter: THREE.LinearFilter,
        type: THREE.UnsignedByteType,
      });
  const composer = composerRt
    ? new EffectComposer(renderer, composerRt)
    : new EffectComposer(renderer);

  const renderPass = new RenderPass(scene, camera);
  composer.addPass(renderPass);

  // B1: strength 0.9 → 0.45, radius 0.4 → 0.25 — adjacent P0 halos no longer merge into one column.
  const bloomPass = new UnrealBloomPass(
    new THREE.Vector2(w0, h0),
    0.45,            // strength
    0.25,            // radius
    BLOOM_THRESHOLD, // only P0 (luminance ≈1.07) crosses it
  );
  // When running LDR render targets (no HalfFloat), bloom threshold > 1
  // can never fire — skip the pass to avoid an unnecessary blit.
  if (!halfFloatOk) bloomPass.enabled = false;
  composer.addPass(bloomPass);

  const outputPass = new OutputPass();
  composer.addPass(outputPass);

  // ── Raycaster ──
  const raycaster = new THREE.Raycaster();
  const mouse = new THREE.Vector2();
  let pickCallback: ((id: string) => void) | null = null;
  let lastPickTime = 0;
  const PICK_THROTTLE_MS = 33; // ~30Hz

  // ── Quality state ──
  let qualState = initialQualityState();
  let currentTier: QualityTier = 0;

  // ── RAF state ──
  let rafId: number | null = null;
  let lastTime = performance.now();
  let sweepAngle = 0; // radians
  let cameraAzimuth = 0; // degrees

  function updateCamera(now: number) {
    const settings = tierSettings(qualState);
    if (!settings.cameraOrbit) return;
    const phase = (now / 1000 / 120) * Math.PI * 2; // 120s period
    cameraAzimuth = 12 * Math.sin(phase);            // ±12°
    const p = orbitPosition(cameraAzimuth);
    camera.position.set(p.x, p.y, p.z);
    camera.lookAt(0, 0, 0);
  }

  function tick(now: number) {
    if (document.hidden) {
      lastTime = now;
      rafId = requestAnimationFrame(tick);
      return;
    }

    const dt = Math.min(now - lastTime, 100); // clamp huge dt (tab switch)
    lastTime = now;

    // Advance FPS quality guard
    const prevTier = qualState.tier;
    qualState = advanceQuality(qualState, dt, now);
    if (qualState.tier !== prevTier) {
      currentTier = qualState.tier;
      applyTier(qualState.tier);
      onTierChange?.(qualState.tier, tierReason(qualState.tier));
    }
    onFpsUpdate?.(Math.round(1000 / dt));

    const settings = tierSettings(qualState);
    if (settings.fallback) {
      // T4: signal caller to switch to SVG; stop rendering
      stop();
      return;
    }

    // Advance scan angle
    sweepAngle = (sweepAngle + dt * (Math.PI * 2 / 6000)) % (Math.PI * 2);
    scanMat.uniforms.uSweep.value = sweepAngle;

    updateCamera(now);

    if (settings.bloom) {
      composer.render();
    } else {
      renderer.render(scene, camera);
    }

    rafId = requestAnimationFrame(tick);
  }

  function start() {
    if (rafId !== null) return;
    lastTime = performance.now();
    rafId = requestAnimationFrame(tick);
  }

  function stop() {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
  }

  // Pause when tab hidden
  const visHandler = () => {
    if (document.hidden) stop();
    else start();
  };
  document.addEventListener('visibilitychange', visHandler);

  start();

  // ── Picking ──
  function handlePointerMove(e: PointerEvent) {
    const now = performance.now();
    if (now - lastPickTime < PICK_THROTTLE_MS) return;
    lastPickTime = now;

    const rect = canvas.getBoundingClientRect();
    mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const targets = [pillarsV0, pillarsV1, pillarsV4];
    const hits = raycaster.intersectObjects(targets);
    if (hits.length > 0) {
      const hit = hits[0];
      const mesh = hit.object as THREE.InstancedMesh;
      const idx  = hit.instanceId ?? 0;
      const bucket = mesh === pillarsV0 ? 0 : mesh === pillarsV1 ? 1 : 2;
      const dot = dotsByBucket[bucket][idx];
      if (dot) canvas.title = `${dot.title} [${dot.severity}]`;
    } else {
      canvas.title = '';
    }
  }

  function handleClick(e: MouseEvent) {
    if (!pickCallback) return;
    const rect = canvas.getBoundingClientRect();
    mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const hits = raycaster.intersectObjects([pillarsV0, pillarsV1, pillarsV4]);
    if (hits.length > 0) {
      const hit = hits[0];
      const mesh = hit.object as THREE.InstancedMesh;
      const idx  = hit.instanceId ?? 0;
      const bucket = mesh === pillarsV0 ? 0 : mesh === pillarsV1 ? 1 : 2;
      const dot = dotsByBucket[bucket][idx];
      if (dot) pickCallback(dot.eventId);
    }
  }

  canvas.addEventListener('pointermove', handlePointerMove);
  canvas.addEventListener('click', handleClick);

  // ── applyTier: update scene objects to match quality settings ──
  function applyTier(tier: QualityTier) {
    const settings = TIER_SETTINGS[tier];
    bloomPass.enabled = settings.bloom;
    renderer.setPixelRatio(Math.min(devicePixelRatio, settings.dpr));
    stars.visible = settings.stars > 0;

    // Update star count (rebuild geometry if count differs significantly)
    if (settings.stars > 0 && starGeo.attributes.position.count !== settings.stars) {
      const newGeo = buildStarGeometry(settings.stars);
      stars.geometry.dispose();
      (stars as THREE.Points).geometry = newGeo;
    }
  }

  // ── setDots: rebuild all InstancedMesh data ──
  function setDots(dots: Dot3D[]) {
    // Partition by shape bucket
    const b0: Dot3D[] = [], b1: Dot3D[] = [], b2: Dot3D[] = [];
    for (const d of dots) {
      if (d.shape === 0) b0.push(d);
      else if (d.shape === 1) b1.push(d);
      else b2.push(d);
    }
    dotsByBucket[0] = b0;
    dotsByBucket[1] = b1;
    dotsByBucket[2] = b2;

    // Severity-based XZ scale: P0 wide, P2 thin dot. P0 2.0 → 1.5 (B1: smaller glowing area per pillar).
    function sevScale(sev: string): number {
      if (sev === 'P0') return 1.5;
      if (sev === 'P1') return 1.2;
      return 0.5; // P2 thin dot
    }

    // Helper: write instance matrix for cylinder (scale y = height, translate y up by h/2)
    function setCylInstance(mesh: THREE.InstancedMesh, i: number, dot: Dot3D) {
      const h = dot.severity === 'P2' ? Math.min(dot.height, 0.5) : dot.height;
      const xzScale = sevScale(dot.severity);
      _pos.set(dot.x, h / 2, dot.z);
      _scale.set(xzScale, h, xzScale);
      _quat.identity();
      _mat.compose(_pos, _quat, _scale);
      mesh.setMatrixAt(i, _mat);
      _color.setRGB(...dot.colorHDR);
      mesh.setColorAt(i, _color);
    }

    // Bucket 0: torus rings
    for (let i = 0; i < b0.length; i++) {
      const d = b0[i];
      _pos.set(d.x, 0.02, d.z);
      _scale.setScalar(1);
      _quat.identity();
      _mat.compose(_pos, _quat, _scale);
      pillarsV0.setMatrixAt(i, _mat);
      _color.setRGB(...d.colorHDR);
      pillarsV0.setColorAt(i, _color);
    }
    pillarsV0.count = b0.length;
    pillarsV0.instanceMatrix.needsUpdate = true;
    if (pillarsV0.instanceColor) pillarsV0.instanceColor.needsUpdate = true;

    // Bucket 1: cylinders
    for (let i = 0; i < b1.length; i++) setCylInstance(pillarsV1, i, b1[i]);
    pillarsV1.count = b1.length;
    pillarsV1.instanceMatrix.needsUpdate = true;
    if (pillarsV1.instanceColor) pillarsV1.instanceColor.needsUpdate = true;

    // Bucket 2: cylinders + octahedron caps
    for (let i = 0; i < b2.length; i++) {
      setCylInstance(pillarsV4, i, b2[i]);

      // Cap at top of pillar
      const d = b2[i];
      _pos.set(d.x, d.height + 0.07, d.z);
      _scale.setScalar(1);
      _quat.identity();
      _mat.compose(_pos, _quat, _scale);
      pillarsV4cap.setMatrixAt(i, _mat);
      _color.setRGB(...d.colorHDR);
      pillarsV4cap.setColorAt(i, _color);
    }
    pillarsV4.count = b2.length;
    pillarsV4.instanceMatrix.needsUpdate = true;
    if (pillarsV4.instanceColor) pillarsV4.instanceColor.needsUpdate = true;
    pillarsV4cap.count = b2.length;
    pillarsV4cap.instanceMatrix.needsUpdate = true;
    if (pillarsV4cap.instanceColor) pillarsV4cap.instanceColor.needsUpdate = true;
  }

  // ── Public handle ──
  return {
    setDots,

    setSelected(_eventId: string | null) {
      // Future: show crosshair ring at selected event position
    },

    onPick(cb) {
      pickCallback = cb;
    },

    setTier(tier) {
      qualState = { ...qualState, tier };
      currentTier = tier;
      applyTier(tier);
    },

    resize(w, h) {
      cssW = w;
      cssH = h;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      composer.setSize(w, h);
      bloomPass.resolution.set(w, h);
    },

    dispose() {
      stop();
      document.removeEventListener('visibilitychange', visHandler);
      canvas.removeEventListener('pointermove', handlePointerMove);
      canvas.removeEventListener('click', handleClick);

      // Dispose scene objects
      [gridGeo, starGeo, scanGeo, torusGeo, cylGeo, octGeo].forEach(g => g.dispose());
      [gridMat, starMat, scanMat, capsMat].forEach(m => m.dispose());
      (pillarsV0.material as THREE.Material).dispose();
      (pillarsV1.material as THREE.Material).dispose();
      (pillarsV4.material as THREE.Material).dispose();

      composer.dispose();
      // renderer.dispose() frees all GPU-side resources (geometries, textures,
      // render targets).  We intentionally do NOT call forceContextLoss() here:
      // in React 18 StrictMode the effect is mounted → cleaned up → re-mounted,
      // and forceContextLoss() kills the canvas context permanently, making the
      // second mount fail with gl.getSupportedExtensions() === null.
      renderer.dispose();
    },

    getReason() {
      return tierReason(currentTier);
    },

    project(points) {
      return projectToScreen(camera, points, cssW, cssH);
    },

    isCameraMoving() {
      return rafId !== null && tierSettings(qualState).cameraOrbit;
    },
  };
}
