/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'

// Mock site-data lives in mock-data/ and is served at /data ONLY by the dev/preview servers.
// It is deliberately outside public/ so `vite build` can never ship fabricated events to production.
function mockData(): Plugin {
  const root = path.resolve(__dirname, 'mock-data')
  const serve = (req: { url?: string }, res: any, next: () => void) => {
    const url = (req.url ?? '').split('?')[0]
    // .diff/.patch = captured Continuum / Security Agent patches (response.patches[].path), served as text
    const m = url.match(/\/data\/(.+\.(json|diff|patch))$/)
    const file = m ? path.resolve(root, 'data', m[1]) : ''
    if (!m || !file.startsWith(root + path.sep) || !fs.existsSync(file)) return next()
    res.setHeader('Content-Type', m[2] === 'json' ? 'application/json' : 'text/plain; charset=utf-8')
    res.end(fs.readFileSync(file))
  }
  return {
    name: 'mock-site-data',
    configureServer: (s) => { s.middlewares.use(serve) },
    configurePreviewServer: (s) => { s.middlewares.use(serve) },
  }
}

// R3.3: one id per build — compiled into the page and written to version.json (uploaded no-cache by deploy-ui.sh); a
// page whose id differs from the deployed version.json offers a reload instead of running old code for days.
const BUILD_ID = process.env.RADAR_BUILD || `dev-${Date.now()}`
function versionFile(): Plugin {
  return {
    name: 'radar-version',
    generateBundle() { this.emitFile({ type: 'asset', fileName: 'version.json', source: JSON.stringify({ build: BUILD_ID }) }) },
  }
}

export default defineConfig({
  define: { __BUILD_ID__: JSON.stringify(BUILD_ID) },
  plugins: [react(), mockData(), versionFile()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  build: {
    // R3.6: never inline fonts. Vite inlines assets under 4 KB as base64, and most @fontsource unicode-range
    // subsets are that small, so 113 KB of the 128 KB render-blocking CSS (gzip) was fonts every page carried,
    // whether or not it used them. As files they load only when a glyph in their range is drawn.
    assetsInlineLimit: (file: string) => (/\.(woff2?|ttf|otf)$/.test(file) ? false : undefined),
    rollupOptions: {
      output: {
        manualChunks(id) {
          // three.js + examples → own lazy chunk (≈138 KB gzip)
          if (id.includes('node_modules/three')) {
            return 'three';
          }
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'node',
    alias: {
      '@/': path.resolve(__dirname, 'src') + '/',
    },
  },
})
