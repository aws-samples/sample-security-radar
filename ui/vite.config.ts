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

export default defineConfig({
  plugins: [react(), mockData()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  build: {
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
