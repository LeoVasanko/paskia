import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import vue from '@vitejs/plugin-vue'
import { existsSync, renameSync, mkdirSync } from 'node:fs'
import sirv from 'sirv'
import fastapiVue from './vite-plugin-fastapi.js'

// Auth host mode: when set, clients accessing the auth host get /auth/ at / and /auth/admin/ at /admin/
const authHost = process.env.PASKIA_AUTH_HOST

export default defineConfig(({ command }) => ({
  appType: 'mpa',
  publicDir: 'public',
  plugins: [
    fastapiVue({ paths: [
      "/auth/api",
      "/auth/ws",
      // Passphrase links: /auth/word1.word2.word3.word4.word5
      "^/auth/[a-z]+\\.[a-z]+\\.[a-z]+\\.[a-z]+\\.[a-z]+$",
      // Passphrase links: /word1.word2.word3.word4.word5
      "^/[a-z]+\\.[a-z]+\\.[a-z]+\\.[a-z]+\\.[a-z]+$",
    ] }),
    vue(),
    // Auth host routing: rewrite paths when accessing dedicated auth host
    // Must run before serve-examples to handle / correctly
    authHost && {
      name: 'auth-host-routing',
      configureServer(server) {
        server.middlewares.use((req, _res, next) => {
          const host = req.headers.host?.split(':')[0]
          // Check if request is coming to the auth host
          if (host === authHost) {
            // Only rewrite specific paths that should map to /auth/*
            // Rewrite / and /index.html to /auth/
            if (req.url === '/' || req.url === '/index.html') {
              req.url = '/auth/'
            }
            // Rewrite /admin/* to /auth/admin/*
            else if (req.url.startsWith('/admin/') || req.url === '/admin') {
              req.url = '/auth' + req.url
            }
            // Everything else (Vite paths, passphrase links, etc.) passes through unchanged
          }
          next()
        })
      }
    },
    {
      name: 'serve-examples',
      configureServer(server) {
        const examplesDir = resolve(__dirname, '../examples')
        const serve = sirv(examplesDir, { dev: true })
        server.middlewares.use((req, _res, next) => {
          // Skip redirect to examples on auth host (handled by auth-host-routing)
          const host = req.headers.host?.split(':')[0]
          if (authHost && host === authHost) {
            next()
            return
          }
          if (req.url === '/' || req.url === '/index.html') req.url = '/examples/'
          next()
        })
        server.middlewares.use('/examples', serve)
      }
    },
    {
      name: 'move-html-files',
      closeBundle() {
        if (command !== 'build') return

        const outDir = resolve(__dirname, '../paskia/frontend-build')
        const moves = [
          { from: 'auth.html', to: 'auth/index.html' },
          { from: 'admin.html', to: 'admin/index.html' },
          { from: 'restricted.html', to: 'restricted/index.html' },
          { from: 'reset.html', to: 'reset/index.html' },
          { from: 'forward.html', to: 'forward/index.html' }
        ]

        for (const { from, to } of moves) {
          const fromPath = resolve(outDir, from)
          const toPath = resolve(outDir, to)
          if (existsSync(fromPath)) {
            mkdirSync(resolve(outDir, to.split('/')[0]), { recursive: true })
            renameSync(fromPath, toPath)
          }
        }
      }
    }
  ].filter(Boolean),
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    }
  },
  base: '/',
  server: {
    port: 4403,
    allowedHosts: true,
    fs: {
      allow: ['..']
    }
  },
  build: {
    outDir: '../paskia/frontend-build',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        auth: resolve(__dirname, 'auth/index.html'),
        admin: resolve(__dirname, 'auth/admin/index.html'),
        restricted: resolve(__dirname, 'auth/restricted/index.html'),
        reset: resolve(__dirname, 'int/reset/index.html'),
        forward: resolve(__dirname, 'int/forward/index.html'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          return 'auth/assets/[name]-[hash].js'
        },
        chunkFileNames: (chunkInfo) => {
          return 'auth/assets/[name]-[hash].js'
        },
        assetFileNames: (assetInfo) => {
          return 'auth/assets/[name]-[hash][extname]'
        }
      }
    }
  }
}))
