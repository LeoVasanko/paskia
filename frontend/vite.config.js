import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import vue from '@vitejs/plugin-vue'
import { readFileSync, existsSync, statSync, renameSync, mkdirSync } from 'node:fs'

export default defineConfig(({ command }) => ({
  appType: 'mpa',
  publicDir: 'public',
  plugins: [
    vue(),
    {
      name: 'move-html-files',
      closeBundle() {
        if (command !== 'build') return

        const outDir = resolve(__dirname, '../passkey/frontend-build')
        const moves = [
          { from: 'auth.html', to: 'auth/index.html' },
          { from: 'admin.html', to: 'admin/index.html' },
          { from: 'restricted.html', to: 'restricted/index.html' },
          { from: 'host.html', to: 'host/index.html' },
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
  ],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  base: '/',
  server: {
    port: 4403,
    fs: {
      allow: ['..']
    },
    proxy: {
      '/': {
        target: 'http://localhost:4402',
        bypass: (req) => {
          const url = req.url?.split('?')[0]

          // Root and examples served by Vite
          if (url === '/' || url === '') return '/../examples/index.html'
          if (url === '/examples' || url === '/examples/') return '/../examples/index.html'
          if (url?.startsWith('/examples/')) return `/../examples${url.slice(9)}`

          // Let other proxies handle their routes
          return null
        }
      },
      '/auth/': {
        target: 'http://localhost:4402',
        ws: true,
        bypass: (req) => {
          const url = req.url?.split('?')[0]
          // Backend handles /auth/api/* and /auth/ws/* (no bypass - let proxy handle)
          if (url?.startsWith('/auth/api/') || url?.startsWith('/auth/ws/')) return null
          // Vite serves all assets
          if (url?.startsWith('/auth/assets/')) return url
          // Vite serves main app routes
          if (url === '/auth' || url === '/auth/') return '/auth/index.html'
          if (url === '/auth/admin' || url === '/auth/admin/') return '/auth/admin/index.html'
          if (url === '/auth/restricted' || url === '/auth/restricted/') return '/auth/restricted/index.html'
          if (url?.startsWith('/auth/') && /^\/auth\/([a-z]+\.)+[a-z]+\/?/.test(url)) return "/int/reset/index.html"
          // Vite serves source files (for HMR and dev)
          if (url?.startsWith('/auth/') && /\.(js|vue|css|ts|jsx|tsx|json)$/.test(url)) return url
          return null
        }
      },
      '/int/': {
        target: 'http://localhost:4402',
        bypass: (req) => {
          const url = req.url?.split('?')[0]
          // Vite serves /int/ apps
          if (url === '/int/host' || url === '/int/host/') return '/int/host/index.html'
          if (url === '/int/reset' || url === '/int/reset/' || url?.match(/^\/int\/reset\/([a-z]+\.){4}[a-z]+\/?$/)) return '/int/reset/index.html'
          if (url === '/int/forward' || url === '/int/forward/') return '/int/forward/index.html'
          if (url?.startsWith('/int/')) return url
          return null
        }
      }
    }
  },
  build: {
    outDir: '../passkey/frontend-build',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        auth: resolve(__dirname, 'auth/index.html'),
        admin: resolve(__dirname, 'auth/admin/index.html'),
        restricted: resolve(__dirname, 'auth/restricted/index.html'),
        host: resolve(__dirname, 'int/host/index.html'),
        reset: resolve(__dirname, 'int/reset/index.html'),
        forward: resolve(__dirname, 'int/forward/index.html')
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
