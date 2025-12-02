import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import vue from '@vitejs/plugin-vue'
import { existsSync, renameSync, mkdirSync } from 'node:fs'

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
      // Only proxy these two specific backend API paths
      '/auth/api': {
        target: 'http://localhost:4402'
      },
      '/auth/ws': {
        target: 'http://localhost:4402',
        ws: true
      }
    }
  },
  preview: {
    port: 4403
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
