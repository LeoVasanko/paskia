import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => ({
  plugins: [
    vue(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  // Use absolute paths at dev, deploy under /auth/
  base: command === 'build' ? '/auth/' : '/',
  server: {
    port: 4403,
    proxy: {
      '/auth/': {
        target: 'http://localhost:4402',
        ws: true,
        changeOrigin: false,
        // We proxy API + WS under /auth/, but want Vite to serve the SPA entrypoints
        // and static assets so that HMR works. Bypass tells http-proxy to skip
        // proxying when we return a (possibly rewritten) local path.
        bypass(req) {
          const url = req.url || ''
          // Paths to serve locally (not proxied):
          //  - /auth/ (root SPA)
          //  - /auth/assets/* (dev static assets)
          //  - /auth/admin/* (admin SPA)
          // NOTE: Keep /auth/ws/* and all other API endpoints proxied.
          if (url === '/auth/' || url === '/auth') {
            return '/'
          }
          if (url.startsWith('/auth/assets')) {
            // Map /auth/assets/* -> /assets/*
            return url.replace(/^\/auth/, '')
          }
          if (url === '/auth/admin' || url === '/auth/admin/') {
            return '/admin/'
          }
          if (url.startsWith('/auth/admin/')) {
            // Map /auth/admin/* -> /admin/*
            return url.replace(/^\/auth\/admin/, '/admin')
          }
          // Otherwise proxy (API, ws, etc.)
        }
      }
    }
  },
  build: {
    outDir: '../passkey/frontend-build',
    emptyOutDir: true,
    assetsDir: 'assets',
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        admin: resolve(__dirname, 'admin/index.html')
      },
      output: {}
    }
  }
}))
