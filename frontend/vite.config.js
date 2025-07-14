import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  base: '/auth/',
  server: {
    port: 3000,
    proxy: {
      '/auth/': {
        target: 'http://localhost:8000',
        ws: true,
        changeOrigin: false
      }
    }
  },
  build: {
    outDir: '../passkeyauth/frontend-static',
    emptyOutDir: true,
    assetsDir: 'assets'
  }
})
