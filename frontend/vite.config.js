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
        target: 'http://localhost:4401',
        ws: true,
        changeOrigin: false
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
      output: {
        // Ensure HTML files land as /auth/index.html and /auth/admin.html -> we will serve /auth/admin mapping in backend
      }
    }
  }
}))
