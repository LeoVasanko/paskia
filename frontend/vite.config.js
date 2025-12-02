import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import { resolve } from 'node:path'
import vue from '@vitejs/plugin-vue'
import { readFileSync, existsSync, statSync } from 'node:fs'

export default defineConfig(({ command }) => ({
  appType: 'mpa',
  plugins: [
    vue(),
    {
      name: 'serve-examples',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const url = req.url?.split('?')[0]
          if (url === '/examples') return res.writeHead(301, { Location: '/examples/' }).end()
          if (url?.startsWith('/examples/')) {
            const file = resolve(__dirname, '../examples', url === '/examples/' ? 'index.html' : url.slice(10))
            if (existsSync(file) && statSync(file).isFile()) {
              res.setHeader('Content-Type', { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript' }[file.slice(file.lastIndexOf('.'))] || 'text/plain')
              return res.end(readFileSync(file))
            }
            return res.writeHead(404).end()
          }
          next()
        })
      }
    }
  ],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) }
  },
  base: command === 'build' ? '/auth/' : '/',
  server: {
    port: 4403,
    proxy: {
      '/auth/': {
        target: 'http://localhost:4402',
        ws: true,
        bypass: (req) => {
          const url = req.url?.split('?')[0]
          if (url?.startsWith('/auth/assets/')) return url.slice(5)

          const routes = { '': '/', host: '/host/index.html', admin: '/admin/', restricted: '/restricted/index.html', 'restricted-api': '/restricted-api/index.html' }
          for (const [path, target] of Object.entries(routes)) {
            if ([`/auth/${path}`, `/auth/${path}/`, `/${path}`, `/${path}/`].includes(url)) return target
          }

          if (/^\/auth\/([a-z]+\.){4}[a-z]+\/?$|^\/([a-z]+\.){4}[a-z]+\/?$/.test(url)) return '/reset/index.html'
        }
      }
    }
  },
  build: {
    outDir: '../passkey/frontend-build',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        admin: resolve(__dirname, 'admin/index.html'),
        reset: resolve(__dirname, 'reset/index.html'),
        restricted: resolve(__dirname, 'restricted/index.html'),
        'restricted-api': resolve(__dirname, 'restricted-api/index.html'),
        host: resolve(__dirname, 'host/index.html')
      }
    }
  }
}))
