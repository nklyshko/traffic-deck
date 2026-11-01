import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: '../dist', emptyOutDir: true, chunkSizeWarningLimit: 1500 },
  // The SPA is same-origin with the API, and the bridge never sends CORS headers.
  server: { proxy: { '/api': 'http://127.0.0.1:18890' } },
})
