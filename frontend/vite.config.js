import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Dev-only: forward API calls to the local backend (no CORS changes needed).
    // NOTE: port 8000 is unusable on this machine (Windows-excluded range
    // 7951-8050); the backend runs on 127.0.0.1:8100 instead.
    proxy: {
      '/api': 'http://127.0.0.1:8100',
      '/health': 'http://127.0.0.1:8100',
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
  },
})
