import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  root: 'web',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    rollupOptions: { input: { main: resolve('web/index.html'), history: resolve('web/history.html') } },
  },
});
