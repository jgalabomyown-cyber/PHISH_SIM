export default defineConfig({
  server: {
    proxy: {
      "/ws": { target: "ws://localhost:8000", ws: true },
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/auth": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});