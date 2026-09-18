import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard calls /v1/... on its own origin and Vite forwards it to the backend, so the
// browser treats the API as same-site and sends the session cookie (GitHub connection).
const API_TARGET = process.env.CHAINSHIELD_API_TARGET || "http://127.0.0.1:8000";
const proxy = { "/v1": { target: API_TARGET } };

export default defineConfig({
  plugins: [react()],
  server: { proxy },
  preview: { proxy },
});
