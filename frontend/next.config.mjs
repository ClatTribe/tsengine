/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Server Components fetch the Go API server-side; no rewrites/CORS needed.
  // Standalone output → a self-contained server.js + minimal node_modules so the
  // production Docker image (frontend/Dockerfile) stays small.
  output: "standalone",
};
export default nextConfig;
