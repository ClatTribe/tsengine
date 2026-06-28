/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Server Components fetch the Go API server-side; no rewrites/CORS needed.
  // Standalone output → a self-contained server.js + minimal node_modules so the
  // production Docker image (frontend/Dockerfile) stays small.
  output: "standalone",
  // Merged-away marketing pages → permanent (308) redirects to their canonical page, so any external
  // links / search-index entries consolidate onto one page instead of two near-duplicates competing.
  //   /identity      was a near-duplicate of the richer SSPM page → /saas-posture
  //   /supply-chain  was a subset of the code-security "Supply-chain risk" coverage → /code-security
  async redirects() {
    return [
      { source: "/identity", destination: "/saas-posture", permanent: true },
      { source: "/supply-chain", destination: "/code-security", permanent: true },
    ];
  },
};
export default nextConfig;
