/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Server Components fetch the Go API server-side; no rewrites/CORS needed.
};
export default nextConfig;
