/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  images: {
    domains: ['IP_DE_POCKETBASE'],
    remotePatterns: [
      {
        protocol: 'http',
        hostname: 'IP_DE_POCKETBASE',
        port: '8080',
        pathname: '/api/files/**',
      },
    ],
  },
}

module.exports = nextConfig
