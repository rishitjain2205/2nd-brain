/** @type {import('next').NextConfig} */
const nextConfig = {
  // Force rebuild
  generateBuildId: async () => {
    return 'catalyst-build-' + Date.now()
  }
}

module.exports = nextConfig
