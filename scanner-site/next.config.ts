import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  turbopack: {
    root: __dirname,
  },

  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "https://anezjwkq4gd90u-8000.proxy.runpod.net/:path*",
      },
    ];
  },
};

export default nextConfig;
