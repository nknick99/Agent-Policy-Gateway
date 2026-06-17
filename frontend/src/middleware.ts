import { NextRequest, NextResponse } from "next/server";

/**
 * Runtime API proxy middleware.
 *
 * Routes requests to the correct microservice based on path:
 *   /api/auth/*      → Auth Service
 *   /api/live-demo/* → Agent Service
 *   /api/*           → Gateway Service
 *
 * This runs at RUNTIME (not build time), so it works
 * with Docker service discovery and env vars.
 */
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (!pathname.startsWith("/api/")) {
    return NextResponse.next();
  }

  const AUTH_URL = process.env.AUTH_URL || "http://localhost:8001";
  const AGENT_URL = process.env.AGENT_URL || "http://localhost:8002";
  const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

  let target: string;

  if (pathname.startsWith("/api/auth")) {
    target = `${AUTH_URL}${pathname}`;
  } else if (pathname.startsWith("/api/live-demo")) {
    target = `${AGENT_URL}${pathname}`;
  } else {
    target = `${BACKEND_URL}${pathname}`;
  }

  // Include query string
  const url = new URL(target);
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.set(key, value);
  });

  return NextResponse.rewrite(url);
}

export const config = {
  matcher: "/api/:path*",
};
