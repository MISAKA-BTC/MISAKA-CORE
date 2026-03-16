// lib/config.ts — Centralized configuration

const isDev = process.env.NODE_ENV === 'development';

/**
 * Mock is ONLY allowed in development, and must be explicitly enabled.
 * In production, mock is always disabled regardless of env.
 */
export const useMock: boolean =
  isDev && process.env.NEXT_PUBLIC_USE_MOCK === 'true';

/**
 * RPC base URL — server-side only.
 * Used by API routes to proxy requests to the MISAKA node.
 * NEVER exposed to the browser.
 */
export const rpcBaseUrl: string =
  process.env.MISAKA_RPC_URL || 'http://localhost:3001';

/**
 * Internal API base — used by client-side code.
 * Always points to our own Next.js API routes.
 */
export const internalApiBase = '/api/explorer';

export const config = {
  isDev,
  useMock,
  rpcBaseUrl,
  internalApiBase,
} as const;
