// src/server/types.d.ts
import 'express-session';
import type { AccountLike } from '@/server/auth.js';

type OidcPendingEntry = { nonce: string; ts: number };

declare module 'express-session' {
  interface SessionData {
    user?: AccountLike | null;

    oidc?: {
      pending?: Record<string, OidcPendingEntry>;
    } | null;
  }
}