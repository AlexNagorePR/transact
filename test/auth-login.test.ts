import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';

vi.mock('@/server/auth.js', () => ({
  login: vi.fn(),
  requireLogin: (_req: any, _res: any, next: any) => next(),

}));

import { createApp } from '@/server/app.js';

describe('Auth', () => {
  it('GET /auth/login redirects and creates pending oidc state', async () => {
    const oidcClient = {
      authorizationUrl: ({ state, nonce }: any) =>
        `http://example/authorize?state=${state}&nonce=${nonce}`,
    };

    const app = createApp({ oidcClient });

    const res = await request(app).get('/auth/login').expect(302);
    expect(res.headers.location).toMatch(/^http:\/\/example\/authorize\?/);
  });
});