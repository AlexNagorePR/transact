import { describe, it, expect } from 'vitest';
import request from 'supertest';

vi.mock('@transitive-sdk/utils', async () => {
  const mod = await import('./mocks/transitive-utils');
  return { default: mod.default };
});

vi.mock('@/server/auth.js', () => {
  return {
    login: vi.fn(),
    requireLogin: (req: any, _res: any, next: any) => {
      req.session.user = { _id: 'u1' };
      next();
    },
  };
});

import { createApp } from '@/server/app.js';

describe('API', () => {
  it('GET /api/health returns ok', async () => {
    const app = createApp({ oidcClient: { authorizationUrl: () => 'http://example/redirect' } });
    const res = await request(app).get('/api/health').expect(200);
    expect(res.body.status).toBe('ok');
    expect(typeof res.body.timestamp).toBe('string');
  });
});