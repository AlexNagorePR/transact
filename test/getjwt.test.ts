import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';

vi.mock('@/server/auth.js', () => ({
  login: vi.fn(),
  requireLogin: (req: any, _res: any, next: any) => {
    req.session ||= {};
    req.session.user = { _id: 'u1' };
    next();
  },
}));

import { createApp } from '@/server/app.js';

describe('JWT', () => {
  it('POST /api/getJWT rejects *_robot-agent', async () => {
    const app = createApp({
      oidcClient: { authorizationUrl: () => 'http://example/redirect' } as any,
    });

    const res = await request(app)
      .post('/api/getJWT')
      .send({ capability: 'abc_robot-agent' })
      .expect(400);

    expect(res.text).toMatch(/do not sign agent tokens/i);
  });

  it('POST /api/getJWT returns token for normal capability', async () => {
    process.env.JWT_SECRET = 'secret';
    process.env.TRANSITIVE_USER = 'transitiveUser';

    const app = createApp({
      oidcClient: { authorizationUrl: () => 'http://example/redirect' } as any,
    });

    const res = await request(app)
      .post('/api/getJWT')
      .send({ capability: 'camera', foo: 1 })
      .expect(200);

    expect(res.body.token).toBeTruthy();
    expect(typeof res.body.token).toBe('string');
  });
});