import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';

vi.mock('@/server/portal.js', () => ({
  signPortalApiJWT: vi.fn(() => 'mock-portal-jwt'),
  fetchPortalApi: vi.fn(),
}));

import { createApp } from '@/server/app.js';
import { fetchPortalApi, signPortalApiJWT } from '@/server/portal.js';

describe('Devices', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('GET /api/devices maps portal object into array with id', async () => {
    (fetchPortalApi as any).mockResolvedValue({
      d1: { name: 'Robot 1', status: 'ok' },
      d2: { name: 'Robot 2', status: 'warn' },
    });

    const app = createApp({
      oidcClient: { authorizationUrl: () => 'http://example/redirect' } as any,
    });

    const res = await request(app).get('/api/devices').expect(200);

    expect(signPortalApiJWT).toHaveBeenCalledTimes(1);

    expect(fetchPortalApi).toHaveBeenCalledTimes(1);
    const [tokenArg, urlArg] = (fetchPortalApi as any).mock.calls[0];
    expect(tokenArg).toBe('mock-portal-jwt');
    expect(typeof urlArg).toBe('string');
    expect(urlArg).toContain('portal.transitiverobotics.com');

    expect(res.body).toEqual([
      { id: 'd1', name: 'Robot 1', status: 'ok' },
      { id: 'd2', name: 'Robot 2', status: 'warn' },
    ]);
  });

  it('GET /api/devices returns 502 on portal failure', async () => {
    (fetchPortalApi as any).mockRejectedValue(new Error('boom'));

    const app = createApp({
      oidcClient: { authorizationUrl: () => 'http://example/redirect' } as any,
    });

    const res = await request(app).get('/api/devices').expect(502);

    expect(res.body).toEqual({ error: 'Portal API request failed' });
  });
});