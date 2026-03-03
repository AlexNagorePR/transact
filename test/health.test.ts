import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';

import { createApp } from '@/server/app.js';

describe('API', () => {
  it('GET /api/health returns ok', async () => {
    const app = createApp({
      oidcClient: { authorizationUrl: () => 'http://example/redirect' } as any,
    });
    
    const res = await request(app).get('/api/health').expect(200);
    expect(res.body.status).toBe('ok');
    expect(typeof res.body.timestamp).toBe('string');
  });
});