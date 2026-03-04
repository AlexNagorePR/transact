// src/server/app.ts
import express from 'express';
import jwt from 'jsonwebtoken';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import path from 'path';
import fs from 'node:fs';

import utils from '@transitive-sdk/utils';
import { loadConfig } from '@/server/config.js';
import { login, requireLogin } from '@/server/auth.js';
import { signPortalApiJWT, fetchPortalApi } from '@/server/portal.js';
import { generators } from 'openid-client';

const log = utils.getLogger('app');
const FileStore = FileStoreFactory(session);

type OidcClientLike = {
  authorizationUrl(args: any): string;
  callbackParams(req: any): any;
  callback(redirectUri: string, params: any, checks: any): Promise<{ claims(): any }>;
};

export function createApp(deps: { oidcClient?: OidcClientLike } = {}) {
  const config = loadConfig();
  const { oidcClient } = deps;

  const app = express();
  app.use(express.json());

  const isProd = config.nodeEnv === 'production';

  const sessionsDir = path.join(config.varDir, 'sessions');
  fs.mkdirSync(sessionsDir, { recursive: true });

  const fileStore = new FileStore({
    path: sessionsDir,
    retries: 0,
  });

  app.use(
    session({
      name: 'connect.sid',
      store: fileStore,
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      proxy: isProd,
      cookie:{
        maxAge: 3 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: isProd ? 'lax' : 'lax',
        secure: isProd,
      },
    })
  );

  // Basic auth status
  app.get('/api/user', (req: any, res) => {
    const user = req.session?.user;
    return res.json({
      isAuthenticated: Boolean(user && user._id),
      userInfo: user || null,
    });
  });

  // OIDC login
  app.get('/auth/login', (req: any, res) => {
    if (!oidcClient) return res.status(500).send('OIDC client not initialized');

    const nonce = generators.nonce();
    const state = generators.state();

    req.session.oidc ||= {};
    req.session.oidc.pending ||= {};
    req.session.oidc.pending[state] = { nonce, ts: Date.now() };

    const authUrl = oidcClient.authorizationUrl({
      scope: 'email openid phone',
      state,
      nonce,
    });

    return res.redirect(authUrl);
  });

  // OIDC callback
  app.get('/auth/callback', async (req: any, res) => {
    try {
      if (!oidcClient) return res.status(500).send('OIDC client not initialized');

      if (req.query?.error) {
        log.error('OIDC error on callback', req.query);
        return res.status(400).send(`OIDC error: ${req.query.error}`);
      }

      const params = oidcClient.callbackParams(req);
      const returnedState = params.state;

      const pending = req.session?.oidc?.pending?.[returnedState];
      if (!pending) {
        log.warn('OIDC callback with unknown/expired state', { returnedState });
        return res.status(400).send('Invalid/expired state. Please try again.');
      }

      const OIDC_STATE_TTL_MS = 10 * 60 * 1000;
      if (Date.now() - pending.ts > OIDC_STATE_TTL_MS) {
        if (req.session?.oidc?.pending) delete req.session.oidc.pending[returnedState];
        return res.status(400).send('Login expired. Please try again.');
      }

      if (req.session?.oidc?.pending) delete req.session.oidc!.pending![returnedState];

      const tokenSet = await oidcClient.callback(
        config.cognitoRedirectUri,
        params,
        { nonce: pending.nonce, state: returnedState }
      );

      const claims = tokenSet.claims();
      const groups: string[] = (claims['cognito:groups'] as string[]) || [];

      if (!groups.includes('allowed')) {
        return req.session.destroy(() => {
          res.clearCookie('connect.sid');
          return res.redirect(`${config.postLoginRedirectUrl}?error=not_allowed`)
        });
      }

      const email = claims.email as string | undefined;
      const userId = email || (claims.sub as string);

      const accountLike = {
        _id: userId,
        email: email || '',
        admin: groups.includes('admin'),
        verified: true,
        created: new Date(),
      };

      return login(req, res, { account: accountLike, redirect: config.postLoginRedirectUrl });
    } catch (err: any) {
      if (res.headersSent) {
        log.error('Callback error after headers sent', err);
        return;
      }
      log.error('Callback error', err);
      return res.status(500).send(`Callback error: ${err?.message || err}`);
    }
  });

  // Logout
  app.get('/auth/logout', (req: any, res) => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      const url =
        `https://${config.cognitoDomain}/logout` +
        `?client_id=${encodeURIComponent(config.cognitoClientId)}` +
        `&logout_uri=${encodeURIComponent(config.cognitoLogoutUri)}`;
      return res.redirect(url);
    });
  });

  // Get a JWT token for the current user
  app.post('/api/getJWT', requireLogin, (req: any, res: any) => {
    req.body.capability ||= 'ignore';

    if (req.body.capability.endsWith('_robot-agent')) {
      const msg = 'We do not sign agent tokens. But capability tokens provide read-access.';
      log.warn(msg);
      return res.status(400).send(msg);
    }

    const token = jwt.sign(
      {
        ...req.body,
        id: config.transitiveUser,
        userId: req.session.user!._id,
        validity: 86400,
      },
      config.jwtSecret
    );

    return res.json({ token });
  });

  app.get('/api/health', (_req, res) => {
    return res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  app.get('/api/devices', requireLogin, async (_req, res) => {
    try {
      const token = signPortalApiJWT({
        jwtSecret: config.jwtSecret,
        transitiveUser: config.transitiveUser,
        validitySeconds: 60,
      });

      const url =
        'https://portal.transitiverobotics.com/@transitive-robotics/_robot-agent/api/v1/running/';
      const data = await fetchPortalApi<any>(token, url, { timeoutMs: 7000 });

      console.log('Portal API response', { url, data });

      return res.json(
        Object.entries(data || {}).map(([id, value]) => ({
          id,
          ...(value as any),
        }))
      );
    } catch (err: any) {
      log.error('Portal API request failed', err);
      return res.status(502).json({ error: 'Portal API request failed' });
    }
  });

  app.get('/', (_req, res) => {
    res.json({
      service: 'transact-backend',
      status: 'running',
      timestamp: new Date().toISOString(),
    });
  });

  return app;
}