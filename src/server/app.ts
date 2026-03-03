// src/server/app.ts
import express from 'express';
import jwt from 'jsonwebtoken';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import path from 'path';

import utils from '@transitive-sdk/utils';
import { COOKIE_NAME } from '@/common/constants.js';
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

  app.use(
    session({
      store: new FileStore({ path: path.join(config.varDir, 'sessions') }),
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: { maxAge: 3 * 24 * 60 * 60 * 1000 },
    })
  );

  // --- routes ---

  // Basic auth status (compatible con tu front actual)
  app.get('/api/user', (req: any, res) => {
    const user = req.session?.user;
    return res.json({
      isAuthenticated: Boolean(user && user._id),
      userInfo: user || null,
    });
  });

  // Login with OIDC provider (Cognito)
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

      delete req.session.oidc!.pending![returnedState];

      const tokenSet = await oidcClient.callback(
        config.cognitoRedirectUri,
        params,
        { nonce: pending.nonce, state: returnedState }
      );

      const claims = tokenSet.claims();
      const groups: string[] = (claims['cognito:groups'] as string[]) || [];

      if (!groups.includes('allowed')) {
        req.session.user = null;
        res.clearCookie(COOKIE_NAME);
        return res.status(403).send('User not allowed');
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

      return login(req, res, { account: accountLike, redirect: '/dashboard/devices' });
    } catch (err: any) {
      if (res.headersSent) {
        log.error('Callback error after headers sent', err);
        return;
      }
      log.error('Callback error', err);
      return res.status(500).send(`Callback error: ${err?.message || err}`);
    }
  });

  app.get('/auth/logout', (req: any, res) => {
    req.session.user = null;
    req.session.oidc = null;

    req.session.save(() => {
      req.session.regenerate(() => {
        res.clearCookie(COOKIE_NAME);

        const url =
          `https://${config.cognitoDomain}/logout` +
          `?client_id=${encodeURIComponent(config.cognitoClientId)}` +
          `&logout_uri=${encodeURIComponent(config.cognitoLogoutUri)}`;

        return res.redirect(url);
      });
    });
  });

  // Refresh session cookie
  app.get('/api/refresh', (req: any, res) => {
    const fail = (error: string) =>
      res.clearCookie(COOKIE_NAME).status(401).json({ error, ok: false });

    const user = req.session?.user;
    if (!user || !user._id) {
      log.info('no session user');
      return fail('no session');
    }

    return login(req, res, { account: user, redirect: false });
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

  app.get('/api/devices', async (_req, res) => {
    try {
      const token = signPortalApiJWT({
        jwtSecret: config.jwtSecret,
        transitiveUser: config.transitiveUser,
        validitySeconds: 60,
      });

      const url =
        'https://portal.transitiverobotics.com/@transitive-robotics/_robot-agent/api/v1/info/';

      const data = await fetchPortalApi<any>(token, url, { timeoutMs: 7000 });

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

  // Protege dashboard
  app.use('/dashboard/', requireLogin);

  return app;
}