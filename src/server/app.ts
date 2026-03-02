// src/server/app.ts
import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import path from 'path';

import utils from '@transitive-sdk/utils';
import { COOKIE_NAME } from '@/common/constants.js';
import { login, requireLogin } from '@/server/auth.js';
import { generators } from 'openid-client';

dotenvExpand.expand(dotenv.config({ path: './.env' }));

const log = utils.getLogger('app');

const FileStore = FileStoreFactory(session);

export function createApp(deps?: { oidcClient?: any }) {
  const oidcClient = deps?.oidcClient;

  const app = express();
  app.use(express.json());

  const varDir = process.env.TRANSACT_VAR_DIR || '/tmp/transact';
  const sessionSecret = process.env.TRANSACT_SESSION_SECRET || 'test-secret';
  const jwtSecret = process.env.JWT_SECRET || 'test-jwt-secret';
  const transitiveUser = process.env.TRANSITIVE_USER || 'test-transitive-user';

  const fileStoreOptions = {
    path: path.join(varDir, 'sessions'),
  };

  app.use(session({
    store: new FileStore(fileStoreOptions),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3 * 24 * 60 * 60 * 1000 },
  }));

  function signPortalApiJWT() {
    return jwt.sign({ userId: 'phenomenonrobotics', api: 1 }, jwtSecret);
  }

  async function fetchPortalApi(token: string, url: string, { timeoutMs = 7000 } = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`Portal API error ${response.status}: ${text.slice(0, 200)}`);
      }

      return await response.json();
    } catch (err: any) {
      if (err?.name === 'AbortError') throw new Error('Portal API timeout');
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  // --- routes (copiadas del main) ---

  app.get('/auth/login', (req, res) => {
    if (!oidcClient) return res.status(500).send('OIDC client not initialized');

    const nonce = generators.nonce();
    const state = generators.state();

    req.session.oidc ||= {};
    req.session.oidc.pending ||= {};
    req.session.oidc.pending[state] = { nonce, ts: Date.now() };

    const authUrl = oidcClient.authorizationUrl({ scope: 'email openid phone', state, nonce });
    res.redirect(authUrl);
  });

  app.post('/api/getJWT', requireLogin, (req, res) => {
    req.body.capability ||= 'ignore';

    if (req.body.capability.endsWith('_robot-agent')) {
      const msg = 'We do not sign agent tokens. But capability tokens provide read-access.';
      log.warn(msg);
      return res.status(400).send(msg);
    }

    const token = jwt.sign({
      ...req.body,
      id: transitiveUser,
      userId: req.session.user._id,
      validity: 86400,
    }, jwtSecret);

    res.json({ token });
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // (el resto de rutas las testearíamos después)
  return app;
}