import express from 'express';
import ViteExpress from 'vite-express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import path from 'path';
import portfinder from 'portfinder';

import utils from '@transitive-sdk/utils';
import { COOKIE_NAME } from '@/common/constants.js';
import { login, requireLogin } from '@/server/auth.js';

import { Issuer, generators } from 'openid-client';

dotenvExpand.expand(dotenv.config({path: './.env'}))

const log = utils.getLogger('main');
log.setLevel('debug');

const FileStore = FileStoreFactory(session);

const basePort = process.env.PORT || 3000;

const app = express();
app.use(express.json());

const fileStoreOptions = {
  path: path.join(process.env.TRANSACT_VAR_DIR + '/sessions'),
};

// Set up session middleware
app.use(session({
  store: new FileStore(fileStoreOptions),
  secret: process.env.TRANSACT_SESSION_SECRET, // used to sign the session ID cookie
  resave: false,
  saveUninitialized: true,
  cookie: {maxAge: 3 * 24 * 60 * 60 * 1000},
}));


let oidcClient;

async function initializeOIDCClient() {
   const issuer = await Issuer.discover(
    'https://cognito-idp.eu-south-2.amazonaws.com/eu-south-2_grNLqDobH'
  );
  
  oidcClient = new issuer.Client({
    client_id: '647r0k8aqekluhfcqksrf1bhsk',
    client_secret: process.env.COGNITO_CLIENT_SECRET,
    redirect_uris: ['http://localhost:3000/auth/callback'],
    response_types: ['code']
  });

  log.info('OIDC client initialized', {
    issuer: issuer.issuer,
    client_id: oidcClient.metadata.client_id,
    redirect_uris: oidcClient.metadata.redirect_uris,
  });
};

initializeOIDCClient().catch(err => {
  log.error('Failed to initialize OIDC client', err);
});

// Example of a simple route
app.get('/hello', (_, res) => {
  res.send('Hello Vite + React + TypeScript!');
});

// Login with OIDC provider (Cognito)
app.get('/auth/login', (req, res) => {
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

  res.redirect(authUrl);
});

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

    delete req.session.oidc.pending[returnedState];

    const tokenSet = await oidcClient.callback(
      'http://localhost:3000/auth/callback',
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

  } catch (err) {
    if (res.headersSent) {
      log.error('Callback error after headers sent', err);
      return;
    }
    log.error('Callback error', err);
    return res.status(500).send(`Callback error: ${err?.message || err}`);
  }
});

// Logout the user
app.post('/api/logout', async (req, res) => {
  log.debug('/api/logout', req.session.user);

  req.session.user = null;
  req.session.oidc = null;

  req.session.save((saveErr) => {
    if (saveErr) {
      log.error('failed to save session', saveErr);
      return res.status(500).json({ ok: false, error: 'Failed to save session' });
    }

    req.session.regenerate((regenErr) => {
      if (regenErr) {
        log.error('failed to regenerate session', regenErr);
        return res.status(500).json({ ok: false, error: 'Failed to regenerate session' });
      }
      res.clearCookie(COOKIE_NAME).json({status: 'ok'});
    });
  })
});

app.get('/auth/logout', (req, res) => {
  req.session.user = null;
  req.session.oidc = null;

  req.session.save(() => {
    req.session.regenerate(() => {
      res.clearCookie(COOKIE_NAME);

      const cognitoDomain = process.env.COGNITO_DOMAIN;
      const clientId = '647r0k8aqekluhfcqksrf1bhsk';
      const logoutUrl = 'http://localhost:3000/';

      const url =
        `https://${cognitoDomain}/logout` +
        `?client_id=${encodeURIComponent(clientId)}` +
        `&logout_uri=${encodeURIComponent(logoutUrl)}`;

      return res.redirect(url);
    });
  });
});

// Refresh the session cookie
app.get('/api/refresh', (req, res) => {
  const fail = (error) =>
    res.clearCookie(COOKIE_NAME).status(401).json({error, ok: false});

  const user = req.session?.user;

  if (!user || !user._id) {
    log.info('no session user');
    return fail('no session');
  }
  
  return login(req, res, { account: user, redirect: false });
});

// Get a JWT token for the current user
app.post('/api/getJWT', requireLogin, (req, res) => {
  console.log('getJWT', req.body, req.session.user._id);
  req.body.capability ||= 'ignore';

  if (req.body.capability.endsWith('_robot-agent')) {
    const msg =
      'We do not sign agent tokens. But capability tokens provide read-access.';
    log.warn(msg);
    return res.status(400).send(msg);
  }

  const token = jwt.sign({
      ...req.body,
      id: process.env.VITE_TRANSITIVE_USER, // Transitive portal user id
      userId: req.session.user._id,  // user name on dashboard
      validity: 86400,   // number of seconds
    }, process.env.JWT_SECRET);
  res.json({token});
});

app.use('/dashboard/', requireLogin);

const start = async () => {

  const port = await portfinder.getPortPromise({
    port: basePort,           // minimum port
    stopPort: basePort + 1000 // maximum port
  });

  ViteExpress.listen(app, port, () => {
    console.log(`Server is listening on port ${port}`);
    console.log(`Now open: http://localhost:${port}/auth/login`);
  });
}

start();