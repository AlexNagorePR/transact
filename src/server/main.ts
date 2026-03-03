// src/server/main.ts
import portfinder from 'portfinder';
import { Issuer } from 'openid-client';
import utils from '@transitive-sdk/utils';

import { loadConfig } from '@/server/config.js';
import { createApp } from '@/server/app.js';

const log = utils.getLogger('main');
log.setLevel('debug');

const config = loadConfig();

async function initializeOIDCClient() {
  const issuer = await Issuer.discover(
    'https://cognito-idp.eu-south-2.amazonaws.com/eu-south-2_8UYEtI33x'
  );

  const oidcClient = new issuer.Client({
    client_id: config.cognitoClientId,
    client_secret: config.cognitoClientSecret,
    redirect_uris: [config.cognitoRedirectUri],
    response_types: ['code'],
  });

  log.info('OIDC client initialized', {
    issuer: issuer.issuer,
    client_id: oidcClient.metadata.client_id,
    redirect_uris: oidcClient.metadata.redirect_uris,
  });

  return oidcClient;
}

async function start() {
  const oidcClient = await initializeOIDCClient();

  const app = createApp({ oidcClient });

  const port = await portfinder.getPortPromise({
    port: config.port,
    stopPort: config.port + 1000,
  });

  app.listen(port, () => {
    console.log(`Server is listening on port ${port}`);
    console.log(`Now open: ${config.cognitoRedirectUri}`);
  });
}

start().catch((err) => {
  log.error('Failed to start server', err);
  process.exit(1);
});