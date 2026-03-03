// test/mocks/setup.ts
import { vi } from 'vitest';

process.env.TRANSACT_SESSION_SECRET ||= 'test-session-secret';
process.env.JWT_SECRET ||= 'test-jwt-secret';
process.env.TRANSITIVE_USER ||= 'test-transitive-user';

process.env.COGNITO_CLIENT_ID ||= 'test-client-id';
process.env.COGNITO_CLIENT_SECRET ||= 'test-client-secret';
process.env.COGNITO_REDIRECT_URI ||= 'http://localhost/auth/callback';
process.env.COGNITO_DOMAIN ||= 'example.auth.eu-south-2.amazoncognito.com';
process.env.COGNITO_LOGOUT_URI ||= 'http://localhost/logout';


vi.mock('@transitive-sdk/utils', () => ({
  default: {
    getLogger: () => ({
      setLevel: () => {},
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    }),
  },
}));
