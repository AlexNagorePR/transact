import { vi } from 'vitest';

// Mock del logger para no depender de typings ni ruido
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

// ✅ Mock de auth.js: requireLogin siempre “loguea” a un usuario fake
vi.mock('@/server/auth.js', () => ({
  login: vi.fn(),
  requireLogin: (req: any, _res: any, next: any) => {
    req.session ||= {};
    req.session.user = { _id: 'test-user' };
    next();
  },
}));