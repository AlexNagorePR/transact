import { COOKIE_NAME } from '@/common/constants.js';
import utils from '@transitive-sdk/utils';

const log = utils.getLogger('auth');
log.setLevel('debug');

interface AccountLike {
    _id: string;
    email?: string;
    admin?: boolean;
    verified?: boolean;
}

/** given an account (object from DB), create the cookie payload string */
const createCookie = (account: AccountLike): string => {
  if (!account._id) throw new Error('Account must have _id');
  
  const payload = {
      user: account._id,
      verified: Boolean(account.verified),
      admin: Boolean(account.admin),
  };

  return JSON.stringify(payload);
};

function wantsJson(req: any): boolean {
  if (req.path?.startsWith('/api/')) return true;

  const accept = String(req.headers?.accept || '').toLowerCase();
  return Boolean(req.xhr) || accept.includes('json');
}

export const requireLogin = (req: any, res: any, next: any) => {
  const user = req.session?.user;
  
  if (user && user._id) {
    return next();
  } 

  log.debug('not logged in', req.url);

  if (wantsJson(req)) {
    return res.status(401).json({
      error: 'Not authorized. You need to be logged in. Please log out and back in.',
      ok: false,
    });
  }
    
  return res.redirect('/auth/login');
};

export const  login = (
  req: any,
  res: any,
  opts: { account: AccountLike, redirect?: string | false }
) => {
  const { account, redirect = false } = opts;
  
  req.session.user = account;
  res.cookie(COOKIE_NAME, createCookie(account));

  if (redirect) {
    return res.redirect(redirect);
  }

  return res.json({ status: 'ok' });
};