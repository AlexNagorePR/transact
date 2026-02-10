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
  if (!account._id) {
    throw new Error('Account must have _id');
  }
  
  const payload = {
      user: account._id,
      verified: account.verified,
      admin: account.admin || false,
  };
  return JSON.stringify(payload);
};

/** simple middleware to check whether the user is logged in */
export const requireLogin = (req, res, next) => {
  if (req.session && req.session.user) {
    return next();
  }

  log.debug('not logged in', req.url);

  if (req.xhr || req.headers.accept.indexOf('json') > -1) {
    res.status(401).json({
      error: 'Not authorized. You need to be logged in. Please log out and back in.',
      ok: false,
    });
  }
  
  return res.redirect('/auth/login');
};

/** Log the user of this request into the given account. */
export const  login = (req, res, opts: { account: AccountLike, redirect?: string | false }) => {
  const { account, redirect = false } = opts;
  
  req.session.user = account;
  res.cookie(COOKIE_NAME, createCookie(account));

  if (redirect) {
    return res.redirect(redirect);
  }
  return res.json({ status: 'ok' });
};