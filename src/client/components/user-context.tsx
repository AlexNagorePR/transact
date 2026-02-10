import React, { useEffect, useState} from 'react';
import { getLogger, parseCookie } from '@transitive-sdk/utils-web';
import { COOKIE_NAME } from '@/common/constants';
import { useLocation } from 'react-router-dom';

const log = getLogger('UserContext');
log.setLevel('debug');

export const UserContext = React.createContext({});

export const UserContextProvider = ({children}) => {
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState();
  const [error, setError] = useState();
  const location = useLocation();

  const refresh = () => {
    const cookie = parseCookie(document.cookie);
    if (cookie[COOKIE_NAME]) {
      setSession(JSON.parse(cookie[COOKIE_NAME]));
    } else {
      setSession(null);
    }
    setReady(true);
  };

  useEffect(() => {
    fetch('/api/refresh', { method: 'GET' })
    .then(response => {
      refresh();
      if (!response.ok) {
        if (location.pathname.startsWith('/auth/')) return;

        log.debug('not logged in');
        window.location.href = '/auth/login';
      }
    })
    .catch(function(err) {
      log.error(err);
      window.location.href = '/auth/login';
    });

  }, []);

  /** execute the login (Cognito Hosted UI) */
  const login = () => {
    window.location.href = '/auth/login';
  };
  
  const logout = () => {
    window.location.href = '/auth/logout';
  };

  return (
    <UserContext.Provider
      value={{ ready, session, login, logout, error }}>
      {children}
    </UserContext.Provider>
  );
};