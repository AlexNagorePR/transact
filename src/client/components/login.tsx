import React, { useEffect } from 'react';

export const Login = () => {
  useEffect(() => {
    window.location.href = '/auth/login';
  }, []);

  return <div>Redirecting to login...</div>;
}