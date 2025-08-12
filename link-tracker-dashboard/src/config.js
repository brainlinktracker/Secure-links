// Auto-patched config.js — defaults to local backend in development.
const defaultDevBase = 'http://localhost:5000/api';

export const API_BASE = import.meta.env.MODE === 'production'
  ? '/api'
  : (import.meta.env.VITE_API_BASE || defaultDevBase);

export const API_ENDPOINTS = {
  BASE: import.meta.env.MODE === 'production'
    ? ''
    : (import.meta.env.VITE_API_BASE ? import.meta.env.VITE_API_BASE.replace(/\/$/, '') : 'http://localhost:5000'),
  AUTH: {
    LOGIN: `${API_BASE}/auth/login`,
    REGISTER: `${API_BASE}/auth/register`,
    ME: `${API_BASE}/auth/me`
  },
  ANALYTICS: `${API_BASE}/analytics`,
  CAMPAIGNS: `${API_BASE}/campaigns`,
  LINKS: `${API_BASE}/links`,
  HEALTH: `${API_BASE}/health`,
  USERS: `${API_BASE}/users`
};
