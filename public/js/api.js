'use strict';

const TOKEN_KEY = 'security.token';

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request(path, { method = 'GET', body, as = 'json' } = {}) {
  const headers = {};
  const options = { method, headers };

  if (body !== undefined && body !== null) {
    const isBinary =
      body instanceof ArrayBuffer ||
      body instanceof Blob ||
      ArrayBuffer.isView(body);
    if (isBinary) {
      options.body = body;
      headers['Content-Type'] = 'application/octet-stream';
    } else {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
  }

  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`/api${path}`, options);
  } catch {
    throw new ApiError('network', 0, null);
  }

  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent('security:unauthorized'));
  }

  if (!response.ok) {
    let data = null;
    try {
      data = await response.json();
    } catch {
      /* тело не JSON */
    }
    throw new ApiError((data && data.error) || 'request_failed', response.status, data);
  }

  if (as === 'buffer') return response.arrayBuffer();
  if (as === 'text') return response.text();
  return response.json();
}

export const api = {
  get token() {
    return getToken();
  },
  get: (path) => request(path),
  post: (path, body) => request(path, { method: 'POST', body }),
  put: (path, body) => request(path, { method: 'PUT', body }),
  patch: (path, body) => request(path, { method: 'PATCH', body }),
  del: (path) => request(path, { method: 'DELETE' }),
  buffer: (path) => request(path, { as: 'buffer' }),
  raw: (path, bytes) => request(path, { method: 'POST', body: bytes }),
};
