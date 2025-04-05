import { CSRFConfig, TokenLocation } from '../types';

export function extractToken(req: any, config: CSRFConfig): string | null {
  switch (config.tokenLocation) {
    case 'header':
      return extractFromHeader(req, config);
    case 'cookie':
      return extractFromCookie(req, config);
    case 'cookie-header':
      return extractFromHeader(req, config) || extractFromCookie(req, config);
    case 'session':
      return extractFromSession(req, config);
    default:
      return (
        extractFromHeader(req, config) ||
        extractFromBody(req, config) ||
        extractFromQuery(req, config) ||
        extractFromCookie(req, config) ||
        extractFromSession(req, config)
      );
  }
}

export function extractFromHeader(req: any, config: CSRFConfig): string | null {
  const headerName = config.headerName.toLowerCase();

  if (req.headers && req.headers[headerName]) {
    return req.headers[headerName] as string;
  }
  if (config.angularCompatible && req.headers && req.headers['x-xsrf-token']) {
    return req.headers['x-xsrf-token'] as string;
  }

  return null;
}

export function extractFromCookie(req: any, config: CSRFConfig): string | null {
  if (req.cookies && req.cookies[config.cookieName]) {
    return req.cookies[config.cookieName];
  }
  if (req.headers && req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies[config.cookieName]) {
      return cookies[config.cookieName];
    }
  }

  return null;
}

export function extractFromBody(req: any, config: CSRFConfig): string | null {
  if (req.body) {
    if (req.body[config.tokenName]) {
      return req.body[config.tokenName];
    }
    if (req.body._csrf) {
      return req.body._csrf;
    }
  }

  return null;
}

export function extractFromQuery(req: any, config: CSRFConfig): string | null {
  if (req.query && req.query[config.tokenName]) {
    return req.query[config.tokenName];
  }
  if (req.query && req.query._csrf) {
    return req.query._csrf;
  }

  return null;
}

export function extractFromSession(req: any, config: CSRFConfig): string | null {
  if (req.session) {
    if (req.session[config.tokenName]) {
      return req.session[config.tokenName];
    }
    if (req.session._csrf) {
      return req.session._csrf;
    }
  }

  console.log('[CSRF] No token found in session');
  return null;
}

export function parseCookies(cookieString: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  if (!cookieString) {
    return cookies;
  }

  cookieString.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    if (parts.length >= 2) {
      const name = parts.shift()?.trim();
      const value = parts.join('=').trim();
      if (name) {
        cookies[name] = value;
      }
    }
  });

  return cookies;
}
