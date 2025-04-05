import { createModule, SecurityContext } from '@lock-sdk/core';
import { registerModule } from '@lock-sdk/core';
import { CSRFConfig, CSRFEventType } from './types';
import { generateToken, validateToken } from './utils/token';
import { extractToken } from './utils/extract-token';
import { createStorage } from './storage';

const DEFAULT_CONFIG: Partial<CSRFConfig> = {
  enabled: true,
  tokenName: 'csrf-token',
  tokenLength: 32,
  headerName: 'x-csrf-token',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: false,
    secure: true,
    sameSite: 'lax',
    path: '/',
  },
  storage: 'memory',
  tokenLocation: 'cookie-header',
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  ignoredPaths: [],
  ignoredContentTypes: ['multipart/form-data'],
  failureStatusCode: 403,
  failureMessage: 'CSRF token validation failed',
  refreshToken: true,
  tokenTtl: 86400,
  doubleSubmit: true,
  samesite: true,
};

/**
 * Create a CSRF protection security module
 * @param config Module configuration
 */
export const csrfProtection = createModule<CSRFConfig>({
  name: 'csrf-protection',

  defaultConfig: DEFAULT_CONFIG,

  async check(context: SecurityContext, config: CSRFConfig) {
    try {
      if (!config.enabled) {
        return { passed: true };
      }

      const req = context.request;
      const res = context.response;
      const method = req.method?.toUpperCase() || '';

      if (config.ignoredMethods.includes(method)) {
        if (method === 'GET' && config.refreshToken) {
          await setCSRFToken(context, config);
        }
        return { passed: true };
      }

      const path = req.path || req.url || '';
      for (const ignoredPath of config.ignoredPaths) {
        if (typeof ignoredPath === 'string' && path === ignoredPath) {
          return { passed: true };
        } else if (ignoredPath instanceof RegExp && ignoredPath.test(path)) {
          return { passed: true };
        }
      }

      const contentType = req.headers?.['content-type'] || '';
      for (const ignoredType of config.ignoredContentTypes) {
        if (contentType.toLowerCase().includes(ignoredType.toLowerCase())) {
          return { passed: true };
        }
      }

      const storage = createStorage(config);
      const token = extractToken(req, config);

      if (!token) {
        return {
          passed: false,
          reason: CSRFEventType.CSRF_TOKEN_MISSING,
          data: { path, method },
          severity: 'medium',
        };
      }

      const sessionIdentifier = getSessionIdentifier(req, config);
      const isValid = await validateToken(token, sessionIdentifier, storage, config);

      if (!isValid) {
        return {
          passed: false,
          reason: CSRFEventType.CSRF_TOKEN_INVALID,
          data: { token, path, method },
          severity: 'medium',
        };
      }

      if (config.doubleSubmit && config.tokenLocation === 'cookie-header') {
        const cookieToken = extractCSRFCookie(req, config);
        if (!cookieToken || cookieToken !== token) {
          return {
            passed: false,
            reason: CSRFEventType.CSRF_DOUBLE_SUBMIT_FAILURE,
            data: { headerToken: token, cookieToken, path, method },
            severity: 'medium',
          };
        }
      }

      if (config.refreshToken) {
        await setCSRFToken(context, config);
      }

      return {
        passed: true,
        reason: CSRFEventType.CSRF_VALIDATED,
        data: { path, method },
        severity: 'low',
      };
    } catch (error) {
      console.error(`CSRF protection error: ${(error as Error).message}`);
      return {
        passed: false,
        reason: CSRFEventType.CSRF_ERROR,
        data: { error: (error as Error).message },
        severity: 'medium',
      };
    }
  },

  async handleFailure(context, reason, data) {
    const config = context.data.get('csrf-protection:config') as CSRFConfig;
    const res = context.response;

    if (res.headersSent || res.writableEnded) {
      return;
    }

    let message = config.failureMessage;
    if (reason === CSRFEventType.CSRF_TOKEN_MISSING) {
      message = 'CSRF token missing';
    } else if (reason === CSRFEventType.CSRF_TOKEN_INVALID) {
      message = 'CSRF token invalid';
    } else if (reason === CSRFEventType.CSRF_DOUBLE_SUBMIT_FAILURE) {
      message = 'CSRF token mismatch between cookie and header';
    }

    if (typeof res.status === 'function') {
      return res.status(config.failureStatusCode).json({
        error: message,
        blocked: true,
      });
    } else if (typeof res.statusCode === 'number') {
      res.statusCode = config.failureStatusCode;
      res.setHeader('Content-Type', 'application/json');
      return res.end(
        JSON.stringify({
          error: message,
          blocked: true,
        })
      );
    }
  },
});

function extractCSRFCookie(req: any, config: CSRFConfig): string | null {
  const cookies = req.cookies || parseCookies(req.headers?.cookie || '');
  return cookies[config.cookieName] || null;
}

function parseCookies(cookieString: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieString.split(';').forEach(cookie => {
    const [name, value] = cookie.split('=').map(c => c.trim());
    if (name && value) cookies[name] = value;
  });
  return cookies;
}

function getSessionIdentifier(req: any, config: CSRFConfig): string {
  if (req.session?.id) {
    return req.session.id;
  }

  const ip = req.ip || req.connection?.remoteAddress || '';
  const userAgent = req.headers?.['user-agent'] || '';

  return `${ip}:${userAgent}`;
}

async function setCSRFToken(context: SecurityContext, config: CSRFConfig): Promise<void> {
  const req = context.request;
  const res = context.response;

  const storage = createStorage(config);
  const sessionIdentifier = getSessionIdentifier(req, config);
  const token = await generateToken(config.tokenLength, sessionIdentifier, storage, config);

  if (config.tokenLocation === 'cookie' || config.tokenLocation === 'cookie-header') {
    if (typeof res.cookie === 'function') {
      res.cookie(config.cookieName, token, config.cookieOptions);
    } else {
      const cookieOptions = [];
      cookieOptions.push(`${config.cookieName}=${token}`);

      if (config.cookieOptions.httpOnly) cookieOptions.push('HttpOnly');
      if (config.cookieOptions.secure) cookieOptions.push('Secure');
      if (config.cookieOptions.sameSite)
        cookieOptions.push(`SameSite=${config.cookieOptions.sameSite}`);
      if (config.cookieOptions.path) cookieOptions.push(`Path=${config.cookieOptions.path}`);
      if (config.cookieOptions.domain) cookieOptions.push(`Domain=${config.cookieOptions.domain}`);
      if (config.cookieOptions.maxAge) cookieOptions.push(`Max-Age=${config.cookieOptions.maxAge}`);

      const cookieString = cookieOptions.join('; ');
      res.setHeader('Set-Cookie', cookieString);
    }
  }

  if (config.tokenLocation === 'header' || config.tokenLocation === 'cookie-header') {
    res.setHeader(config.headerName, token);
  }
  if (config.tokenLocation === 'session' && req.session) {
    req.session[config.tokenName] = token;
  }

  if (res.locals) {
    res.locals[config.tokenName] = token;
  }
}

export function csrfToken(config: Partial<CSRFConfig> = {}) {
  const finalConfig = { ...DEFAULT_CONFIG, ...config } as CSRFConfig;

  return async (req: any, res: any, next: Function) => {
    try {
      const context = {
        request: req,
        response: res,
        data: new Map(),
      } as SecurityContext;

      await setCSRFToken(context, finalConfig);
      next();
    } catch (error) {
      console.error('Error setting CSRF token:', error);
      next(error);
    }
  };
}

registerModule('csrfProtection', csrfProtection);

export * from './types';
export * from './utils/token';
export * from './utils/extract-token';
export * from './storage';
