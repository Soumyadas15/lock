import { describe, it, expect, beforeEach, vi } from 'vitest';
import { csrfProtection, csrfToken } from '../src/index'; // adjust path if needed
import { CSRFConfig, CSRFEventType } from '../src/types';
import type { SecurityContext } from '@lock-sdk/core';

vi.mock('../src/utils/token', () => ({
  generateToken: vi.fn(() => 'generated-token'),
  validateToken: vi.fn((token, id) => token === 'valid-token'),
}));

vi.mock('../src/utils/extract-token', () => ({
  extractToken: vi.fn(() => 'valid-token'),
}));

vi.mock('../src/storage', () => ({
  createStorage: vi.fn(() => ({
    saveToken: vi.fn(),
    getToken: vi.fn(),
    validateToken: vi.fn(() => true),
    deleteToken: vi.fn(),
    deleteExpiredTokens: vi.fn(),
  })),
}));

function createMockContext(
  method = 'POST',
  path = '/submit',
  cookieToken = 'valid-token'
): SecurityContext {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'user-agent': 'vitest',
  };
  const cookies = { 'csrf-token': cookieToken };
  const dataMap = new Map();

  return {
    request: {
      method,
      url: path,
      headers,
      cookies,
      ip: '127.0.0.1',
      session: { id: 'abc123' },
    },
    response: {
      statusCode: 200,
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      end: vi.fn(),
      setHeader: vi.fn(),
      cookie: vi.fn(),
      headersSent: false,
      writableEnded: false,
      locals: {},
    },
    data: {
      set: dataMap.set.bind(dataMap),
      get: dataMap.get.bind(dataMap),
    },
  } as unknown as SecurityContext;
}

const baseConfig: CSRFConfig = {
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

describe('CSRF Protection Module', () => {
  let context: SecurityContext;

  beforeEach(() => {
    context = createMockContext();
    vi.clearAllMocks();
  });

  it('bypasses ignored methods like GET and sets token', async () => {
    context = createMockContext('GET');
    const mod = csrfProtection(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
    expect(context.response.setHeader).toHaveBeenCalledWith('x-csrf-token', 'generated-token');
  });

  it('bypasses ignored paths', async () => {
    context = createMockContext('POST', '/health');
    const mod = csrfProtection({
      ...baseConfig,
      ignoredPaths: ['/health'],
    });
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('bypasses ignored content types', async () => {
    context = createMockContext('POST');
    context.request.headers['content-type'] = 'multipart/form-data';
    const mod = csrfProtection(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(true);
  });

  it('fails if token is missing', async () => {
    const { extractToken } = await import('../src/utils/extract-token');
    (extractToken as any).mockReturnValueOnce(null);

    const mod = csrfProtection(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(CSRFEventType.CSRF_TOKEN_MISSING);
  });

  it('fails if token is invalid', async () => {
    const { validateToken } = await import('../src/utils/token');
    (validateToken as any).mockReturnValueOnce(false);

    const mod = csrfProtection(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(CSRFEventType.CSRF_TOKEN_INVALID);
  });

  it('fails if double-submit cookie doesn’t match header', async () => {
    context = createMockContext('POST', '/submit', 'cookie-value-doesnt-match');
    const mod = csrfProtection(baseConfig);
    const result = await mod.check(context);
    expect(result.passed).toBe(false);
    expect(result.event?.type).toBe(CSRFEventType.CSRF_DOUBLE_SUBMIT_FAILURE);
  });

  it('csrfToken middleware sets token properly', async () => {
    const req = { headers: {}, cookies: {}, session: {}, ip: '127.0.0.1' };
    const res = {
      setHeader: vi.fn(),
      cookie: vi.fn(),
      locals: {},
    };
    const next = vi.fn();

    const middleware = csrfToken();
    await middleware(req, res, next);

    expect(res.setHeader).toHaveBeenCalledWith('x-csrf-token', 'generated-token');
    expect(res.cookie).toHaveBeenCalledWith('csrf-token', 'generated-token', expect.anything());
    expect(next).toHaveBeenCalled();
  });
});
