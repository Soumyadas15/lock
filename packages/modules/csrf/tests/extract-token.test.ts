import { describe, it, expect } from 'vitest';
import {
  extractToken,
  extractFromHeader,
  extractFromCookie,
  extractFromBody,
  extractFromQuery,
  extractFromSession,
  parseCookies,
} from '../src/utils/extract-token';

const config: any = {
  headerName: 'x-csrf-token',
  cookieName: 'csrf-token',
  tokenName: 'csrf-token',
  angularCompatible: false,
};

describe('Extract Token Utilities', () => {
  it('should extract token from header', () => {
    const req = { headers: { 'x-csrf-token': 'headerToken' } };
    const token = extractFromHeader(req, config);
    expect(token).toBe('headerToken');
  });

  it('should extract token from cookie (parsed cookies)', () => {
    const req = { cookies: { 'csrf-token': 'cookieToken' }, headers: {} };
    const token = extractFromCookie(req, config);
    expect(token).toBe('cookieToken');
  });

  it('should extract token from cookie header when cookies are not parsed', () => {
    const req = { headers: { cookie: 'csrf-token=cookieToken; other=val' } };
    const token = extractFromCookie(req, config);
    expect(token).toBe('cookieToken');
  });

  it('should extract token from body', () => {
    const req = { body: { 'csrf-token': 'bodyToken' } };
    const token = extractFromBody(req, config);
    expect(token).toBe('bodyToken');
  });

  it('should extract token from query parameters', () => {
    const req = { query: { 'csrf-token': 'queryToken' } };
    const token = extractFromQuery(req, config);
    expect(token).toBe('queryToken');
  });

  it('should extract token from session', () => {
    const req = { session: { 'csrf-token': 'sessionToken' } };
    const token = extractFromSession(req, config);
    expect(token).toBe('sessionToken');
  });

  it('should extract token using default extraction order (header prioritized)', () => {
    const req = {
      headers: { 'x-csrf-token': 'headerToken' },
      body: { 'csrf-token': 'bodyToken' },
      query: { 'csrf-token': 'queryToken' },
      cookies: { 'csrf-token': 'cookieToken' },
      session: { 'csrf-token': 'sessionToken' },
    };
    const token = extractToken(req, config);
    expect(token).toBe('headerToken');
  });

  it('should parse cookie string correctly', () => {
    const cookieString = 'csrf-token=cookieToken; foo=bar';
    const cookies = parseCookies(cookieString);
    expect(cookies['csrf-token']).toBe('cookieToken');
    expect(cookies['foo']).toBe('bar');
  });
});
