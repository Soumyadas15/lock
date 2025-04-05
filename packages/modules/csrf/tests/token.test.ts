import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import {
  generateToken,
  validateToken,
  hashToken,
  generateSecret,
  generateTokenSync,
  secureCompare,
} from '../src/utils/token';
import { TokenStorageProvider, CSRFConfig } from '../src/types';

class FakeStorage implements TokenStorageProvider {
  tokens = new Map<string, { token: string; expiresAt: number }>();

  async init(): Promise<void> {}

  async saveToken(token: string, identifier: string, ttl: number): Promise<void> {
    this.tokens.set(identifier, { token, expiresAt: Date.now() + ttl * 1000 });
  }

  async getToken(identifier: string): Promise<string | null> {
    const record = this.tokens.get(identifier);
    if (!record || record.expiresAt < Date.now()) {
      this.tokens.delete(identifier);
      return null;
    }
    return record.token;
  }

  async validateToken(token: string, identifier: string): Promise<boolean> {
    const stored = await this.getToken(identifier);
    return stored === token;
  }

  async deleteToken(identifier: string): Promise<void> {
    this.tokens.delete(identifier);
  }

  async deleteExpiredTokens(): Promise<void> {
    for (const [identifier, record] of this.tokens.entries()) {
      if (record.expiresAt < Date.now()) {
        this.tokens.delete(identifier);
      }
    }
  }
}

const config: CSRFConfig = {
  tokenName: 'csrf-token',
  tokenLength: 32,
  tokenTtl: 3600,
  enabled: true,
  headerName: 'x-csrf-token',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: false,
    secure: true,
    sameSite: 'lax',
    path: '/',
  },
  storage: 'memory',
  tokenLocation: 'header',
  ignoredMethods: [],
  ignoredPaths: [],
  ignoredContentTypes: [],
  failureStatusCode: 403,
  failureMessage: 'CSRF token validation failed',
  refreshToken: false,
  doubleSubmit: false,
  samesite: true,
};

describe('Token Utilities', () => {
  const fakeStorage = new FakeStorage();

  it('should generate a token of expected type and store it', async () => {
    const identifier = 'test-session';
    const token = await generateToken(config.tokenLength, identifier, fakeStorage, config);
    expect(typeof token).toBe('string');
    const stored = await fakeStorage.getToken(identifier);
    expect(stored).toBe(token);
  });

  it('should validate a valid token', async () => {
    const identifier = 'session-validate';
    const token = await generateToken(config.tokenLength, identifier, fakeStorage, config);
    const isValid = await validateToken(token, identifier, fakeStorage, config);
    expect(isValid).toBe(true);
  });

  it('should fail validation for an invalid token', async () => {
    const identifier = 'session-invalid';
    await fakeStorage.saveToken('correcttoken', identifier, 3600);
    const isValid = await validateToken('wrongtoken', identifier, fakeStorage, config);
    expect(isValid).toBe(false);
  });

  it('should create a hash token using the default algorithm', () => {
    const token = 'sometoken';
    const secret = 'secret';
    const hashed = hashToken(token, secret);
    expect(typeof hashed).toBe('string');
    const expected = crypto.createHmac('sha256', secret).update(token).digest('base64');
    expect(hashed).toBe(expected);
  });

  it('should generate a secret of expected length', () => {
    const secret = generateSecret();
    expect(secret).toHaveLength(64);
  });

  it('should synchronously generate a token', () => {
    const token = generateTokenSync(config.tokenLength);
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  it('should securely compare tokens correctly', () => {
    expect(secureCompare('same', 'same')).toBe(true);
    expect(secureCompare('same', 'diff')).toBe(false);
  });
});
