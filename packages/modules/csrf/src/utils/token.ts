import * as crypto from 'crypto';
import { CSRFConfig } from '../types';
import { TokenStorageProvider } from '../types';

export async function generateToken(
  length: number,
  identifier: string,
  storage: TokenStorageProvider,
  config: CSRFConfig
): Promise<string> {
  const randomBytes = crypto.randomBytes(length);
  const token = randomBytes.toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  await storage.saveToken(token, identifier, config.tokenTtl);

  return token;
}

export async function validateToken(
  token: string,
  identifier: string,
  storage: TokenStorageProvider,
  config: CSRFConfig
): Promise<boolean> {
  if (!token) {
    return false;
  }
  return await storage.validateToken(token, identifier);
}

export function hashToken(token: string, secret: string, algorithm: string = 'sha256'): string {
  return crypto.createHmac(algorithm, secret).update(token).digest('base64');
}

export function generateSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function generateTokenSync(length: number): string {
  return crypto
    .randomBytes(length)
    .toString('base64')
    .replace(/[^a-zA-Z0-9]/g, '');
}

export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}
