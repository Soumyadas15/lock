import { TokenStorageProvider } from '../types';
import { secureCompare } from '../utils/token';

interface TokenRecord {
  token: string;
  createdAt: number;
  expiresAt: number;
}

export class MemoryStorage implements TokenStorageProvider {
  private store: Map<string, TokenRecord>;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.store = new Map();
    this.scheduleCleanup();
  }
  async init(): Promise<void> {}
  async saveToken(token: string, identifier: string, ttl: number): Promise<void> {
    const now = Date.now();

    this.store.set(identifier, {
      token,
      createdAt: now,
      expiresAt: now + ttl * 1000,
    });
  }
  async getToken(identifier: string): Promise<string | null> {
    const record = this.store.get(identifier);

    if (!record) {
      return null;
    }

    if (record.expiresAt < Date.now()) {
      this.store.delete(identifier);
      return null;
    }

    return record.token;
  }

  async validateToken(token: string, identifier: string): Promise<boolean> {
    const storedToken = await this.getToken(identifier);

    if (!storedToken) {
      return false;
    }
    return secureCompare(token, storedToken);
  }

  async deleteToken(identifier: string): Promise<void> {
    this.store.delete(identifier);
  }

  async deleteExpiredTokens(): Promise<void> {
    const now = Date.now();

    for (const [identifier, record] of this.store.entries()) {
      if (record.expiresAt < now) {
        this.store.delete(identifier);
      }
    }
  }

  private scheduleCleanup(): void {
    this.cleanupInterval = setInterval(
      () => {
        this.deleteExpiredTokens().catch(err => {
          console.error('Error cleaning up expired CSRF tokens:', err);
        });
      },
      15 * 60 * 1000
    );

    process.on('beforeExit', () => {
      if (this.cleanupInterval) {
        clearInterval(this.cleanupInterval);
        this.cleanupInterval = null;
      }
    });
  }
}
