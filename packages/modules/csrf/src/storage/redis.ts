import { TokenStorageProvider, RedisOptions } from '../types';
import { secureCompare } from '../utils/token';

type RedisClient = any;

export class RedisStorage implements TokenStorageProvider {
  private client: RedisClient | null = null;
  private keyPrefix: string;
  private options: RedisOptions;
  private externalClient: boolean;

  constructor(options: RedisOptions = {}) {
    this.options = options;
    this.keyPrefix = options.keyPrefix || 'csrf:';
    this.externalClient = !!options.client;
  }

  async init(): Promise<void> {
    if (this.client) {
      return;
    }

    if (this.options.client) {
      this.client = this.options.client;
      return;
    }

    try {
      const redis = await import('redis');

      if (this.options.url) {
        this.client = redis.createClient({ url: this.options.url });
      } else {
        this.client = redis.createClient({
          socket: {
            host: this.options.host || 'localhost',
            port: this.options.port || 6379,
          },
          password: this.options.password,
          database: this.options.db || 0,
          username: this.options.username,
        });
      }

      this.client.on('error', (err: Error) => {
        console.error('Redis error:', err);
      });

      if (typeof this.client.connect === 'function') {
        await this.client.connect();
      }
    } catch (err) {
      console.error('Failed to initialize Redis client:', err);
      throw new Error('Failed to initialize Redis client for CSRF token storage');
    }
  }

  async saveToken(token: string, identifier: string, ttl: number): Promise<void> {
    await this.ensureInitialized();

    const key = this.getKey(identifier);
    if (this.isRedisV4()) {
      await this.client!.set(key, token, { EX: ttl });
    } else {
      await new Promise<void>((resolve, reject) => {
        this.client!.set(key, token, 'EX', ttl, (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }

  async getToken(identifier: string): Promise<string | null> {
    await this.ensureInitialized();

    const key = this.getKey(identifier);
    if (this.isRedisV4()) {
      return await this.client!.get(key);
    } else {
      return await new Promise((resolve, reject) => {
        this.client!.get(key, (err: Error | null, reply: string | null) => {
          if (err) reject(err);
          else resolve(reply);
        });
      });
    }
  }

  async validateToken(token: string, identifier: string): Promise<boolean> {
    const storedToken = await this.getToken(identifier);

    if (!storedToken) {
      return false;
    }

    return secureCompare(token, storedToken);
  }

  async deleteToken(identifier: string): Promise<void> {
    await this.ensureInitialized();

    const key = this.getKey(identifier);
    if (this.isRedisV4()) {
      await this.client!.del(key);
    } else {
      await new Promise<void>((resolve, reject) => {
        this.client!.del(key, (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
  }

  async deleteExpiredTokens(): Promise<void> {}

  private async ensureInitialized(): Promise<void> {
    if (!this.client) {
      await this.init();
    }
  }

  private getKey(identifier: string): string {
    return `${this.keyPrefix}${identifier}`;
  }

  private isRedisV4(): boolean {
    return (
      typeof this.client!.get === 'function' &&
      this.client!.get.constructor.name === 'AsyncFunction'
    );
  }

  async close(): Promise<void> {
    if (this.client && !this.externalClient) {
      if (typeof this.client.quit === 'function') {
        await this.client.quit();
      } else if (typeof this.client.disconnect === 'function') {
        await this.client.disconnect();
      }
      this.client = null;
    }
  }
}
