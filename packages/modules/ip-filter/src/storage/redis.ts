import { IPCacheStore } from '.';
import { IPFilterConfig } from '../types';

export class RedisIPCacheStore implements IPCacheStore {
  private client: any;
  private keyPrefix: string;
  private config: any;
  private ttl: number;

  constructor(config: IPFilterConfig) {
    this.keyPrefix = config.redis?.keyPrefix || 'ipfilter:';
    this.config = config.redis;
    this.ttl = Math.floor((config.cacheTtl || 3600000) / 1000);
  }

  async init(): Promise<void> {
    try {
      const { createClient } = await import('redis');

      if (this.config.url) {
        this.client = createClient({ url: this.config.url });
      } else {
        this.client = createClient({
          socket: {
            host: this.config.host || 'localhost',
            port: this.config.port || 6379,
          },
          username: this.config.username,
          password: this.config.password,
          database: this.config.database || 0,
        });
      }

      await this.client.connect();

      this.client.on('error', (err: Error) => {
        console.error('Redis client error:', err);
      });
    } catch (error) {
      console.error('Failed to initialize Redis client:', error);
      throw new Error('Redis initialization failed');
    }
  }

  async get(key: string): Promise<boolean | null> {
    try {
      const data = await this.client.get(this.keyPrefix + key);
      if (data === null) return null;
      return data === 'true';
    } catch (error) {
      console.error('Redis get error:', error);
      return null;
    }
  }

  async set(key: string, value: boolean): Promise<void> {
    try {
      await this.client.set(this.keyPrefix + key, value.toString(), { EX: this.ttl });
    } catch (error) {
      console.error('Redis set error:', error);
    }
  }

  async close(): Promise<void> {
    try {
      if (this.client) {
        await this.client.quit();
      }
    } catch (error) {
      console.error('Redis close error:', error);
    }
  }
}
