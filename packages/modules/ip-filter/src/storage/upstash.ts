import { IPCacheStore } from '.';
import { IPFilterConfig } from '../types';

export class UpstashIPCacheStore implements IPCacheStore {
  private client: any;
  private keyPrefix: string;
  private config: any;
  private ttl: number;

  constructor(config: IPFilterConfig) {
    this.keyPrefix = config.upstash?.keyPrefix || 'ipfilter:';
    this.config = config.upstash;
    this.ttl = Math.floor((config.cacheTtl || 3600000) / 1000);
  }

  async init(): Promise<void> {
    try {
      const { Redis } = await import('@upstash/redis');

      this.client = new Redis({
        url: this.config.url,
        token: this.config.token,
      });

      await this.client.ping();
    } catch (error) {
      console.error('Failed to initialize Upstash client:', error);
      throw new Error('Upstash initialization failed');
    }
  }

  async get(key: string): Promise<boolean | null> {
    try {
      const data = await this.client.get(this.keyPrefix + key);
      if (data === null) return null;

      if (typeof data === 'boolean') {
        return data;
      }

      if (typeof data === 'string') {
        return data === 'true';
      }

      return null;
    } catch (error) {
      console.error('Upstash get error:', error);
      return null;
    }
  }

  async set(key: string, value: boolean): Promise<void> {
    try {
      await this.client.set(this.keyPrefix + key, value.toString(), { ex: this.ttl });
    } catch (error) {
      console.error('Upstash set error:', error);
    }
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
