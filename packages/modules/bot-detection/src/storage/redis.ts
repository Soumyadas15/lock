import { BotCacheStore } from '.';
import { BotDetectorConfig, RequestMetadata, BotDetectionResult } from '../types';

export class RedisBotCacheStore implements BotCacheStore {
  private client: any;
  private requestKeyPrefix: string;
  private resultKeyPrefix: string;
  private config: any;
  private ttl: number;

  constructor(config: BotDetectorConfig) {
    this.requestKeyPrefix = config.redis?.keyPrefix
      ? `${config.redis.keyPrefix}req:`
      : 'botcache:req:';
    this.resultKeyPrefix = config.redis?.keyPrefix
      ? `${config.redis.keyPrefix}res:`
      : 'botcache:res:';
    this.config = config.redis;
    this.ttl = Math.floor((config.cache?.ttl || 3600000) / 1000);
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

  async getRequests(ip: string): Promise<RequestMetadata[] | null> {
    try {
      const data = await this.client.get(this.requestKeyPrefix + ip);
      if (!data) return null;

      try {
        return JSON.parse(data);
      } catch (parseError) {
        console.error('Error parsing request data from Redis:', parseError);
        return null;
      }
    } catch (error) {
      console.error('Redis getRequests error:', error);
      return null;
    }
  }

  async setRequests(ip: string, requests: RequestMetadata[]): Promise<void> {
    try {
      await this.client.set(this.requestKeyPrefix + ip, JSON.stringify(requests), { EX: this.ttl });
    } catch (error) {
      console.error('Redis setRequests error:', error);
    }
  }

  async getResult(ip: string): Promise<BotDetectionResult | null> {
    try {
      const data = await this.client.get(this.resultKeyPrefix + ip);
      if (!data) return null;

      if (typeof data === 'string') {
        try {
          return JSON.parse(data);
        } catch (parseError) {
          console.error('Error parsing result data from Redis:', parseError);
          return null;
        }
      } else if (typeof data === 'object') {
        return data as BotDetectionResult;
      }

      return null;
    } catch (error) {
      console.error('Redis getResult error:', error);
      return null;
    }
  }

  async setResult(ip: string, result: BotDetectionResult): Promise<void> {
    try {
      await this.client.set(this.resultKeyPrefix + ip, JSON.stringify(result), { EX: this.ttl });
    } catch (error) {
      console.error('Redis setResult error:', error);
    }
  }

  async deleteResult(ip: string): Promise<void> {
    try {
      await this.client.del(this.resultKeyPrefix + ip);
    } catch (error) {
      console.error('Redis deleteResult error:', error);
    }
  }

  async prune(maxAge: number): Promise<void> {
    try {
      const now = Date.now();
      const pattern = this.requestKeyPrefix + '*';

      const keys = await this.client.keys(pattern);
      if (!keys || keys.length === 0) return;

      for (const key of keys) {
        const data = await this.client.get(key);
        if (!data) continue;

        try {
          const requests = JSON.parse(data) as RequestMetadata[];
          const allOld = requests.every(req => now - req.timestamp > maxAge);

          if (allOld) {
            const ip = key.substring(this.requestKeyPrefix.length);
            await this.client.del(key);
            await this.client.del(this.resultKeyPrefix + ip);
          }
        } catch (parseError) {
          console.error('Error parsing request data during prune:', parseError);
        }
      }
    } catch (error) {
      console.error('Redis prune error:', error);
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
