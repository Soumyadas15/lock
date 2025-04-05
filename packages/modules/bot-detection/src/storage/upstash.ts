import { BotCacheStore } from '.';
import { BotDetectorConfig, RequestMetadata, BotDetectionResult } from '../types';

export class UpstashBotCacheStore implements BotCacheStore {
  private client: any;
  private requestKeyPrefix: string;
  private resultKeyPrefix: string;
  private config: any;
  private ttl: number;

  constructor(config: BotDetectorConfig) {
    this.requestKeyPrefix = config.upstash?.keyPrefix
      ? `${config.upstash.keyPrefix}req:`
      : 'botcache:req:';
    this.resultKeyPrefix = config.upstash?.keyPrefix
      ? `${config.upstash.keyPrefix}res:`
      : 'botcache:res:';
    this.config = config.upstash;
    this.ttl = Math.floor((config.cache?.ttl || 3600000) / 1000);
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

  async getRequests(ip: string): Promise<RequestMetadata[] | null> {
    try {
      const data = await this.client.get(this.requestKeyPrefix + ip);
      if (!data) return null;

      if (typeof data === 'string') {
        try {
          return JSON.parse(data);
        } catch (parseError) {
          console.error('Error parsing request data from Upstash:', parseError);
          return null;
        }
      } else if (typeof data === 'object' && Array.isArray(data)) {
        return data as RequestMetadata[];
      }

      return null;
    } catch (error) {
      console.error('Upstash getRequests error:', error);
      return null;
    }
  }

  async setRequests(ip: string, requests: RequestMetadata[]): Promise<void> {
    try {
      const stringValue = JSON.stringify(requests);

      await this.client.set(this.requestKeyPrefix + ip, stringValue, { ex: this.ttl });
    } catch (error) {
      console.error('Upstash setRequests error:', error);
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
          console.error('Error parsing result data from Upstash:', parseError);
          return null;
        }
      } else if (typeof data === 'object') {
        return data as BotDetectionResult;
      }

      return null;
    } catch (error) {
      console.error('Upstash getResult error:', error);
      return null;
    }
  }

  async setResult(ip: string, result: BotDetectionResult): Promise<void> {
    try {
      const stringValue = JSON.stringify(result);

      await this.client.set(this.resultKeyPrefix + ip, stringValue, { ex: this.ttl });
    } catch (error) {
      console.error('Upstash setResult error:', error);
    }
  }

  async deleteResult(ip: string): Promise<void> {
    try {
      await this.client.del(this.resultKeyPrefix + ip);
    } catch (error) {
      console.error('Upstash deleteResult error:', error);
    }
  }

  async prune(maxAge: number): Promise<void> {
    try {
      const now = Date.now();
      const scan = await this.client.scan(0, { match: this.requestKeyPrefix + '*', count: 1000 });
      const keys = scan[1];

      if (!keys || keys.length === 0) return;

      for (const key of keys) {
        const data = await this.client.get(key);
        if (!data) continue;

        try {
          let requests: RequestMetadata[];

          if (typeof data === 'string') {
            requests = JSON.parse(data);
          } else if (typeof data === 'object' && Array.isArray(data)) {
            requests = data;
          } else {
            continue;
          }

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
      console.error('Upstash prune error:', error);
    }
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
