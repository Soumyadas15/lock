import { BotCacheStore } from '.';
import { BotDetectorConfig, RequestMetadata, BotDetectionResult } from '../types';
import { LRUCache } from 'lru-cache';

export class MemoryBotCacheStore implements BotCacheStore {
  private requestCache: LRUCache<string, RequestMetadata[]>;
  private resultCache: LRUCache<string, BotDetectionResult>;

  constructor(config: BotDetectorConfig) {
    this.requestCache = new LRUCache<string, RequestMetadata[]>({
      max: config.cache?.size || 10000,
      ttl: config.cache?.ttl || 3600000,
      ttlAutopurge: true,
    });

    this.resultCache = new LRUCache<string, BotDetectionResult>({
      max: config.cache?.size || 10000,
      ttl: config.cache?.ttl || 3600000,
      ttlAutopurge: true,
    });
  }

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async getRequests(ip: string): Promise<RequestMetadata[] | null> {
    return this.requestCache.get(ip) || null;
  }

  async setRequests(ip: string, requests: RequestMetadata[]): Promise<void> {
    this.requestCache.set(ip, requests);
  }

  async getResult(ip: string): Promise<BotDetectionResult | null> {
    return this.resultCache.get(ip) || null;
  }

  async setResult(ip: string, result: BotDetectionResult): Promise<void> {
    this.resultCache.set(ip, result);
  }

  async deleteResult(ip: string): Promise<void> {
    this.resultCache.delete(ip);
  }

  async prune(maxAge: number): Promise<void> {
    const now = Date.now();
    const keysToDelete: string[] = [];

    this.requestCache.forEach((requests, key) => {
      const allOld = requests.every(req => now - req.timestamp > maxAge);
      if (allOld) keysToDelete.push(key);
    });

    keysToDelete.forEach(key => {
      this.requestCache.delete(key);
      this.resultCache.delete(key);
    });
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
