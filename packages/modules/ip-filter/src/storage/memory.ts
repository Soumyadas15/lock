import { LRUCache } from 'lru-cache';
import { IPCacheStore } from '.';
import { IPFilterConfig } from '../types';

export class MemoryIPCacheStore implements IPCacheStore {
  private cache: LRUCache<string, boolean>;

  constructor(config: IPFilterConfig) {
    this.cache = new LRUCache<string, boolean>({
      max: config.cacheSize || 10000,
      ttl: config.cacheTtl || 3600000,
      ttlAutopurge: true,
    });
  }

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(key: string): Promise<boolean | null> {
    const value = this.cache.get(key);
    return value === undefined ? null : value;
  }

  async set(key: string, value: boolean): Promise<void> {
    this.cache.set(key, value);
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
