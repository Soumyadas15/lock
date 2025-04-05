import { GeoCacheStore } from '.';
import { GeoInfo, GeoBlockConfig } from '../types';
import { LRUCache } from 'lru-cache';

export class MemoryGeoCacheStore implements GeoCacheStore {
  private cache: LRUCache<string, GeoInfo>;

  constructor(config: GeoBlockConfig) {
    this.cache = new LRUCache<string, GeoInfo>({
      max: config.cacheSize || 10000,
      ttl: config.cacheTtl || 3600000,
      ttlAutopurge: true,
    });
  }

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(ip: string): Promise<GeoInfo | null> {
    return this.cache.get(ip) || null;
  }

  async set(ip: string, value: GeoInfo): Promise<void> {
    this.cache.set(ip, value);
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
