import { VPNCacheStore } from '.';
import { VPNDetectionConfig, VPNDetectionResult } from '../types';
import { LRUCache } from 'lru-cache';

export class MemoryVPNCacheStore implements VPNCacheStore {
  private cache: LRUCache<string, VPNDetectionResult>;

  constructor(config: VPNDetectionConfig) {
    this.cache = new LRUCache<string, VPNDetectionResult>({
      max: config.cacheSize || 10000,
      ttl: config.cacheTtl || 3600000,
      ttlAutopurge: true,
    });
  }

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(ip: string): Promise<VPNDetectionResult | null> {
    return this.cache.get(ip) || null;
  }

  async set(ip: string, value: VPNDetectionResult): Promise<void> {
    this.cache.set(ip, value);
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
