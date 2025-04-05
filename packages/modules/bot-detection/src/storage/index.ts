import { BotDetectorConfig, RequestMetadata, BotDetectionResult } from '../types';
import { LRUCache } from 'lru-cache';
import { RedisBotCacheStore } from './redis';
import { UpstashBotCacheStore } from './upstash';
import { MemoryBotCacheStore } from './memory';

export type BotCacheType = 'requests' | 'results';

export interface BotCacheStore {
  init(): Promise<void>;
  getRequests(ip: string): Promise<RequestMetadata[] | null>;
  setRequests(ip: string, requests: RequestMetadata[]): Promise<void>;
  getResult(ip: string): Promise<BotDetectionResult | null>;
  setResult(ip: string, result: BotDetectionResult): Promise<void>;
  deleteResult(ip: string): Promise<void>;
  prune(maxAge: number): Promise<void>;
  close(): Promise<void>;
}

export async function createCacheStore(config: BotDetectorConfig): Promise<BotCacheStore> {
  const storageType = config.storage || 'memory';
  let store: BotCacheStore;

  switch (storageType) {
    case 'redis':
      if (!config.redis) {
        throw new Error('Redis configuration is required when using Redis storage');
      }
      store = new RedisBotCacheStore(config);
      break;

    case 'upstash':
      if (!config.upstash) {
        throw new Error('Upstash configuration is required when using Upstash storage');
      }
      store = new UpstashBotCacheStore(config);
      break;

    case 'memory':
    default:
      store = new MemoryBotCacheStore(config);
      break;
  }

  await store.init();
  return store;
}

export * from './memory';
export * from './redis';
export * from './upstash';
