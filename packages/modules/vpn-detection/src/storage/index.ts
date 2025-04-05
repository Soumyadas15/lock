import { VPNDetectionConfig, VPNDetectionResult } from '../types';
import { MemoryVPNCacheStore } from './memory';
import { RedisVPNCacheStore } from './redis';
import { UpstashVPNCacheStore } from './upstash';

export interface VPNCacheStore {
  init(): Promise<void>;
  get(ip: string): Promise<VPNDetectionResult | null>;
  set(ip: string, value: VPNDetectionResult): Promise<void>;
  close(): Promise<void>;
}

export async function createCacheStore(config: VPNDetectionConfig): Promise<VPNCacheStore> {
  const storageType = config.storage || 'memory';
  let store: VPNCacheStore;

  switch (storageType) {
    case 'redis':
      if (!config.redis) {
        throw new Error('Redis configuration is required when using Redis storage');
      }
      store = new RedisVPNCacheStore(config);
      break;

    case 'upstash':
      if (!config.upstash) {
        throw new Error('Upstash configuration is required when using Upstash storage');
      }
      store = new UpstashVPNCacheStore(config);
      break;

    case 'memory':
    default:
      store = new MemoryVPNCacheStore(config);
      break;
  }

  await store.init();
  return store;
}

export * from './memory';
export * from './redis';
export * from './upstash';
