import { GeoInfo, GeoBlockConfig } from '../types';
import { RedisGeoCacheStore } from './redis';
import { UpstashGeoCacheStore } from './upstash';
import { MemoryGeoCacheStore } from './memory';

export interface GeoCacheStore {
  init(): Promise<void>;
  get(ip: string): Promise<GeoInfo | null>;
  set(ip: string, value: GeoInfo): Promise<void>;
  close(): Promise<void>;
}

export async function createCacheStore(config: GeoBlockConfig): Promise<GeoCacheStore> {
  const storageType = config.storage || 'memory';
  let store: GeoCacheStore;

  switch (storageType) {
    case 'redis':
      if (!config.redis) {
        throw new Error('Redis configuration is required when using Redis storage');
      }
      store = new RedisGeoCacheStore(config);
      break;

    case 'upstash':
      if (!config.upstash) {
        throw new Error('Upstash configuration is required when using Upstash storage');
      }
      store = new UpstashGeoCacheStore(config);
      break;

    case 'memory':
    default:
      store = new MemoryGeoCacheStore(config);
      break;
  }

  await store.init();
  return store;
}

export * from './memory';
export * from './redis';
export * from './upstash';
