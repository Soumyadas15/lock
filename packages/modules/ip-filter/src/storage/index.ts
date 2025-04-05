import { IPFilterConfig } from '../types';
import { MemoryIPCacheStore } from './memory';
import { RedisIPCacheStore } from './redis';
import { UpstashIPCacheStore } from './upstash';

export interface IPCacheStore {
  init(): Promise<void>;
  get(key: string): Promise<boolean | null>;
  set(key: string, value: boolean): Promise<void>;
  close(): Promise<void>;
}

export async function createCacheStore(config: IPFilterConfig): Promise<IPCacheStore> {
  const storageType = config.storage || 'memory';
  let store: IPCacheStore;

  switch (storageType) {
    case 'redis':
      if (!config.redis) {
        throw new Error('Redis configuration is required when using Redis storage');
      }
      store = new RedisIPCacheStore(config);
      break;

    case 'upstash':
      if (!config.upstash) {
        throw new Error('Upstash configuration is required when using Upstash storage');
      }
      store = new UpstashIPCacheStore(config);
      break;

    case 'memory':
    default:
      store = new MemoryIPCacheStore(config);
      break;
  }

  await store.init();
  return store;
}

export * from './memory';
export * from './redis';
export * from './upstash';
