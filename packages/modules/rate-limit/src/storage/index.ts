import { RateLimitConfig, RateLimitStore } from '../types';
import { MemoryStore } from './memory';
import { RedisStore } from './redis';
import { UpstashStore } from './upstash';

export async function createStore(config: RateLimitConfig): Promise<RateLimitStore> {
  const storageType = config.storage || 'memory';
  let store: RateLimitStore;

  switch (storageType) {
    case 'redis':
      if (!config.redis) {
        throw new Error('Redis configuration is required when using Redis storage');
      }
      store = new RedisStore(config);
      break;

    case 'upstash':
      if (!config.upstash) {
        throw new Error('Upstash configuration is required when using Upstash storage');
      }
      store = new UpstashStore(config);
      break;

    case 'memory':
    default:
      store = new MemoryStore(config.memoryOptions || { max: 10000, ttl: 3600000 });
      break;
  }

  await store.init();
  return store;
}

export { MemoryStore } from './memory';
export { RedisStore } from './redis';
export { UpstashStore } from './upstash';
