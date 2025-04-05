import { CSRFConfig, TokenStorage, TokenStorageProvider } from '../types';
import { MemoryStorage } from './memory';
import { RedisStorage } from './redis';

const STORAGE_INSTANCES = new Map<string, TokenStorageProvider>();

export function createStorage(config: CSRFConfig): TokenStorageProvider {
  const key = `storage:${config.storage}`;

  if (STORAGE_INSTANCES.has(key)) {
    return STORAGE_INSTANCES.get(key)!;
  }

  let storage: TokenStorageProvider;

  switch (config.storage) {
    case 'redis':
      storage = new RedisStorage(config.redisOptions);
      break;
    case 'memory':
    default:
      storage = new MemoryStorage();
  }

  STORAGE_INSTANCES.set(key, storage);
  return storage;
}

export * from './memory';
export * from './redis';
