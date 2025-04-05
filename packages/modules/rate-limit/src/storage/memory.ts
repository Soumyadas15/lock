import { LRUCache } from 'lru-cache';
import { RateLimitRecord, RateLimitStore } from '../types';

export class MemoryStore implements RateLimitStore {
  private cache: LRUCache<string, RateLimitRecord>;

  constructor(options: { max: number; ttl: number }) {
    this.cache = new LRUCache<string, RateLimitRecord>({
      max: options.max || 10000,
      ttl: options.ttl || 3600000,
      ttlAutopurge: true,
    });
  }

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(key: string): Promise<RateLimitRecord | null> {
    const record = this.cache.get(key) || null;
    return record;
  }

  async set(key: string, value: RateLimitRecord): Promise<void> {
    this.cache.set(key, value);
    return Promise.resolve();
  }

  async increment(key: string, value: number = 1): Promise<RateLimitRecord> {
    const now = Date.now();
    let record = this.cache.get(key);

    if (!record) {
      record = {
        count: value,
        firstRequest: now,
        lastRequest: now,
        history: [now],
      };
    } else {
      record.count += value;
      record.lastRequest = now;

      if (!record.history) {
        record.history = [];
      }

      record.history.push(now);
    }

    this.cache.set(key, record);
    return record;
  }

  async reset(key: string): Promise<void> {
    this.cache.delete(key);
    return Promise.resolve();
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }

  async addToHistory(key: string, timestamp: number): Promise<void> {
    const record = this.cache.get(key);

    if (record) {
      if (!record.history) {
        record.history = [];
      }
      record.history.push(timestamp);
      this.cache.set(key, record);
    }

    return Promise.resolve();
  }

  async getWindowHistory(key: string, startTime: number): Promise<number[]> {
    const record = this.cache.get(key);
    const history = record?.history || [];
    const filtered = history.filter(time => time >= startTime);
    return filtered;
  }
}
