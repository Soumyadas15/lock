import { RateLimitConfig, RateLimitRecord, RateLimitStore } from '../types';

export class RedisStore implements RateLimitStore {
  private client: any;
  private keyPrefix: string;
  private config: any;

  constructor(config: RateLimitConfig) {
    this.keyPrefix = config.redis?.keyPrefix || 'ratelimit:';
    this.config = config.redis;
  }

  async init(): Promise<void> {
    try {
      const { createClient } = await import('redis');
      if (this.config.url) {
        this.client = createClient({ url: this.config.url });
      } else {
        this.client = createClient({
          socket: {
            host: this.config.host || 'localhost',
            port: this.config.port || 6379,
          },
          username: this.config.username,
          password: this.config.password,
          database: this.config.database || 0,
        });
      }

      await this.client.connect();
      this.client.on('error', (err: Error) => {
        console.error('Redis client error:', err);
      });
    } catch (error) {
      console.error('Failed to initialize Redis client:', error);
      throw new Error('Redis initialization failed');
    }
  }

  async get(key: string): Promise<RateLimitRecord | null> {
    try {
      const data = await this.client.get(this.keyPrefix + key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      console.error('Redis get error:', error);
      return null;
    }
  }

  async set(key: string, value: RateLimitRecord): Promise<void> {
    try {
      const ttl = Math.ceil((value.firstRequest + 3600000 - Date.now()) / 1000);
      await this.client.set(this.keyPrefix + key, JSON.stringify(value), {
        EX: ttl > 0 ? ttl : 60,
      });
    } catch (error) {
      console.error('Redis set error:', error);
    }
  }

  async increment(key: string, value: number = 1): Promise<RateLimitRecord> {
    try {
      const fullKey = this.keyPrefix + key;
      const now = Date.now();
      const exists = await this.client.exists(fullKey);

      if (!exists) {
        const record: RateLimitRecord = {
          count: value,
          firstRequest: now,
          lastRequest: now,
          history: [now],
        };

        await this.client.set(fullKey, JSON.stringify(record), { EX: 3600 }); // 1 hour expiry
        return record;
      } else {
        const script = `
          local record = cjson.decode(redis.call('get', KEYS[1]))
          record.count = record.count + ARGV[1]
          record.lastRequest = ARGV[2]
          if record.history then
            table.insert(record.history, ARGV[2])
          else
            record.history = {ARGV[2]}
          end
          redis.call('set', KEYS[1], cjson.encode(record))
          return cjson.encode(record)
        `;

        const result = await this.client.eval(script, {
          keys: [fullKey],
          arguments: [value.toString(), now.toString()],
        });

        return JSON.parse(result);
      }
    } catch (error) {
      console.error('Redis increment error:', error);
      const record = (await this.get(key)) || {
        count: 0,
        firstRequest: Date.now(),
        lastRequest: Date.now(),
        history: [],
      };

      record.count += value;
      record.lastRequest = Date.now();
      if (record.history) {
        record.history.push(record.lastRequest);
      } else {
        record.history = [record.lastRequest];
      }

      await this.set(key, record);
      return record;
    }
  }

  async reset(key: string): Promise<void> {
    try {
      await this.client.del(this.keyPrefix + key);
      await this.client.del(this.keyPrefix + key + ':history');
    } catch (error) {
      console.error('Redis reset error:', error);
    }
  }

  async close(): Promise<void> {
    try {
      if (this.client) {
        await this.client.quit();
      }
    } catch (error) {
      console.error('Redis close error:', error);
    }
  }

  async addToHistory(key: string, timestamp: number): Promise<void> {
    try {
      const historyKey = this.keyPrefix + key + ':history';
      await this.client.lPush(historyKey, timestamp.toString());
      await this.client.expire(historyKey, 3600); // 1 hour expiry
    } catch (error) {
      console.error('Redis addToHistory error:', error);
    }
  }

  async getWindowHistory(key: string, startTime: number): Promise<number[]> {
    try {
      const historyKey = this.keyPrefix + key + ':history';
      const allItems = await this.client.lRange(historyKey, 0, -1);
      return allItems
        .map((item: string) => parseInt(item, 10))
        .filter((time: number) => time >= startTime);
    } catch (error) {
      console.error('Redis getWindowHistory error:', error);
      return [];
    }
  }
}
