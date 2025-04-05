import { RateLimitConfig, RateLimitRecord, RateLimitStore } from '../types';

export class UpstashStore implements RateLimitStore {
  private client: any;
  private keyPrefix: string;
  private config: any;

  constructor(config: RateLimitConfig) {
    this.keyPrefix = config.upstash?.keyPrefix || 'ratelimit:';
    this.config = config.upstash;
  }

  async init(): Promise<void> {
    try {
      const { Redis } = await import('@upstash/redis');

      this.client = new Redis({
        url: this.config.url,
        token: this.config.token,
      });

      await this.client.ping();
    } catch (error) {
      console.error('Failed to initialize Upstash client:', error);
      throw new Error('Upstash initialization failed');
    }
  }

  async get(key: string): Promise<RateLimitRecord | null> {
    try {
      const data = await this.client.get(this.keyPrefix + key);

      if (!data) return null;

      if (typeof data === 'string') {
        try {
          return JSON.parse(data);
        } catch (parseError) {
          console.error('Error parsing JSON from Upstash:', parseError);
          return null;
        }
      } else if (typeof data === 'object') {
        return data as RateLimitRecord;
      }

      return null;
    } catch (error) {
      console.error('Upstash get error:', error);
      return null;
    }
  }

  async set(key: string, value: RateLimitRecord): Promise<void> {
    try {
      const ttl = Math.ceil((value.firstRequest + 3600000 - Date.now()) / 1000);
      const stringValue = JSON.stringify(value);

      await this.client.set(this.keyPrefix + key, stringValue, { ex: ttl > 0 ? ttl : 60 });
    } catch (error) {
      console.error('Upstash set error:', error);
    }
  }

  async increment(key: string, value: number = 1): Promise<RateLimitRecord> {
    try {
      const fullKey = this.keyPrefix + key;
      const now = Date.now();

      const [exists] = await this.client.pipeline().exists(fullKey).exec();

      if (!exists) {
        const record: RateLimitRecord = {
          count: value,
          firstRequest: now,
          lastRequest: now,
          history: [now],
        };

        await this.client.set(fullKey, JSON.stringify(record), { ex: 3600 });
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
          redis.call('set', KEYS[1], cjson.encode(record), 'EX', 3600)
          return cjson.encode(record)
        `;

        const result = await this.client.eval(
          script,
          [fullKey],
          [value.toString(), now.toString()]
        );

        if (typeof result === 'string') {
          try {
            return JSON.parse(result);
          } catch (parseError) {
            console.error('Error parsing script result:', parseError);
            throw new Error('Failed to parse increment result');
          }
        } else if (typeof result === 'object') {
          return result as RateLimitRecord;
        }

        throw new Error('Invalid result type from Upstash script');
      }
    } catch (error) {
      console.error('Upstash increment error:', error);

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
      console.error('Upstash reset error:', error);
    }
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }

  async addToHistory(key: string, timestamp: number): Promise<void> {
    try {
      const historyKey = this.keyPrefix + key + ':history';
      await this.client.lpush(historyKey, timestamp.toString());
      await this.client.expire(historyKey, 3600);
    } catch (error) {
      console.error('Upstash addToHistory error:', error);
    }
  }

  async getWindowHistory(key: string, startTime: number): Promise<number[]> {
    try {
      const historyKey = this.keyPrefix + key + ':history';
      const allItems = await this.client.lrange(historyKey, 0, -1);

      if (!Array.isArray(allItems)) {
        return [];
      }

      return allItems
        .map(item => (typeof item === 'string' ? parseInt(item, 10) : (item as number)))
        .filter(time => !isNaN(time) && time >= startTime);
    } catch (error) {
      console.error('Upstash getWindowHistory error:', error);
      return [];
    }
  }
}
