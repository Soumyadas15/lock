import { VPNCacheStore } from '.';
import { VPNDetectionConfig, VPNDetectionResult } from '../types';

export class UpstashVPNCacheStore implements VPNCacheStore {
  private client: any;
  private keyPrefix: string;
  private config: any;
  private ttl: number;

  constructor(config: VPNDetectionConfig) {
    this.keyPrefix = config.upstash?.keyPrefix || 'vpncache:';
    this.config = config.upstash;
    this.ttl = Math.floor((config.cacheTtl || 3600000) / 1000);
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

  async get(ip: string): Promise<VPNDetectionResult | null> {
    try {
      const data = await this.client.get(this.keyPrefix + ip);

      if (!data) return null;
      if (typeof data === 'string') {
        try {
          return JSON.parse(data);
        } catch (parseError) {
          console.error('Error parsing JSON from Upstash:', parseError);
          return null;
        }
      } else if (typeof data === 'object') {
        return data as VPNDetectionResult;
      }

      return null;
    } catch (error) {
      console.error('Upstash get error:', error);
      return null;
    }
  }

  async set(ip: string, value: VPNDetectionResult): Promise<void> {
    try {
      const stringValue = JSON.stringify(value);
      await this.client.set(this.keyPrefix + ip, stringValue, { ex: this.ttl });
    } catch (error) {
      console.error('Upstash set error:', error);
    }
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }
}
