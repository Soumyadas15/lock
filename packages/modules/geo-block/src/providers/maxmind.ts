import * as maxmind from 'maxmind';
import * as fs from 'fs';
import { GeoLookupProvider, GeoInfo, GeoBlockConfig } from '../types';

export class MaxMindProvider implements GeoLookupProvider {
  private reader: any;
  private dbPath: string;
  private initialized = false;

  constructor(config: GeoBlockConfig) {
    if (!config.maxmindDbPath) {
      throw new Error('MaxMind database path must be provided');
    }
    this.dbPath = config.maxmindDbPath;
  }

  async init(): Promise<void> {
    if (this.initialized) return;
    try {
      if (!fs.existsSync(this.dbPath)) {
        throw new Error(`MaxMind database file not found at: ${this.dbPath}`);
      }
      this.reader = await maxmind.open(this.dbPath);
      this.initialized = true;
    } catch (error) {
      throw new Error(
        `Failed to initialize MaxMind database: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async lookup(ip: string): Promise<GeoInfo> {
    if (!this.initialized) {
      await this.init();
    }
    try {
      const result = this.reader.get(ip);
      if (!result) {
        return {};
      }
      return {
        country: result.country?.iso_code,
        region: result.subdivisions?.[0]?.iso_code,
        city: result.city?.names?.en,
        latitude: result.location?.latitude,
        longitude: result.location?.longitude,
      };
    } catch (error) {
      console.error(`Error looking up IP ${ip}:`, error);
      return {};
    }
  }
}
