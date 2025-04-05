export enum GeoBlockEventType {
  GEO_BLOCKED = 'geo.blocked',
}

export type GeoStorage = 'memory' | 'redis' | 'upstash';

export interface GeoBlockConfig {
  mode: 'whitelist' | 'blacklist';
  countries: string[];
  provider: 'maxmind' | 'ipapi' | 'ipstack';
  storage?: GeoStorage;
  maxmindDbPath?: string;
  apiKey?: string;
  customLookup?: (ip: string) => Promise<GeoInfo>;
  ipHeaders?: string[];
  useRemoteAddress?: boolean;
  blockStatusCode?: number;
  blockMessage?: string;
  cacheTtl?: number;
  cacheSize?: number;
  failBehavior?: 'open' | 'closed';
  redis?: {
    url?: string;
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    database?: number;
    keyPrefix?: string;
  };
  upstash?: {
    url: string;
    token: string;
    keyPrefix?: string;
  };
}

export interface GeoInfo {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
}

export interface GeoLookupProvider {
  init(): Promise<void>;
  lookup(ip: string): Promise<GeoInfo>;
}
