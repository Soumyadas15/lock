import { SecurityContext } from '@lock-sdk/core';

export type RateLimitStrategy =
  | 'fixed-window'
  | 'sliding-window'
  | 'token-bucket'
  | 'leaky-bucket'
  | 'adaptive';

export type RateLimitStorage = 'memory' | 'redis' | 'upstash';

export type GeoProvider = 'ipapi' | 'maxmind';

export enum RateLimitEventType {
  RATE_LIMITED = 'rate.limited',
  RATE_LIMIT_WARNING = 'rate.limit.warning',
  RATE_LIMIT_ADAPTIVE_ESCALATION = 'rate.limit.adaptive.escalation',
  DDOS_PROTECTION_TRIGGERED = 'ddos.protection.triggered',
}

export interface RateLimitKey {
  identifier: string;
  resource?: string;
  country?: string;
}

export interface RateLimitRecord {
  count: number;
  firstRequest: number;
  lastRequest: number;
  history?: number[];
  tokens?: number;
  warningIssued?: boolean;
  ddosScore?: number;
}

export interface RateLimitResult {
  passed: boolean;
  remaining?: number;
  limit?: number;
  retry?: number;
  reason?: string;
  data?: any;
}

export interface RateLimitConfig {
  limit: number;
  windowMs: number;
  strategy?: RateLimitStrategy;
  storage?: RateLimitStorage;

  resources?: {
    [resource: string]: {
      limit: number;
      windowMs: number;
    };
  };

  countryLimits?: {
    [country: string]: {
      limit: number;
      windowMs: number;
    };
  };

  geoProvider?: {
    type: GeoProvider;
    dbPath?: string;
    cacheSize?: number;
    cacheTtl?: number;
  };

  adaptive?: {
    enabled: boolean;
    thresholds: {
      normal: number;
      elevated: number;
      high: number;
      extreme: number;
    };
    escalationPeriod: number;
    cooldownPeriod: number;
  };

  ddosPrevention?: {
    enabled: boolean;
    requestRateThreshold: number;
    burstThreshold: number;
    banDurationMs: number;
    ipReputation?: boolean;
    behavioralAnalysis?: boolean;
    challengeMode?: boolean;
  };

  headers?: boolean;
  standardHeaders?: boolean;
  headerLimit?: string;
  headerRemaining?: string;
  headerReset?: string;
  statusCode?: number;
  message?: string;

  ipHeaders?: string[];
  useRemoteAddress?: boolean;

  redis?: {
    url?: string;
    host?: string;
    port?: number;
    password?: string;
    username?: string;
    database?: number;
    keyPrefix?: string;
  };
  upstash?: {
    url: string;
    token: string;
    keyPrefix?: string;
  };
  memoryOptions?: {
    max: number;
    ttl: number;
  };

  skipFunction?: (context: SecurityContext) => boolean | Promise<boolean>;
  keyGenerator?: (context: SecurityContext) => string | Promise<string>;
  handler?: (context: SecurityContext, info: any) => void | Promise<void>;
}

export interface RateLimitStore {
  init(): Promise<void>;
  get(key: string): Promise<RateLimitRecord | null>;
  set(key: string, value: RateLimitRecord): Promise<void>;
  increment(key: string, value?: number): Promise<RateLimitRecord>;
  reset(key: string): Promise<void>;
  close(): Promise<void>;

  addToHistory?(key: string, timestamp: number): Promise<void>;
  getWindowHistory?(key: string, startTime: number): Promise<number[]>;
}

export interface GeoLocationProvider {
  lookupCountry(ip: string): Promise<string | null>;
}
