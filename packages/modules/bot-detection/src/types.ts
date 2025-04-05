import { SecurityEvent } from '@lock-sdk/core';

export enum BotDetectorEventType {
  BOT_DETECTED = 'bot.detected',
  SUSPICIOUS_BEHAVIOR = 'suspicious.behavior',
  INVALID_USER_AGENT = 'invalid.user.agent',
  SUSPICIOUS_HEADERS = 'suspicious.headers',
  BROWSER_FINGERPRINT_MISMATCH = 'browser.fingerprint.mismatch',
}

export type BotStorage = 'memory' | 'redis' | 'upstash';

export interface BotDetectorConfig {
  enabled: boolean;
  captchaRedirectUrl: string;

  storage?: BotStorage;

  userAgent?: {
    enabled: boolean;
    blockEmpty: boolean;
    blockedPatterns: string[];
    requiredPatterns?: string[];
  };

  behavior?: {
    enabled: boolean;
    minRequestInterval?: number;
    maxSessionRequests?: number;
    sessionDuration?: number;
    checkPathPatterns?: boolean;
  };

  headers?: {
    enabled: boolean;
    required?: string[];
    suspicious?: Record<string, string[]>;
    checkBrowserFingerprint?: boolean;
  };

  fingerprinting?: {
    enabled: boolean;
    cookieName?: string;
    hashHeaderName?: string;
  };

  cache?: {
    ttl: number;
    size: number;
  };

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

  redirectStatusCode?: number;
  redirectMessage?: string;
  includeOriginalUrl?: boolean;
  allowQueryParamBypass?: boolean;
  bypassParam?: string;
  bypassValue?: string;
  failBehavior?: 'open' | 'closed';
}

export interface RequestMetadata {
  timestamp: number;
  ip: string;
  userAgent?: string;
  path: string;
  method: string;
  headers: Record<string, string | string[] | undefined>;
  fingerprint?: string;
}

export interface BotDetectionResult {
  timestamp: number;
  isBot: boolean;
  reason?: string;
  score?: number;
  detectionMethod?: string;
  event?: SecurityEvent;
}
