export enum IPFilterEventType {
  IP_BLOCKED = 'ip.blocked',
  IP_ALLOWED = 'ip.allowed',
  IP_FILTER_ERROR = 'ip.error',
}

export type IPStorage = 'memory' | 'redis' | 'upstash';

export interface IPFilterConfig {
  mode: 'blacklist' | 'whitelist';
  ipAddresses: string[];
  storage?: IPStorage;
  ipHeaders?: string[];
  useRemoteAddress?: boolean;
  blockStatusCode?: number;
  blockMessage?: string;
  cacheTtl?: number;
  cacheSize?: number;
  failBehavior?: 'open' | 'closed';
  logFunction?: (message: string, data?: any) => void;
  logAllowed?: boolean;
  logBlocked?: boolean;

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
