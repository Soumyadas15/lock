export enum VPNDetectionEventType {
  VPN_DETECTED = 'vpn.detected',
  NO_VPN_DETECTED = 'vpn.not.detected',
  VPN_DETECTION_ERROR = 'vpn.error',
}

export type VPNDetectionProvider = 'ipqualityscore' | 'ipapi';
export type VPNStorage = 'memory' | 'redis' | 'upstash';

export interface VPNDetectionResult {
  isVpn: boolean;
  vpnScore: number;
  isProxy: boolean;
  proxyScore: number;
  isTor: boolean;
  torScore: number;
  isDatacenter: boolean;
  datacenterScore: number;
  providerData?: Record<string, any>;
  timestamp: number;
}

export interface VPNDetectionProviderInterface {
  init(): Promise<void>;
  checkIp(ip: string): Promise<VPNDetectionResult>;
}

export interface VPNDetectionConfig {
  ipHeaders?: string[];
  useRemoteAddress?: boolean;
  blockStatusCode?: number;
  blockMessage?: string;
  provider?: VPNDetectionProvider;

  storage?: VPNStorage;

  cacheTtl?: number;
  cacheSize?: number;
  vpnScoreThreshold?: number;
  proxyScoreThreshold?: number;
  datacenterScoreThreshold?: number;
  torScoreThreshold?: number;
  checkVpn?: boolean;
  checkProxy?: boolean;
  checkDatacenter?: boolean;
  checkTor?: boolean;
  failBehavior?: 'open' | 'closed';
  blockTor?: boolean;
  blockVpn?: boolean;
  blockProxy?: boolean;
  blockDatacenter?: boolean;
  apiKey?: string;
  customProvider?: VPNDetectionProviderInterface;
  customProviderOptions?: Record<string, any>;
  logFunction?: (message: string, data?: any) => void;
  logResults?: boolean;

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
}
