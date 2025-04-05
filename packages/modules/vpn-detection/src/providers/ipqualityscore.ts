import axios from 'axios';
import { VPNDetectionConfig, VPNDetectionProviderInterface, VPNDetectionResult } from '../types';

interface IPQualityScoreResponse {
  success: boolean;
  message?: string;
  fraud_score: number;
  country_code: string;
  region: string;
  city: string;
  ISP: string;
  ASN: number;
  organization: string;
  is_crawler: boolean;
  timezone: string;
  mobile: boolean;
  host: string;
  proxy: boolean;
  vpn: boolean;
  tor: boolean;
  active_vpn: boolean;
  active_tor: boolean;
  recent_abuse: boolean;
  bot_status: boolean;
  connection_type: string;
  abuse_velocity: string;
  zip_code: string;
  latitude: number;
  longitude: number;
  request_id: string;
  transient?: boolean;
  residential?: boolean;
  public_access_point?: boolean;
  hosting?: boolean;
  [key: string]: any;
}

export class IPQualityScoreProvider implements VPNDetectionProviderInterface {
  private apiKey: string;
  private baseUrl: string = 'https://www.ipqualityscore.com/api/json/ip';
  private strictMode: boolean;
  private extraParams: Record<string, any>;

  constructor(private config: VPNDetectionConfig) {
    this.apiKey = config.apiKey || '';
    this.strictMode = config.customProviderOptions?.strictMode || false;
    this.extraParams = config.customProviderOptions?.extraParams || {};
  }

  async init(): Promise<void> {
    if (!this.apiKey) {
      throw new Error('IPQualityScore API key is required');
    }
  }

  async checkIp(ip: string): Promise<VPNDetectionResult> {
    try {
      const params = {
        strictness: this.strictMode ? 1 : 0,
        allow_public_access_points: true,
        fast: false,
        mobile: false,
        ...this.extraParams,
      };

      const url = `${this.baseUrl}/${this.apiKey}/${ip}`;

      const response = await axios.get<IPQualityScoreResponse>(url, { params });

      if (!response.data.success) {
        throw new Error(response.data.message || 'IPQualityScore API request failed');
      }

      return {
        isVpn: response.data.vpn || response.data.active_vpn || false,
        vpnScore: response.data.vpn ? response.data.fraud_score / 100 : 0,
        isProxy: response.data.proxy || false,
        proxyScore: response.data.proxy ? response.data.fraud_score / 100 : 0,
        isTor: response.data.tor || response.data.active_tor || false,
        torScore: response.data.tor ? 1 : 0,
        isDatacenter: response.data.hosting || false,
        datacenterScore: response.data.hosting ? 1 : 0,
        providerData: {
          fraudScore: response.data.fraud_score,
          country: response.data.country_code,
          isp: response.data.ISP,
          organization: response.data.organization,
          asn: response.data.ASN,
          connectionType: response.data.connection_type,
          isBot: response.data.bot_status,
          isMobile: response.data.mobile,
          isResidential: response.data.residential,
          isPublicAccessPoint: response.data.public_access_point,
          recentAbuse: response.data.recent_abuse,
        },
        timestamp: Date.now(),
      };
    } catch (error) {
      console.error(`IPQualityScore API error: ${(error as Error).message}`);
      throw error;
    }
  }
}
