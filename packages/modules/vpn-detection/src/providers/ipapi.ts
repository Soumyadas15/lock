import axios from 'axios';
import { VPNDetectionConfig, VPNDetectionProviderInterface, VPNDetectionResult } from '../types';

interface IPAPIResponse {
  status: string;
  message?: string;
  continent: string;
  continentCode: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  district: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  offset: number;
  currency: string;
  isp: string;
  org: string;
  as: string;
  asname: string;
  reverse: string;
  mobile: boolean;
  proxy: boolean;
  hosting: boolean;
  query: string;
}

export class IPAPIProvider implements VPNDetectionProviderInterface {
  private baseUrl: string = 'http://ip-api.com/json';
  private proUrl: string = 'http://pro.ip-api.com/json';
  private useProVersion: boolean;
  private apiKey: string;
  private fields: string[];

  constructor(private config: VPNDetectionConfig) {
    this.useProVersion = !!config.apiKey;
    this.apiKey = config.apiKey || '';
    this.fields = [
      'status',
      'message',
      'continent',
      'continentCode',
      'country',
      'countryCode',
      'region',
      'regionName',
      'city',
      'district',
      'zip',
      'lat',
      'lon',
      'timezone',
      'offset',
      'currency',
      'isp',
      'org',
      'as',
      'asname',
      'reverse',
      'mobile',
      'proxy',
      'hosting',
      'query',
    ];
  }

  async init(): Promise<void> {}

  async checkIp(ip: string): Promise<VPNDetectionResult> {
    try {
      const url = this.useProVersion
        ? `${this.proUrl}/${ip}?key=${this.apiKey}&fields=${this.fields.join(',')}`
        : `${this.baseUrl}/${ip}?fields=${this.fields.join(',')}`;

      const response = await axios.get<IPAPIResponse>(url);

      if (response.data.status !== 'success') {
        throw new Error(response.data.message || 'IP-API request failed');
      }

      const isProxyOrVPN = response.data.proxy;
      const isHosting = response.data.hosting;
      const proxyScore = isProxyOrVPN ? 1 : 0;
      const datacenterScore = isHosting ? 1 : 0;
      const orgLower = (response.data.org || '').toLowerCase();
      const isTor =
        isProxyOrVPN &&
        (orgLower.includes('tor') || orgLower.includes('exit') || orgLower.includes('node'));
      const torScore = isTor ? 0.8 : 0;

      return {
        isVpn: isProxyOrVPN,
        vpnScore: proxyScore,
        isProxy: isProxyOrVPN,
        proxyScore,
        isTor,
        torScore,
        isDatacenter: isHosting,
        datacenterScore,
        providerData: {
          country: response.data.country,
          countryCode: response.data.countryCode,
          isp: response.data.isp,
          organization: response.data.org,
          asn: response.data.as,
          asnName: response.data.asname,
          city: response.data.city,
          region: response.data.regionName,
          timezone: response.data.timezone,
          isMobile: response.data.mobile,
        },
        timestamp: Date.now(),
      };
    } catch (error) {
      console.error(`IP-API error: ${(error as Error).message}`);
      throw error;
    }
  }
}
