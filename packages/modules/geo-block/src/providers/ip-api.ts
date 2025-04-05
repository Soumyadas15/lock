import { GeoLookupProvider, GeoInfo, GeoBlockConfig } from '../types';

export class IpApiProvider implements GeoLookupProvider {
  private apiKey?: string;

  constructor(config: GeoBlockConfig) {
    this.apiKey = config.apiKey;
  }

  async init(): Promise<void> {}

  async lookup(ip: string): Promise<GeoInfo> {
    try {
      const url = this.apiKey
        ? `https://pro.ip-api.com/json/${ip}?key=${this.apiKey}&fields=status,message,countryCode,region,city,lat,lon`
        : `http://ip-api.com/json/${ip}?fields=status,message,countryCode,region,city,lat,lon`;

      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`IP-API request failed with status: ${response.status}`);
      }

      const data = await response.json();
      if (data.status === 'success') {
        return {
          country: data.countryCode,
          region: data.region,
          city: data.city,
          latitude: data.lat,
          longitude: data.lon,
        };
      } else {
        console.warn(`IP-API lookup failed: ${data.message}`);
        return {};
      }
    } catch (error) {
      console.error(`Error looking up IP ${ip} with IP-API:`, error);
      return {};
    }
  }
}
