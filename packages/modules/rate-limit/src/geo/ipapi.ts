import { GeoLocationProvider } from '../types';

const countryCache = new Map<string, { country: string; timestamp: number }>();
let CACHE_TTL = 24 * 60 * 60 * 1000;

export class IpApiProvider implements GeoLocationProvider {
  constructor(private options: { cacheTtl?: number } = {}) {
    if (options.cacheTtl) {
      CACHE_TTL = options.cacheTtl;
    }
  }

  async lookupCountry(ip: string): Promise<string | null> {
    try {
      const now = Date.now();
      const cached = countryCache.get(ip);

      if (cached && now - cached.timestamp < CACHE_TTL) {
        return cached.country;
      }

      console.log(`[GeoIP] Looking up country for IP: ${ip}`);
      const response = await fetch(
        `http://ip-api.com/json/${ip}?fields=status,message,countryCode`
      );
      const data = await response.json();

      if (data && data.status === 'success' && data.countryCode) {
        countryCache.set(ip, { country: data.countryCode, timestamp: now });
        return data.countryCode;
      }
      return null;
    } catch (error) {
      console.error(`[GeoIP] Error looking up country for IP ${ip}:`, error);
      return null;
    }
  }
}
