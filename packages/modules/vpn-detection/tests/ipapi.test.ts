import { describe, it, expect, beforeEach, vi } from 'vitest';
import axios from 'axios';
import { IPAPIProvider } from '../src/providers/ipapi';
import { VPNDetectionConfig } from '../src/types';

vi.mock('axios');
const mockedAxios = axios as any;

describe('IPAPIProvider', () => {
  const config: VPNDetectionConfig = { apiKey: '' };
  let provider: IPAPIProvider;

  beforeEach(() => {
    provider = new IPAPIProvider(config);
    vi.resetAllMocks();
  });

  describe('Normal Tests', () => {
    it('should return a valid detection result on a successful API call', async () => {
      const ip = '1.2.3.4';
      const apiResponse = {
        data: {
          status: 'success',
          continent: 'North America',
          continentCode: 'NA',
          country: 'United States',
          countryCode: 'US',
          region: 'CA',
          regionName: 'California',
          city: 'Mountain View',
          district: '',
          zip: '94043',
          lat: 37.386,
          lon: -122.084,
          timezone: 'America/Los_Angeles',
          offset: -480,
          currency: 'USD',
          isp: 'Google LLC',
          org: 'Google',
          as: 'AS15169 Google LLC',
          asname: 'Google LLC',
          reverse: 'google.com',
          mobile: false,
          proxy: true,
          hosting: false,
          query: ip,
        },
      };

      mockedAxios.get.mockResolvedValue(apiResponse);

      const result = await provider.checkIp(ip);
      expect(result.isProxy).toBe(true);
      expect(result.vpnScore).toBe(1);
      expect(result.providerData && result.providerData.country).toBe('United States');
    });
  });

  describe('Penetration Tests', () => {
    it('should throw an error when API returns non-success status', async () => {
      const ip = '1.2.3.4';
      const apiResponse = {
        data: {
          status: 'fail',
          message: 'invalid query',
          continent: '',
          continentCode: '',
          country: '',
          countryCode: '',
          region: '',
          regionName: '',
          city: '',
          district: '',
          zip: '',
          lat: 0,
          lon: 0,
          timezone: '',
          offset: 0,
          currency: '',
          isp: '',
          org: '',
          as: '',
          asname: '',
          reverse: '',
          mobile: false,
          proxy: false,
          hosting: false,
          query: ip,
        },
      };

      mockedAxios.get.mockResolvedValue(apiResponse);
      await expect(provider.checkIp(ip)).rejects.toThrow('invalid query');
    });

    it('should throw an error when the axios call fails', async () => {
      const ip = '1.2.3.4';
      mockedAxios.get.mockRejectedValue(new Error('Network error'));

      await expect(provider.checkIp(ip)).rejects.toThrow('Network error');
    });
  });
});
