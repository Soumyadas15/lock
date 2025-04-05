import * as ipaddr from 'ipaddr.js';

export function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const addr = ipaddr.parse(ip);
    const range = ipaddr.parseCIDR(cidr);

    return addr.kind() === range[0].kind() && addr.match(range);
  } catch (error) {
    console.error(`Error checking IP ${ip} against CIDR ${cidr}:`, error);
    return false;
  }
}

export function ipEquals(ip1: string, ip2: string): boolean {
  try {
    const addr1 = ipaddr.parse(ip1);
    const addr2 = ipaddr.parse(ip2);
    return addr1.kind() === addr2.kind() && addr1.toString() === addr2.toString();
  } catch (error) {
    console.error(`Error comparing IPs ${ip1} and ${ip2}:`, error);
    return false;
  }
}

export function isIpInList(ip: string, list: string[]): boolean {
  try {
    const parsedIp = ipaddr.parse(ip);
    const normalizedIp = parsedIp.toString();

    return list.some(entry => {
      if (entry.includes('/')) {
        return ipInCidr(normalizedIp, entry);
      }
      return ipEquals(normalizedIp, entry);
    });
  } catch (error) {
    console.error(`Error checking IP ${ip} against list:`, error);
    return false;
  }
}

export function normalizeIp(ip: string): string | null {
  try {
    return ipaddr.parse(ip).toString();
  } catch (error) {
    return null;
  }
}

export function isValidIpOrCidr(input: string): boolean {
  try {
    if (input.includes('/')) {
      ipaddr.parseCIDR(input);
    } else {
      ipaddr.parse(input);
    }
    return true;
  } catch (error) {
    return false;
  }
}
