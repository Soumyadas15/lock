export function extractIp(
  req: any,
  ipHeaders: string[] = ['x-forwarded-for', 'cf-connecting-ip', 'x-real-ip'],
  useRemoteAddress: boolean = true
): string | undefined {
  if (!req) return undefined;
  const headers = req.headers || {};
  for (const header of ipHeaders) {
    const headerValue = headers[header] || headers[header.toLowerCase()];
    if (headerValue) {
      const ips = Array.isArray(headerValue)
        ? headerValue[0]?.split(',')[0]?.trim()
        : headerValue.split(',')[0]?.trim();
      if (ips) {
        return ips;
      }
    }
  }
  if (useRemoteAddress) {
    const socket = req.socket || req.connection;
    const connection = req.connection || socket;
    if (connection && connection.remoteAddress) {
      return connection.remoteAddress;
    }
    if (req.socket && req.socket.remoteAddress) {
      return req.socket.remoteAddress;
    }
  }
  return undefined;
}

export function normalizeIp(ip: string): string {
  if (ip.includes('::ffff:') && ip.includes('.')) {
    return ip.replace(/^.*:/, '');
  }
  return ip;
}
