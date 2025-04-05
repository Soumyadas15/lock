export function extractIp(
  req: any,
  ipHeaders: string[] = ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'],
  useRemoteAddress: boolean = true
): string | null {
  for (const header of ipHeaders) {
    const headerValue = req.headers?.[header] || req.headers?.[header.toLowerCase()];

    if (headerValue) {
      if (typeof headerValue === 'string' && headerValue.includes(',')) {
        const firstIp = headerValue.split(',')[0].trim();
        if (firstIp) return firstIp;
      } else {
        return headerValue as string;
      }
    }
  }

  if (useRemoteAddress) {
    const connection = req.connection || req.socket || req.info;

    if (connection?.remoteAddress) {
      return connection.remoteAddress;
    }

    if (req.ip) {
      return req.ip;
    }

    if (req.socket?.remoteAddress) {
      return req.socket.remoteAddress;
    }
  }

  return null;
}

export function cleanIp(ip: string): string {
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  return ip;
}
