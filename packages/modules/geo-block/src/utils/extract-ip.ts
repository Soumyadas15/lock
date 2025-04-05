export function extractIp(
  request: any,
  ipHeaders: string[] = [],
  useRemoteAddress = true
): string | null {
  if (request.headers) {
    for (const header of ipHeaders) {
      const value = request.headers[header.toLowerCase()];
      if (value) {
        const parts = value.split(',');
        return parts[0].trim();
      }
    }
  }
  if (useRemoteAddress) {
    if (request.connection && request.connection.remoteAddress) {
      return request.connection.remoteAddress;
    }
    if (request.socket && request.socket.remoteAddress) {
      return request.socket.remoteAddress;
    }
  }
  return null;
}
