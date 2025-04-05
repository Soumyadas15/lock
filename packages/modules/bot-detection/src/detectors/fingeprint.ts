import { BotDetectionResult, RequestMetadata } from '../types';

/**
 * Checks if the browser fingerprint is consistent across requests and detects potential bot activity.
 *
 * This function evaluates a list of request metadata from the same IP address and compares the current request's
 * fingerprint with those in previous requests. It analyzes the count of distinct fingerprints, rapid fingerprint changes,
 * and consistency between browser fingerprints and user agents to determine if the requests are likely coming from a bot.
 *
 * @param {RequestMetadata[]} requests - Array of request metadata from the same IP.
 * @param {string} [currentFingerprint] - The current request's browser fingerprint.
 * @returns {BotDetectionResult} - An object indicating if a bot is detected, along with details like detection method and timestamp.
 */
export function checkFingerprint(
  requests: RequestMetadata[],
  currentFingerprint?: string
): BotDetectionResult {
  if (!requests || requests.length <= 1 || !currentFingerprint) {
    return { isBot: false, timestamp: Date.now() };
  }

  const previousRequestsWithFingerprints = requests
    .filter(r => r.fingerprint && r.fingerprint !== currentFingerprint)
    .slice(0, -1);

  if (previousRequestsWithFingerprints.length === 0) {
    return { isBot: false, timestamp: Date.now() };
  }

  const fingerprintCounts: Record<string, number> = {};

  for (const req of previousRequestsWithFingerprints) {
    if (req.fingerprint) {
      fingerprintCounts[req.fingerprint] = (fingerprintCounts[req.fingerprint] || 0) + 1;
    }
  }

  const fingerprints = Object.keys(fingerprintCounts);

  if (fingerprints.length >= 3) {
    return {
      isBot: true,
      reason: `Multiple browser fingerprints (${fingerprints.length}) from same IP`,
      detectionMethod: 'fingerprint-multiple',
      timestamp: Date.now(),
    };
  }

  if (fingerprints.length > 0) {
    const sortedRequests = [...previousRequestsWithFingerprints].sort(
      (a, b) => a.timestamp - b.timestamp
    );

    let lastFingerprint: string | undefined;
    let lastTimestamp = 0;
    let suspiciousChanges = 0;

    for (const req of sortedRequests) {
      if (req.fingerprint && lastFingerprint && req.fingerprint !== lastFingerprint) {
        const timeSinceLastChange = req.timestamp - lastTimestamp;
        if (timeSinceLastChange < 30000) {
          suspiciousChanges++;
        }
      }
      lastFingerprint = req.fingerprint;
      lastTimestamp = req.timestamp;
    }

    if (suspiciousChanges >= 2) {
      return {
        isBot: true,
        reason: 'Suspiciously rapid changes in browser fingerprint',
        detectionMethod: 'fingerprint-timing',
        timestamp: Date.now(),
      };
    }
  }

  const userAgents = new Set<string>();
  const fingerprintToUserAgent: Record<string, Set<string>> = {};

  for (const req of requests) {
    if (req.fingerprint && req.userAgent) {
      if (!fingerprintToUserAgent[req.fingerprint]) {
        fingerprintToUserAgent[req.fingerprint] = new Set<string>();
      }
      fingerprintToUserAgent[req.fingerprint].add(req.userAgent);
      userAgents.add(req.userAgent);
    }
  }

  for (const [fingerprint, agents] of Object.entries(fingerprintToUserAgent)) {
    if (agents.size > 1) {
      const browserCores = new Set<string>();

      agents.forEach(agent => {
        let core = 'unknown';
        if (agent.includes('Firefox/')) core = 'firefox';
        else if (agent.includes('Chrome/')) core = 'chrome';
        else if (agent.includes('Safari/')) core = 'safari';
        else if (agent.includes('Edg/')) core = 'edge';
        else if (agent.includes('OPR/')) core = 'opera';
        browserCores.add(core);
      });

      if (browserCores.size > 1) {
        return {
          isBot: true,
          reason: 'Same browser fingerprint used with different browsers',
          detectionMethod: 'fingerprint-useragent-mismatch',
          timestamp: Date.now(),
        };
      }
    }
  }

  return { isBot: false, timestamp: Date.now() };
}
