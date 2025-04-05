import { BotDetectionResult, RequestMetadata } from '../types';

/**
 * Configuration object for behavioral analysis in bot detection.
 *
 * @typedef {Object} BehaviorConfig
 * @property {boolean} enabled - Flag to enable or disable the behavior check.
 * @property {number} [minRequestInterval] - Minimum interval (in ms) between consecutive requests to flag as suspicious.
 * @property {number} [maxSessionRequests] - Maximum number of requests allowed in a session before being flagged.
 * @property {number} [sessionDuration] - Duration (in ms) of the session, after which it is reset.
 * @property {boolean} [checkPathPatterns] - Flag to enable or disable path pattern analysis.
 */
export interface BehaviorConfig {
  enabled: boolean;
  minRequestInterval?: number;
  maxSessionRequests?: number;
  sessionDuration?: number;
  checkPathPatterns?: boolean;
}

/**
 * Detects suspicious patterns in the requests based on behavioral analysis.
 * This function checks several behaviors to identify potential bot activity.
 * It evaluates request timing patterns, volume of requests within a session, and path access patterns.
 *
 * It returns a `BotDetectionResult` that indicates whether the requests are likely from a bot and provides a reason
 * for the detection. This result is based on factors like:
 * - Requests being made too quickly in succession.
 * - The frequency of requests during a session exceeding a specified limit.
 * - Repetitive or cyclical access patterns of URLs.
 *
 * @param {RequestMetadata[]} requests - An array of request metadata from the same IP to analyze for suspicious behavior.
 * @param {BehaviorConfig} config - Configuration for the behavior analysis process.
 * @returns {BotDetectionResult} The result of the bot detection analysis, including whether the request pattern is suspicious,
 * the reason for the flag, and a score indicating the strength of the suspicion.
 */
export function checkBehavior(
  requests: RequestMetadata[],
  config: BehaviorConfig
): BotDetectionResult {
  if (!requests || requests.length <= 1) {
    return { isBot: false, timestamp: Date.now() };
  }

  const sortedRequests = [...requests].sort((a, b) => a.timestamp - b.timestamp);

  if (config.minRequestInterval && config.minRequestInterval > 0) {
    const intervals: number[] = [];

    for (let i = 1; i < sortedRequests.length; i++) {
      const interval = sortedRequests[i].timestamp - sortedRequests[i - 1].timestamp;
      intervals.push(interval);
    }

    if (intervals.length >= 5) {
      const tooFastCount = intervals.filter(
        interval => interval < config.minRequestInterval!
      ).length;
      const tooFastRatio = tooFastCount / intervals.length;

      if (tooFastRatio > 0.7) {
        return {
          isBot: true,
          reason: `Request timing too regular: ${tooFastCount} requests under minimum interval of ${config.minRequestInterval}ms`,
          score: tooFastRatio,
          detectionMethod: 'behavior-timing',
          timestamp: Date.now(),
        };
      }

      if (intervals.length >= 10) {
        const mean = intervals.reduce((sum, val) => sum + val, 0) / intervals.length;
        const squaredDiffs = intervals.map(val => Math.pow(val - mean, 2));
        const variance = squaredDiffs.reduce((sum, val) => sum + val, 0) / intervals.length;
        const stdDev = Math.sqrt(variance);

        if (mean > 0 && stdDev / mean < 0.1) {
          return {
            isBot: true,
            reason: 'Suspiciously regular request timing pattern',
            score: 0.9,
            detectionMethod: 'behavior-timing-regularity',
            timestamp: Date.now(),
          };
        }
      }
    }
  }

  if (config.maxSessionRequests && sortedRequests.length > config.maxSessionRequests) {
    return {
      isBot: true,
      reason: `Too many requests in session: ${sortedRequests.length} requests (max: ${config.maxSessionRequests})`,
      score: sortedRequests.length / config.maxSessionRequests,
      detectionMethod: 'behavior-volume',
      timestamp: Date.now(),
    };
  }

  if (config.checkPathPatterns && sortedRequests.length >= 10) {
    const pathCounts: Record<string, number> = {};
    const pathSequences: string[] = [];

    for (const req of sortedRequests) {
      pathCounts[req.path] = (pathCounts[req.path] || 0) + 1;
      pathSequences.push(req.path);
    }

    const sortedPaths = Object.entries(pathCounts).sort((a, b) => b[1] - a[1]);
    if (sortedPaths.length > 0 && sortedPaths[0][1] / sortedRequests.length > 0.9) {
      return {
        isBot: true,
        reason: `Path access pattern too repetitive: ${sortedPaths[0][0]} requested ${sortedPaths[0][1]} times`,
        score: 0.9,
        detectionMethod: 'behavior-path-repetition',
        timestamp: Date.now(),
      };
    }

    if (sortedPaths.length >= 3) {
      const pathStr = pathSequences.join(',');
      const maxPatternLength = Math.min(5, Math.floor(pathSequences.length / 3));

      for (let patternLength = 3; patternLength <= maxPatternLength; patternLength++) {
        for (let i = 0; i < pathSequences.length - patternLength * 3; i++) {
          const pattern = pathSequences.slice(i, i + patternLength).join(',');

          if (
            pathStr.indexOf(pattern) !== pathStr.lastIndexOf(pattern) &&
            pathStr.split(pattern).length >= 4
          ) {
            return {
              isBot: true,
              reason: 'Cyclical path access pattern detected',
              score: 0.8,
              detectionMethod: 'behavior-path-cyclical',
              timestamp: Date.now(),
            };
          }
        }
      }
    }
  }

  return { isBot: false, timestamp: Date.now() };
}
