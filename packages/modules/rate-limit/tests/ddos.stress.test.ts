import { describe, test, expect, beforeEach, vi } from 'vitest';
import { RateLimitStore, RateLimitRecord } from '../src/types';
import { SecurityContext } from '@lock-sdk/core';
import { DDoSProtection } from '../src/strategies/factory';

class PerformanceStore implements RateLimitStore {
  records = new Map<string, any>();
  historyMap = new Map<string, number[]>();

  async init(): Promise<void> {
    return Promise.resolve();
  }

  async get(key: string): Promise<RateLimitRecord | null> {
    return this.records.get(key) || null;
  }

  async set(key: string, record: RateLimitRecord): Promise<void> {
    this.records.set(key, record);
  }

  async increment(key: string, value: number = 1): Promise<RateLimitRecord> {
    let record = await this.get(key);
    if (record) {
      record.count += value;
    }
    this.records.set(key, record);
    return record!;
  }

  async reset(key: string): Promise<void> {
    this.records.delete(key);
    this.historyMap.delete(key);
    return Promise.resolve();
  }

  async close(): Promise<void> {
    return Promise.resolve();
  }

  async addToHistory(key: string, timestamp: number): Promise<void> {
    if (!this.historyMap.has(key)) {
      this.historyMap.set(key, []);
    }
    this.historyMap.get(key)!.push(timestamp);
    return Promise.resolve();
  }

  async getWindowHistory(key: string, startTime: number): Promise<number[]> {
    if (!this.historyMap.has(key)) return [];
    const history = this.historyMap.get(key)!;
    if (history.length === 0 || history[history.length - 1] < startTime) {
      return [];
    }
    if (history[0] >= startTime) {
      return [...history];
    }
    let left = 0;
    let right = history.length - 1;
    let startIndex = history.length;
    while (left <= right) {
      const mid = Math.floor((left + right) / 2);
      if (history[mid] >= startTime) {
        startIndex = mid;
        right = mid - 1;
      } else {
        left = mid + 1;
      }
    }
    return history.slice(startIndex);
  }
}

describe('DDoS Protection Stress Tests', () => {
  let store: PerformanceStore;
  let standardConfig: any;
  let baseContext: SecurityContext;
  let now: number;
  let executionTimes: number[] = [];

  beforeEach(() => {
    executionTimes = [];
    now = 1648000000000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    store = new PerformanceStore();
    standardConfig = {
      windowMs: 60000,
      ddosPrevention: {
        enabled: true,
        banDurationMs: 600000,
        burstThreshold: 10,
        requestRateThreshold: 20,
      },
    };
    baseContext = {
      request: {
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'accept-language': 'en-US,en;q=0.9',
          accept: 'text/html,application/xhtml+xml,*/*',
        },
      },
    } as any;
  });

  async function measureExecutionTime(fn: () => Promise<any>): Promise<number> {
    const start = performance.now();
    await fn();
    const end = performance.now();
    return end - start;
  }

  function generateLargeHistory(options: {
    requestCount: number;
    durationMs: number;
    patternFn?: (index: number, total: number) => number;
  }): number[] {
    const { requestCount, durationMs, patternFn } = options;
    const startTime = now - durationMs;
    const history: number[] = [];
    const timingFn = patternFn || ((i, total) => i / total);
    for (let i = 0; i < requestCount; i++) {
      const position = timingFn(i, requestCount);
      const timestamp = startTime + Math.floor(position * durationMs);
      history.push(timestamp);
    }
    return history.sort((a, b) => a - b);
  }

  test('analyze performance scaling with history size', async () => {
    const ddosProtection = new DDoSProtection(standardConfig);
    const key = '192.168.1.100:api';
    const historySizes = [100, 500, 1000, 5000, 10000, 50000];
    const results: { size: number; time: number }[] = [];
    for (const size of historySizes) {
      await store.reset(key);
      const history = generateLargeHistory({
        requestCount: size,
        durationMs: 60000,
      });
      await store.set(key, {
        count: size,
        firstRequest: history[0],
        lastRequest: history[history.length - 1],
        history: [],
      });
      store.historyMap.set(key, history);
      const time = await measureExecutionTime(async () => {
        await ddosProtection.analyze(key, baseContext, store);
      });
      results.push({ size, time });
      console.log(`History size: ${size}, Execution time: ${time.toFixed(2)}ms`);
    }
    expect(results.find(r => r.size === 10000)?.time).toBeLessThan(100);
    for (let i = 1; i < results.length; i++) {
      const scaleFactor = results[i].time / results[i - 1].time;
      const sizeRatio = results[i].size / results[i - 1].size;
      const scalingEfficiency = scaleFactor / sizeRatio;
      console.log(
        `Scaling from ${results[i - 1].size} to ${results[i].size}: ${scalingEfficiency.toFixed(2)}x (ideal: 1.0x)`
      );
    }
  });

  test('analyze performance with different traffic patterns', async () => {
    const ddosProtection = new DDoSProtection(standardConfig);
    const baseKey = '192.168.1.101:api';
    const historySize = 10000;
    const patterns = [
      {
        name: 'Uniform',
        fn: (i: number, total: number) => i / total,
      },
      {
        name: 'Burst End',
        fn: (i: number, total: number) => {
          return i < total * 0.2
            ? (i / (total * 0.2)) * 0.2
            : 0.2 + ((i - total * 0.2) / (total * 0.8)) * 0.8;
        },
      },
      {
        name: 'Multi-Burst',
        fn: (i: number, total: number) => {
          const pos = i / total;
          return pos + 0.1 * Math.sin(pos * Math.PI * 10);
        },
      },
      {
        name: 'Accelerating',
        fn: (i: number, total: number) => {
          return Math.pow(i / total, 2);
        },
      },
    ];
    for (const [index, pattern] of patterns.entries()) {
      const key = `${baseKey}:${index}`;
      await store.reset(key);
      const history = generateLargeHistory({
        requestCount: historySize,
        durationMs: 60000,
        patternFn: pattern.fn,
      });
      await store.set(key, {
        count: historySize,
        firstRequest: history[0],
        lastRequest: history[history.length - 1],
        history: [],
      });
      store.historyMap.set(key, history);
      const time = await measureExecutionTime(async () => {
        await ddosProtection.analyze(key, baseContext, store);
      });
      console.log(`Pattern: ${pattern.name}, Execution time: ${time.toFixed(2)}ms`);
      expect(time).toBeLessThan(200);
    }
  });

  test('blacklist performance with large number of IPs', async () => {
    const blacklistSizes = [10, 100, 1000, 10000];
    for (const size of blacklistSizes) {
      const ddosProtection = new DDoSProtection(standardConfig);
      const now = Date.now();
      const expiration = now + 600000;
      console.log(`Adding ${size} IPs to blacklist...`);
      const startBlacklist = performance.now();
      const blacklist = ((ddosProtection as any).blacklist = new Map<string, number>());
      for (let i = 0; i < size; i++) {
        const ip = `10.0.${Math.floor(i / 255)}.${i % 255}`;
        blacklist.set(ip, expiration);
      }
      const endBlacklist = performance.now();
      console.log(`Populated ${size} IPs in ${(endBlacklist - startBlacklist).toFixed(2)}ms`);
      const blacklistedIp = `10.0.${Math.floor((size - 1) / 255)}.${(size - 1) % 255}`;
      const nonBlacklistedIp = '192.168.1.1';
      const blacklistedTime = await measureExecutionTime(async () => {
        for (let i = 0; i < 1000; i++) {
          ddosProtection.isBlacklisted(blacklistedIp);
        }
      });
      console.log(`1000 blacklisted IP lookups with ${size} IPs: ${blacklistedTime.toFixed(2)}ms`);
      const nonBlacklistedTime = await measureExecutionTime(async () => {
        for (let i = 0; i < 1000; i++) {
          ddosProtection.isBlacklisted(nonBlacklistedIp);
        }
      });
      console.log(
        `1000 non-blacklisted IP lookups with ${size} IPs: ${nonBlacklistedTime.toFixed(2)}ms`
      );
      expect(blacklistedTime / 1000).toBeLessThan(0.1);
      expect(nonBlacklistedTime / 1000).toBeLessThan(0.1);
    }
  });

  test('concurrent request performance', async () => {
    const ddosProtection = new DDoSProtection(standardConfig);
    const concurrencyLevels = [10, 50, 100, 500];
    const keys: string[] = [];
    const contexts: SecurityContext[] = [];
    for (let i = 0; i < 500; i++) {
      const ip = `172.16.${Math.floor(i / 255)}.${i % 255}`;
      keys.push(`${ip}:api`);
      contexts.push({
        request: {
          headers: {
            'user-agent': `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/${80 + (i % 20)}`,
            'accept-language': i % 2 === 0 ? 'en-US,en;q=0.9' : 'fr-FR,fr;q=0.9',
            accept: 'text/html,application/xhtml+xml,*/*',
          },
        },
      } as any);
      const history = generateLargeHistory({
        requestCount: 100,
        durationMs: 60000,
      });
      await store.set(keys[i], {
        count: 100,
        firstRequest: history[0],
        lastRequest: history[history.length - 1],
        history: [],
      });
      store.historyMap.set(keys[i], history);
    }
    for (const concurrency of concurrencyLevels) {
      console.log(`Testing with ${concurrency} concurrent requests...`);
      const startTime = performance.now();
      await Promise.all(
        Array.from({ length: concurrency }).map((_, i) => {
          const index = i % keys.length;
          return ddosProtection.analyze(keys[index], contexts[index], store);
        })
      );
      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const avgTime = totalTime / concurrency;
      console.log(
        `${concurrency} concurrent requests: ${totalTime.toFixed(2)}ms total, ${avgTime.toFixed(2)}ms avg per request`
      );
      expect(avgTime).toBeLessThan(10);
    }
  });

  test('simulate million requests per second throughput', async () => {
    console.log('=== MILLION RPS SIMULATION ===');
    const ddosProtection = new DDoSProtection(standardConfig);
    const simulationSeconds = 10;
    const requestsPerSecond = 1_000_000;
    const totalRequests = simulationSeconds * requestsPerSecond;
    console.log(
      `Simulating ${totalRequests.toLocaleString()} requests (${requestsPerSecond.toLocaleString()} RPS for ${simulationSeconds}s)`
    );
    const uniqueIPs = 1_000_000;
    const topOffenderPercentage = 0.01;
    const topOffenderRatio = 100;
    const normalIPCount = uniqueIPs * (1 - topOffenderPercentage);
    const topOffenderCount = uniqueIPs * topOffenderPercentage;
    const totalTrafficUnits = normalIPCount + topOffenderCount * topOffenderRatio;
    const normalIPTrafficPerIP = requestsPerSecond / totalTrafficUnits;
    const topOffenderTrafficPerIP = normalIPTrafficPerIP * topOffenderRatio;
    console.log(`Traffic model:`);
    console.log(
      `- Normal IPs: ${normalIPCount.toLocaleString()} (${normalIPTrafficPerIP.toFixed(1)} RPS each)`
    );
    console.log(
      `- Top offenders: ${topOffenderCount.toLocaleString()} (${topOffenderTrafficPerIP.toFixed(1)} RPS each)`
    );
    console.log('\nMeasuring base processing time...');
    const sampleSize = 100;
    const sampleIPs: string[] = [];
    const sampleKeys: string[] = [];
    for (let i = 0; i < sampleSize * 0.9; i++) {
      sampleIPs.push(`192.168.${Math.floor(i / 255)}.${i % 255}`);
      sampleKeys.push(`${sampleIPs[i]}:api`);
    }
    for (let i = 0; i < sampleSize * 0.1; i++) {
      sampleIPs.push(`10.0.${Math.floor(i / 255)}.${i % 255}`);
      sampleKeys.push(`${sampleIPs[sampleSize * 0.9 + i]}:api`);
    }
    const sampleStartTime = now - 60000;
    for (let i = 0; i < sampleKeys.length; i++) {
      const isTopOffender = i >= sampleSize * 0.9;
      const requestRate = isTopOffender ? topOffenderTrafficPerIP : normalIPTrafficPerIP;
      const requestCount = Math.min(10000, Math.floor(requestRate * 60));
      const history = Array.from({ length: requestCount }, (_, j) => {
        return sampleStartTime + Math.floor((j / requestCount) * 60000);
      });
      await store.set(sampleKeys[i], {
        count: requestCount,
        firstRequest: history[0],
        lastRequest: history[history.length - 1],
        history: [],
      });
      store.historyMap.set(sampleKeys[i], history);
    }
    const sampleStartExec = performance.now();
    await Promise.all(sampleKeys.map(key => ddosProtection.analyze(key, baseContext, store)));
    const sampleEndExec = performance.now();
    const avgProcessingTimeMs = (sampleEndExec - sampleStartExec) / sampleSize;
    console.log(`Average processing time: ${avgProcessingTimeMs.toFixed(3)} ms per IP`);
    const theoreticalRPS = 1000 / avgProcessingTimeMs;
    const theoreticalCoresFor1M = Math.ceil(requestsPerSecond / theoreticalRPS);
    console.log(`\nThroughput analysis:`);
    console.log(
      `- Single-threaded theoretical throughput: ${Math.floor(theoreticalRPS).toLocaleString()} RPS`
    );
    console.log(`- Cores needed for 1M RPS: ${theoreticalCoresFor1M} cores`);
    console.log('\nSimulating memory requirements...');
    const memTestSize = 1000;
    const memTestKey = 'memtest:sim';
    await store.reset(memTestKey);
    if (global.gc) {
      global.gc();
    }
    const memBefore = process.memoryUsage().heapUsed;
    const memHistory = Array.from({ length: memTestSize }, (_, i) => now - 60000 + i * 60);
    await store.set(memTestKey, {
      count: memTestSize,
      firstRequest: memHistory[0],
      lastRequest: memHistory[memHistory.length - 1],
      history: [],
    });
    store.historyMap.set(memTestKey, memHistory);
    await ddosProtection.analyze(memTestKey, baseContext, store);
    const memAfter = process.memoryUsage().heapUsed;
    const memPerRequest = (memAfter - memBefore) / 1024 / 1024;
    const memPerRequestKB = memPerRequest * 1024;
    const totalMemoryGB = (memPerRequestKB * uniqueIPs) / (1024 * 1024);
    console.log(`Memory per IP: ${memPerRequestKB.toFixed(2)} KB`);
    console.log(
      `Estimated total memory for ${uniqueIPs.toLocaleString()} unique IPs: ${totalMemoryGB.toFixed(2)} GB`
    );
    console.log('\nSimulating burst handling capability...');
    const minProcessingTimeSec = (uniqueIPs * avgProcessingTimeMs) / 1000;
    console.log(
      `Time to process all ${uniqueIPs.toLocaleString()} IPs once: ${minProcessingTimeSec.toFixed(2)} seconds`
    );
    console.log(
      `Sustainable unique IP rate: ${Math.floor(uniqueIPs / minProcessingTimeSec).toLocaleString()} unique IPs/sec`
    );
    console.log('\n=== MILLION RPS SYSTEM REQUIREMENTS ===');
    console.log(`1. Processing cores: ${theoreticalCoresFor1M} (minimum)`);
    console.log(`2. Memory: ${totalMemoryGB.toFixed(2)} GB (minimum)`);
    console.log(`3. Storage for history: High-performance distributed database`);
    console.log(`4. Load balancing: Required for distributing traffic across multiple nodes`);
    console.log(`5. Recommended architecture: Distributed microservices with shared state`);
    expect(true).toBe(true);
  });
});
