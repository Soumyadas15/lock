import { SecurityContext } from '@lock-sdk/core';
import { RateLimitConfig, RateLimitResult, RateLimitStore } from '../types';

export interface RateLimitStrategyImplementation {
  check(
    key: string,
    context: SecurityContext,
    config: RateLimitConfig,
    store: RateLimitStore
  ): Promise<RateLimitResult>;
}

export * from './fixed';
export * from './leaky-bucket';
export * from './sliding-window';
export * from './token-bucket';
export * from './adaptive';
