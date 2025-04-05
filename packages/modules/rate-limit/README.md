# Rate Limit

A powerful and flexible rate limiting module for the Lock security framework. Protect your backend services from abuse, brute-force attacks, DDoS attempts, and unexpected surges in traffic using a variety of strategies and pluggable storage options.

## 🚀 Features

- ✅ Fixed, sliding, token, and leaky bucket strategies
- 🌍 Country-based throttling via IP geolocation
- 🌐 Distributed rate limit storage with Redis & Upstash support
- 🛡️ Built-in DDoS heuristics and adaptive escalation
- 🧠 Custom key generators and smart skip logic
- 📦 Headers for standard and RFC-compliant rate info
- 🔥 Fast in-memory caching via LRU strategies

## 🛠 Usage

### Basic Example (100 requests per minute)

```ts
import { secure, rateLimit } from '@lock-sdk/main';

const middleware = secure()(
  rateLimit({
    limit: 100,
    windowMs: 60_000, // 1 minute
  })
);
```

## ⚙️ Configuration

| Option            | Type                                                                                 | Description                                      |
| ----------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `limit`           | number                                                                               | Max number of requests allowed in the window     |
| `windowMs`        | number                                                                               | Duration of window in milliseconds               |
| `strategy`        | 'fixed-window' \| 'sliding-window' \| 'token-bucket' \| 'leaky-bucket' \| 'adaptive' | Algorithm used to track requests                 |
| `storage`         | 'memory' \| 'redis' \| 'upstash'                                                     | Backend for storing request counters             |
| `headers`         | boolean                                                                              | Whether to add rate-limit headers                |
| `standardHeaders` | boolean                                                                              | Include legacy `X-RateLimit-*` headers           |
| `statusCode`      | number                                                                               | Response code on limit exceeded (default: `429`) |
| `message`         | string                                                                               | Error message when blocked                       |
| `resources`       | Record<string, { limit, windowMs }>                                                  | Route-specific throttles                         |
| `countryLimits`   | Record<string, { limit, windowMs }>                                                  | Per-country overrides                            |
| `geoProvider`     | { type: 'ipapi' \| 'maxmind' }                                                       | Used for country detection                       |
| `ddosPrevention`  | object                                                                               | Enable traffic heuristics for spike prevention   |
| `keyGenerator`    | Function                                                                             | Custom function to generate unique request key   |
| `skipFunction`    | Function                                                                             | Skip check conditionally (e.g., internal IPs)    |

## 📡 Header Output

When enabled, Lock sets the following headers:

| Header                  | Description                          |
| ----------------------- | ------------------------------------ |
| `X-RateLimit-Limit`     | Max requests per window              |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset`     | Time (seconds) until window resets   |
| `Retry-After`           | Delay before retrying (if blocked)   |

## 🧪 Example: Per-resource Limits

```ts
rateLimit({
  limit: 100,
  windowMs: 60_000,
  resources: {
    '/api/login': { limit: 10, windowMs: 60_000 },
    '/api/posts': { limit: 500, windowMs: 60_000 },
  },
});
```

## 🌍 Example: Country-specific Throttling

```ts
rateLimit({
  limit: 100,
  windowMs: 60_000,
  geoProvider: { type: 'ipapi' },
  countryLimits: {
    US: { limit: 200, windowMs: 60_000 },
  },
});
```

## 🔐 DDoS Protection

Built-in heuristic-based protection:

```ts
ddosPrevention: {
  enabled: true,
  requestRateThreshold: 100,
  burstThreshold: 30,
  banDurationMs: 600_000
}
```

## 🧩 Storage Backends

### Memory (Default)

```ts
storage: 'memory',
memoryOptions: {
  max: 10_000,
  ttl: 3600_000
}
```

### Redis

```ts
storage: 'redis',
redis: {
  url: 'redis://localhost:6379',
  password: 'secret'
  //pass username if using Redis cloud
}
```

### Upstash

```ts
storage: 'upstash',
upstash: {
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!
}
```

## 💡 Pro Tip: Custom Key (e.g., User ID)

```ts
rateLimit({
  keyGenerator: async ctx => ctx.request.headers['x-user-id'] || 'anonymous',
});
```

## 🧪 Testing

Use any HTTP client like `curl`, `Postman`, or `k6` to simulate burst requests and test blocking.

## 🛡 Maintained By

**Lock Team**
