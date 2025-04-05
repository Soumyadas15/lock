# 🕵️‍♂️ VPN Detector

A pluggable VPN, proxy, Tor, and datacenter IP detection module for the Lock security framework. Protect your APIs and backend services from anonymous or malicious network traffic using external IP reputation services, caching, and flexible scoring thresholds.

## 🚀 Features

- 🔍 VPN, proxy, Tor, and datacenter detection
- 🌐 Provider support: IPQualityScore and IPAPI
- 🧠 Confidence score-based blocking (custom thresholds)
- 💾 Built-in caching with memory, Redis, or Upstash support

## 🛠 Usage

### Basic Example (blocks VPN/proxy/Tor/Data centers)

```ts
import { secure, vpnDetector } from '@lock-sdk/main';

const middleware = secure()(
  vpnDetector({
    provider: 'ipapi',
    blockVpn: true,
    blockProxy: true,
    blockTor: true,
    blockDatacenter: true,
  })
);
```

## ⚙️ Configuration

| Option                     | Type                                   | Default                                                | Description                              |
| -------------------------- | -------------------------------------- | ------------------------------------------------------ | ---------------------------------------- |
| `provider`                 | `'ipqualityscore'` \| `'ipapi'`        | `'ipapi'`                                              | IP intelligence service                  |
| `blockVpn`                 | `boolean`                              | `true`                                                 | Block request if VPN is detected         |
| `blockProxy`               | `boolean`                              | `true`                                                 | Block if proxy is detected               |
| `blockTor`                 | `boolean`                              | `true`                                                 | Block if Tor is detected                 |
| `blockDatacenter`          | `boolean`                              | `false`                                                | Block known cloud/hosted IP ranges       |
| `vpnScoreThreshold`        | `number`                               | `0.7`                                                  | Score ≥ this will be considered VPN      |
| `proxyScoreThreshold`      | `number`                               | `0.7`                                                  | Threshold for proxy detection            |
| `torScoreThreshold`        | `number`                               | `0.7`                                                  | Threshold for Tor exit nodes             |
| `datacenterScoreThreshold` | `number`                               | `0.7`                                                  | Threshold for datacenter classification  |
| `failBehavior`             | `'open'` \| `'closed'`                 | `'open'`                                               | Allow or block on provider/cache error   |
| `blockStatusCode`          | `number`                               | `403`                                                  | HTTP status when request is blocked      |
| `blockMessage`             | `string`                               | `'Access denied: VPN or proxy detected'`               | Error message sent to client             |
| `logFunction`              | `(msg, data) => void`                  | `undefined`                                            | Optional logger hook                     |
| `logResults`               | `boolean`                              | `false`                                                | Log all detection results                |
| `ipHeaders`                | `string[]`                             | `['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']` | Headers to check for client IP           |
| `useRemoteAddress`         | `boolean`                              | `true`                                                 | Fallback to socket IP if headers missing |
| `storage`                  | `'memory'` \| `'redis'` \| `'upstash'` | `'memory'`                                             | Caching backend                          |
| `cacheTtl`                 | `number` (ms)                          | `3600000`                                              | Time to live for cached entries          |
| `cacheSize`                | `number`                               | `10000`                                                | Max cached IPs for in-memory store       |

## 🌐 Geo-aware Throttling?

Pair `vpnDetector()` with `rateLimit()` and `geoBlock()` for advanced traffic policies.

## 🧩 Storage Backends

### Memory (Default)

```ts
storage: 'memory',
cacheTtl: 3600_000,
cacheSize: 10000
```

### Redis

```ts
storage: 'redis',
redis: {
  url: 'redis://localhost:6379',
  password: 'secret',
  username: 'default',
  keyPrefix: 'vpn:',
}
```

### Upstash

```ts
storage: 'upstash',
upstash: {
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
  keyPrefix: 'vpn:',
}
```

## 🧪 Testing

Use tools like `curl`, `Postman`, or `k6` with VPN enabled IPs to simulate detection:

## 🛡 Maintained By

**Lock Team**
