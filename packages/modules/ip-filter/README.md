# 🌐 IP Filter

An IP allow/block list module for the **Lock Security Framework**. Use it to selectively deny or permit access based on client IP addresses. Supports CIDR ranges, LRU caching, and Redis/Upstash for distributed enforcement.

## 🚀 Features

- 🔒 IP whitelist and blacklist modes
- 📍 CIDR and exact IP matching
- ⚡ Fast in-memory or distributed caching (Redis, Upstash)
- 🧠 Smart header detection & fallback to remote address
- 🛠 Fail-safe options for zero-downtime

## 🛠 Usage

### Basic Example (Blacklist)

```ts
import { secure, ipFilter } from '@lock-sdk/main';

const middleware = secure()(
  ipFilter({
    mode: 'blacklist',
    ipAddresses: ['203.0.113.5', '192.168.1.0/24'],
  })
);
```

### Whitelist Example

```ts
ipFilter({
  mode: 'whitelist',
  ipAddresses: ['10.0.0.1', '172.16.0.0/12'],
});
```

## ⚙️ Configuration

| Option             | Type                                   | Default                                                | Description                                  |
| ------------------ | -------------------------------------- | ------------------------------------------------------ | -------------------------------------------- |
| `mode`             | `'blacklist'` \| `'whitelist'`         | `'blacklist'`                                          | Select deny- or allowlist mode               |
| `ipAddresses`      | `string[]`                             | `[]`                                                   | List of IPs or CIDRs                         |
| `ipHeaders`        | `string[]`                             | `['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']` | Headers to check for client IP               |
| `useRemoteAddress` | `boolean`                              | `true`                                                 | Fallback to `req.socket.remoteAddress`       |
| `blockStatusCode`  | `number`                               | `403`                                                  | HTTP status code on block                    |
| `blockMessage`     | `string`                               | `'Access denied based on your IP address'`             | Error message if blocked                     |
| `failBehavior`     | `'open'` \| `'closed'`                 | `'open'`                                               | Fail-safe behavior if matching/storage fails |
| `logFunction`      | `(msg, data?) => void`                 | `console.log`                                          | Optional logger hook                         |
| `logBlocked`       | `boolean`                              | `false`                                                | Log blocked IPs                              |
| `logAllowed`       | `boolean`                              | `false`                                                | Log allowed IPs                              |
| `storage`          | `'memory'` \| `'redis'` \| `'upstash'` | `'memory'`                                             | Where to cache results                       |
| `cacheTtl`         | `number` (ms)                          | `3600000` (1 hour)                                     | TTL for IP decision cache                    |
| `cacheSize`        | `number`                               | `10000`                                                | Max IPs cached in memory                     |
| `redis`            | `object`                               | `–`                                                    | Redis configuration                          |
| `upstash`          | `object`                               | `–`                                                    | Upstash configuration                        |

### Memory (default)

```ts
storage: 'memory',
cacheTtl: 3600000, // 1 hour
cacheSize: 10000
```

### Redis

```ts
storage: 'redis',
redis: {
  url: 'redis://localhost:6379',
  password: 'secret',
  keyPrefix: 'ipfilter:'
}
```

### Upstash

```ts
storage: 'upstash',
upstash: {
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
  keyPrefix: 'ipfilter:'
}
```

## 🛡 Maintained By

**Lock Team**
