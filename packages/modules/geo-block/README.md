# 🌍 Geo Block

A geo-based access control module for the **Lock Security Framework**. Block or allow traffic based on a user's country, with support for providers like **MaxMind**, **IPAPI**, plus caching, failovers, and distributed storage.

## 🚀 Features

- 🌎 Country-based access rules (whitelist / blacklist modes)
- 📡 Supports IPAPI, MaxMind DB
- 💾 In-memory or distributed caching (Redis / Upstash)
- 🔁 Built-in fallback and fail-safe logic
- 🧠 Smart IP extraction from headers or remote address

## 🛠 Usage

### Example: Block Requests from Specific Countries

```ts
import { secure, geoBlock } from '@lock-sdk/main';

const middleware = secure()(
  geoBlock({
    mode: 'blacklist',
    countries: ['RU', 'CN', 'IR'],
    provider: 'ipapi',
  })
);
```

### Example: Allow Only US and CA

```ts
geoBlock({
  mode: 'whitelist',
  countries: ['US', 'CA'],
  provider: 'maxmind',
  maxmindDbPath: './GeoLite2-Country.mmdb',
});
```

## ⚙️ Configuration

| Option             | Type                                   | Default                                                | Description                                      |
| ------------------ | -------------------------------------- | ------------------------------------------------------ | ------------------------------------------------ |
| `mode`             | `'blacklist'` \| `'whitelist'`         | `'blacklist'`                                          | Block or allow traffic based on country list     |
| `countries`        | `string[]`                             | `[]`                                                   | List of country ISO codes (e.g. `'US'`, `'IN'`)  |
| `provider`         | `'ipapi'` \| `'maxmind'`               | `'ipapi'`                                              | Geo location service provider                    |
| `maxmindDbPath`    | `string`                               | –                                                      | Path to `.mmdb` file if using MaxMind            |
| `apiKey`           | `string`                               | –                                                      | API key for IPAPI/IPStack                        |
| `ipHeaders`        | `string[]`                             | `['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']` | Headers to check for client IP                   |
| `useRemoteAddress` | `boolean`                              | `true`                                                 | Use `req.socket.remoteAddress` if header missing |
| `blockStatusCode`  | `number`                               | `403`                                                  | HTTP status on geo block                         |
| `blockMessage`     | `string`                               | `'Access denied based on your location'`               | Error message sent to client                     |
| `failBehavior`     | `'open'` \| `'closed'`                 | `'open'`                                               | Whether to allow traffic if provider fails       |
| `customLookup`     | `(ip: string) => Promise<GeoInfo>`     | –                                                      | Override provider with your own lookup function  |
| `storage`          | `'memory'` \| `'redis'` \| `'upstash'` | `'memory'`                                             | Backend used for caching lookups                 |
| `cacheTtl`         | `number` (ms)                          | `3600000`                                              | Duration for which geo result is cached          |
| `cacheSize`        | `number`                               | `10000`                                                | Max entries for memory cache                     |
| `redis`            | `object`                               | –                                                      | Redis connection config                          |
| `upstash`          | `object`                               | –                                                      | Upstash Redis config                             |

## 🛡 Maintained By

**Lock Team**
