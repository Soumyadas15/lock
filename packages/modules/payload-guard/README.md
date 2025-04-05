# 🛡 Payload Guard

A smart and extensible request payload inspection module for the **Lock Security Framework**. Protect your APIs and web services from malicious input patterns like **XSS, SQLi, command injection, SSRF**, and more — with configurable modes, caching, and field-level filtering.

## 🚀 Features

- 🧪 Detects XSS, SQLi, SSRF, command/path/template injections
- ⚙️ Supports `query`, `params`, `body`, `headers`, and `cookies`
- 🔐 Block or detect mode per environment
- 📦 Smart LRU caching to avoid reprocessing

## 🛠 Usage

### Basic Example (block malicious content)

```ts
import { secure, payloadGuard } from '@lock-sdk/main';

const middleware = secure()(
  payloadGuard({
    detectXSS: true,
    detectSQLi: true,
    detectSSRF: true,
  })
);
```

## ⚙️ Configuration

| Option                   | Type                                                                  | Default                                              | Description                                    |
| ------------------------ | --------------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------- |
| `mode`                   | `'block'` \| `'detect'`                                               | `'block'`                                            | Block immediately or just log/detect           |
| `blockStatusCode`        | `number`                                                              | `403`                                                | Status code when blocked                       |
| `blockMessage`           | `string`                                                              | `'Request blocked due to potential security threat'` | Error message for blocked responses            |
| `checkParts`             | (`'params'` \| `'query'` \| `'body'` \| `'headers'` \| `'cookies'`)[] | `['params', 'query', 'body', 'headers']`             | Request parts to inspect                       |
| `excludeHeaders`         | `string[]`                                                            | `['authorization', 'cookie', 'set-cookie']`          | Headers to ignore                              |
| `excludeFields`          | `string[][]`                                                          |                                                      | JSON keys to skip during inspection            |
| `detectXSS`              | `boolean`                                                             | `true`                                               | Enable XSS detection                           |
| `detectSQLi`             | `boolean`                                                             | `true`                                               | Enable SQL injection detection                 |
| `detectSSRF`             | `boolean`                                                             | `true`                                               | Enable SSRF detection                          |
| `detectCommandInjection` | `boolean`                                                             | `true`                                               | Enable shell injection detection               |
| `detectPathTraversal`    | `boolean`                                                             | `true`                                               | Enable `../` and file path traversal detection |
| `enableCaching`          | `boolean`                                                             | `true`                                               | Enable LRU-based payload caching               |
| `cacheTtl`               | `number` (ms)                                                         | `3600000`                                            | Cache expiration time                          |
| `cacheSize`              | `number`                                                              | `10000`                                              | Max entries in cache                           |
| `failBehavior`           | `'open'` \| `'closed'`                                                | `'open'`                                             | What to do if the module throws internally     |

## 🛡 Maintained By

**Lock Team**
