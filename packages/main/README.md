# 🔒 Lock Middleware

The entry point of the **Lock Security Framework**. The `secure()` function is a flexible middleware initializer that allows you to combine and orchestrate multiple security modules in one unified pipeline.

## 🚀 Features

- 🔌 Plug and play any Lock modules: Rate limiters, IP filters, CSRF, bot detectors, etc.
- 🧩 Composable: Add multiple layered protections in one line
- ✅ Compatible with Express, Next.js framework
- 📦 Zero-config defaults for rapid prototyping

## 🛠 Usage

### Basic Setup with a Single Module

```typescript
import { secure, ipFilter } from '@lock-sdk/main';

const lockMiddleware = secure()(
  ipFilter({
    ipAddresses: ['178.238.11.6'],
    storage: 'redis',
    redis: {
      host: 'your-redis-host',
      port: 6379,
      username: 'default',
      password: 'your-password',
      keyPrefix: 'ipfilter:',
    },
  })
);
```

### Example with Multiple Modules

```typescript
import { secure, csrfProtection, rateLimit, geoBlock, botDetector } from '@lock-sdk/main';

const lockMiddleware = secure()(
  rateLimit({
    limit: 100,
    windowMs: 60000,
  }),
  csrfProtection({
    tokenLocation: 'cookie-header',
    doubleSubmit: true,
  }),
  geoBlock({
    mode: 'blacklist',
    countries: ['RU', 'CN'],
  }),
  botDetector({
    captchaRedirectUrl: '/verify-human',
  })
);
```

## 🔃 Composition Pattern

The `secure()` function returns a **curried middleware combinator**:

```typescript
secure()(module1, module2, module3, ...)
```

Each module runs **in sequence**, and the request halts immediately on the first failure (e.g. CSRF fail, IP block, DDoS spike, etc.).

## 🛡 Maintained By

**Lock Team**
