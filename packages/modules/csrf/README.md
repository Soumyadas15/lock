# 🛡️ CSRF Protection

A robust and flexible Cross-Site Request Forgery (CSRF) protection module for the **Lock Security Framework**. Supports token generation, header/cookie/session validation, double-submit patterns, and pluggable storage backends.

## 🚀 Features

- 🔐 Supports token validation via cookie, header, session, or combo
- ✌️ Double-submit cookie + header validation
- 🧠 Smart auto-ignore for GET, OPTIONS, and form uploads
- 🍪 Custom cookie options with secure, SameSite, and domain control
- 🔄 Optional token refresh on every request
- 📦 Pluggable token stores: memory or Redis
- ⚙️ Fine-grained config for ignored methods, paths, content-types

## 🛠 Usage

### Basic Middleware (Cookie + Header)

```ts
import { secure, csrfProtection } from '@lock-sdk/main';

const middleware = secure()(
  csrfProtection({
    enabled: true,
    tokenLocation: 'cookie-header',
    doubleSubmit: true,
  })
);
```

## ⚙️ Configuration

| Option                | Type                                                         | Default                          | Description                                        |
| --------------------- | ------------------------------------------------------------ | -------------------------------- | -------------------------------------------------- |
| `enabled`             | `boolean`                                                    | `true`                           | Toggle protection                                  |
| `tokenName`           | `string`                                                     | `'csrf-token'`                   | Token name (used in cookie/header/session)         |
| `tokenLength`         | `number`                                                     | `32`                             | Length of generated token                          |
| `headerName`          | `string`                                                     | `'x-csrf-token'`                 | Header to check when using header or cookie-header |
| `cookieName`          | `string`                                                     | `'csrf-token'`                   | Cookie name for token (if applicable)              |
| `cookieOptions`       | `CookieOptions`                                              | See below                        | Customization for Set-Cookie                       |
| `storage`             | `'memory'` \| `'redis'`                                      | `'memory'`                       | Backend for token persistence                      |
| `tokenLocation`       | `'cookie'` \| `'header'` \| `'cookie-header'` \| `'session'` | `'cookie-header'`                | Where to expect/return token                       |
| `ignoredMethods`      | `string[]`                                                   | `['GET','HEAD','OPTIONS']`       | Skip token check for these methods                 |
| `ignoredPaths`        | `(string \| RegExp)[]`                                       | `[]`                             | Skip token check for these routes                  |
| `ignoredContentTypes` | `string[]`                                                   | `['multipart/form-data']`        | Skip check for uploads                             |
| `failureStatusCode`   | `number`                                                     | `403`                            | Response status on failure                         |
| `failureMessage`      | `string`                                                     | `'CSRF token validation failed'` | Response message                                   |
| `refreshToken`        | `boolean`                                                    | `true`                           | Regenerate token on each request                   |
| `tokenTtl`            | `number` (seconds)                                           | `86400 (24hr)`                   | Expiry duration for stored tokens                  |
| `doubleSubmit`        | `boolean`                                                    | `true`                           | Enforce cookie + header match                      |
| `samesite`            | `boolean`                                                    | `true`                           | Apply SameSite cookie flags                        |
| `redisOptions`        | `RedisOptions`                                               | –                                | Redis connection settings                          |
| `customStorage`       | `TokenStorageProvider`                                       | –                                | Provide your own storage logic                     |
| `includeFormToken`    | `boolean`                                                    | –                                | (Coming soon) Inject token into forms              |
| `angularCompatible`   | `boolean`                                                    | –                                | (Coming soon) Support Angular's $http token style  |

## 🍪 Cookie Options

```ts
cookieOptions: {
  httpOnly: false,
  secure: true,
  sameSite: 'lax',
  path: '/',
  domain: 'example.com',
  maxAge: 3600,
}
```

## 📡 Token Sources

| Location        | Description                                             |
| --------------- | ------------------------------------------------------- |
| `cookie`        | Token is read from a cookie                             |
| `header`        | Token is sent via header (x-csrf-token by default)      |
| `cookie-header` | Token must be in both header and cookie (double-submit) |
| `session`       | Token is stored in req.session[tokenName]               |

## 📛 Event Types

| Event Code                   | Description                        |
| ---------------------------- | ---------------------------------- |
| `csrf.token.missing`         | Token was not found in the request |
| `csrf.token.invalid`         | Token did not validate             |
| `csrf.double.submit.failure` | Cookie and header token mismatch   |
| `csrf.validated`             | Request passed CSRF validation     |
| `csrf.error`                 | Unhandled exception in CSRF logic  |

## 🧩 Storage Backends

### Memory (default)

```ts
storage: 'memory',
tokenTtl: 86400
```

### Redis

```ts
storage: 'redis',
redisOptions: {
  url: 'redis://localhost:6379',
  password: 'secret',
  keyPrefix: 'csrf:',
}
```

## 🛡 Maintained By

**Lock Team**
