# 🤖 Bot Detector

A powerful module in the **Lock Security Framework** that detects bots using heuristics, fingerprints, request behavior, and header/user-agent analysis. Automatically block suspicious traffic or redirect to CAPTCHA.

## 🚀 Features

- 🔍 Detects headless browsers and bad user-agents
- 🕵️ Behavioral heuristics: frequency, burst, session replay
- 🧠 Optional browser fingerprint mismatch checks
- 🧾 Suspicious or missing header detection
- 🗃 Memory, Redis, or Upstash storage for request/session tracking
- 🪝 Configurable bypass via query param
- 🔁 Optional CAPTCHA redirect with return URL

## 🛠 Usage

### Basic Example (Redirect to CAPTCHA if suspicious)

```typescript
import { secure, botDetector } from '@lock-sdk/main';

const middleware = secure()(
  botDetector({
    enabled: true,
    captchaRedirectUrl: '/verify-human',
  })
);
```

## ⚙️ Configuration

| Option                  | Type               | Default    | Description                     |
| ----------------------- | ------------------ | ---------- | ------------------------------- |
| `enabled`               | boolean            | true       | Enable or disable bot detection |
| `captchaRedirectUrl`    | string             | /captcha   | Redirect URL for detected bots  |
| `redirectStatusCode`    | number             | 302        | HTTP code for redirect          |
| `redirectMessage`       | string             | See above  | Text fallback if redirect fails |
| `includeOriginalUrl`    | boolean            | true       | Add `returnTo` query param      |
| `allowQueryParamBypass` | boolean            | false      | Allow skipping via URL param    |
| `bypassParam`           | string             | \_botcheck | Param name for bypass           |
| `bypassValue`           | string             | bypass     | Param value to allow bypass     |
| `failBehavior`          | 'open' \| 'closed' | 'closed'   | Whether to fail open if error   |

### 🧠 User Agent Checks

```typescript
userAgent: {
  enabled: true,
  blockEmpty: true,
  blockedPatterns: ['bot', 'curl', 'wget'],
  requiredPatterns: ['mozilla', 'chrome']
}
```

### 🕵️ Behavior Heuristics

```typescript
behavior: {
  enabled: true,
  minRequestInterval: 50, // ms
  maxSessionRequests: 1000, // per session
  sessionDuration: 3600000, // 1 hour
  checkPathPatterns: true
}
```

### 🧾 Header Analysis

```typescript
headers: {
  enabled: true,
  required: ['accept', 'accept-language'],
  suspicious: {
    accept: ['*/*'],
    'accept-language': ['']
  },
  checkBrowserFingerprint: true
}
```

### 🔎 Fingerprinting

```typescript
fingerprinting: {
  enabled: true,
  cookieName: '__bot_fp',
  hashHeaderName: 'x-browser-fingerprint'
}
```

### 🧩 Storage Options

| Backend   | Description                       |
| --------- | --------------------------------- |
| `memory`  | In-process memory store (default) |
| `redis`   | Supports clustering, TTL, etc.    |
| `upstash` | Serverless Redis variant          |

```typescript
storage: 'redis',
redis: {
  url: 'redis://localhost:6379',
  keyPrefix: 'bot:',
}
```

### 🧠 Caching

```typescript
cache: {
  ttl: 3600000, // 1 hour
  size: 10000
}
```

## 📛 Event Types

| Event Code                     | Description                               |
| ------------------------------ | ----------------------------------------- |
| `bot.detected`                 | Bot was detected and blocked              |
| `suspicious.behavior`          | Behavioral patterns were suspicious       |
| `invalid.user.agent`           | User agent string was abnormal            |
| `suspicious.headers`           | Headers were missing or suspicious        |
| `browser.fingerprint.mismatch` | Fingerprint didn't match expected pattern |

## 🔁 Bypass Protection

To enable bypass using a URL like `/api/ping?_botcheck=bypass`:

```typescript
allowQueryParamBypass: true,
bypassParam: '_botcheck',
bypassValue: 'bypass'
```

## 🛡 Maintained By

**Lock Team**
