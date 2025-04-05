<p align="center">
  <img src="logo.png" alt="Lock Cover" />
</p>

# Lock 🛡️

_Modular, modern security middleware for web APIs and backend frameworks._

---

Lock is a **drop-in security toolkit** designed for modern applications. Whether you're building APIs, serverless functions, or microservices, Lock helps you secure your routes with powerful and composable middleware modules like:

- 🔒 **Rate limiting**
- 🌍 **Geo blocking**
- 🤖 **Bot detection**
- 🧠 **VPN and proxy filtering**
- 📦 **Payload inspection**
- 🧬 **CSRF protection**

---

## ✨ Features

- ✅ Plug-and-play modules
- 🧱 Composable middleware engine
- ⚡️ Zero-config defaults, full-config control
- 🎯 Framework support: **Express**, **Next.js (App & Pages routers)**
- 🌐 Distributed storage support (Redis, Upstash)

---

## 📦 Installation

```bash
npm install @lock-sdk/main
```

## 🚀 Quick Start

```ts
import { secure, rateLimit } from '@lock-sdk/main';

const middleware = secure()(
  rateLimit({
    limit: 100,
    windowMs: 60_000,
  })
);
```

### 💡 In Express

```ts
app.use('/api', middleware);
```

### 💡 In Next.js App Router

```ts
export const GET = secureAppRoute(handler)(rateLimit({ limit: 10, windowMs: 10_000 }));
```

## ✨ Check out modules

✅ [Bot Detection](https://github.com/Soumyadas15/lock/tree/main/packages/modules/bot-detection)
✅ [CSRF](https://github.com/Soumyadas15/lock/tree/main/packages/modules/csrf)
✅ [Geo-Block](https://github.com/Soumyadas15/lock/tree/main/packages/modules/geo-block)
✅ [IP Filter](https://github.com/Soumyadas15/lock/tree/main/packages/modules/ip-filter)
✅ [Payload Guard](https://github.com/Soumyadas15/lock/tree/main/packages/modules/payload-guard)
✅ [Rate Limit](https://github.com/Soumyadas15/lock/tree/main/packages/modules/rate-limit)
✅ [VPN Detection](https://github.com/Soumyadas15/lock/tree/main/packages/modules/vpn-detection)

## 🧩 Framework Support

✅ Express / Node HTTP

✅ Next.js

🧪 Fastify, H3, and others (coming soon)

## 🛠 Contributing

We love contributions! Read our [CONTRIBUTE.md](CONTRIBUTE.md) to get started.

## 📄 License

MIT — © 2025 Lock
