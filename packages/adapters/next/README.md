# ⚙️ Lock Next.js Adapter

A powerful integration layer that brings **Lock security modules** to **Next.js** — including API routes, App Router handlers, and Server Actions. Protect your endpoints with rate limiting, CSRF, IP filtering, and more — all seamlessly integrated into your Next.js app.

## 📦 Installation

```bash
npm install @lock-sdk/next-adapter # or yarn add @lock-sdk/next-adapter
```

## 🚀 Features

- ✅ Works with **Pages Router** and **App Router**
- 🔐 Supports **Server Actions** with automatic token/header propagation
- 🧩 Full compatibility with any `secure()`-compliant Lock modules
- 📦 Tiny, framework-native, zero-dependency layer

## 🧠 Usage

### 🗂 Pages Router API Example

```typescript
// pages/api/secure.ts
import { securePageRoute } from '@lock-sdk/next-adapter';
import { csrfProtection, rateLimit } from '@lock-sdk/main';

const handler = (req, res) => {
  res.status(200).json({ message: 'Secure API route' });
};

export default securePageRoute(handler)(
  rateLimit({ limit: 50, windowMs: 60000 }),
  csrfProtection()
);
```

### 📦 App Router API Example

```typescript
// app/api/secure/route.ts
import { NextResponse } from 'next/server';
import { secureAppRoute } from '@lock-sdk/next-adapter';
import { botDetector } from '@lock-sdk/main';

const handler = async (req: Request) => {
  return NextResponse.json({ message: 'Secure App Router' });
};

export const GET = secureAppRoute(handler)(botDetector());
```

### 🧬 Server Action Example

```typescript
'use server';

import { secureServerAction } from '@lock-sdk/next-adapter';
import { csrfProtection } from '@lock-sdk/main';

const submitForm = async (formData: FormData) => {
  // Handle your form logic here
  return { success: true };
};

export const protectedSubmit = secureServerAction(submitForm)(csrfProtection());
```

🧠 **Note:** CSRF tokens must be injected in your form as `csrf-token` or `csrfToken` and `$REQUEST_HEADERS` (stringified `headers`) must also be included for secure server actions.

## 🔌 API Reference

`securePageRoute(handler)(...modules)`  
Wraps a `NextApiHandler` (Pages Router) with Lock security modules.

`secureAppRoute(handler)(...modules)`  
Wraps an `App Router` request handler with Lock security modules.

`secureServerAction(fn)(...modules)`  
Wraps a Server Action (`'use server'` function) and protects it using Lock modules.

## 🔁 Failure Behavior

If a security check fails:

- ✅ `securePageRoute` sends JSON error response.
- ✅ `secureAppRoute` returns a `Response` object with error and appropriate status.
- ✅ `secureServerAction` throws an `Error` that can be caught by the frontend.

## 🛡 Maintained By

**Lock Team**
