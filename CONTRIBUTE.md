# Contributing to Lock 🛡️

Thank you for considering a contribution to **Lock**! Whether you're fixing bugs, improving docs, or building new modules — you're welcome here.

---

## 🧭 Project Structure

```
packages/
├── core                → Main secure() + context logic
├── main                → Central exposure of all modules
├── modules/
│   ├── rate-limit      → Rate limiting module
│   ├── bot-detection   → User-agent, fingerprint, behavioral heuristics
│   ├── vpn-detection   → Proxy/VPN detection
│   ├── geo-block       → Geo-based access control
│   ├── csrf            → CSRF token middleware
│   └── payload-guard   → Request payload injection scanning
└── adapters/
    └── next            → Next.js adapters (App Router + Pages Router + Server Actions)
```

---

## 🚀 Getting Started

1. **Fork + clone** the repo
2. Run `pnpm install` in the root
3. Run `pnpm run dev` or `pnpm run build` inside any package to test
4. Create a new branch: `git checkout -b fix/thing` or `feature/new-module`

---

## 📦 Building a Module

To create a new security module:

1. Use `createModule` from `@lock-sdk/core`
2. Implement the `check(context, config)` function
3. Implement `handleFailure()`
4. Export it and register via `registerModule`
5. Add your module to the `@lock-sdk/main` `index.ts` export for proper exposure
6. Create a README.md in your module directory explaining usage and configuration
7. Do write tests

Use existing modules as references!

### Module README Requirements

Each module should include its own README.md with:

- Module purpose and features
- Configuration options and defaults
- Usage examples
- Any gotchas or important notes

---

## ✅ Submitting a PR

- Format code with Prettier
- Follow the existing code style
- Include relevant unit tests
- Add docs if it's a new feature

PR title format:

```
fix: handle multi-IP headers properly
feat: add 'user-agent regex' support to botDetector
```

---

## ✨ Code of Conduct

Please be respectful, kind, and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

---

Built with ❤️ by Lock Team.
