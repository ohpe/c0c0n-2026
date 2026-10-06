# Simple Anti-Sandbox

A Cloudflare Worker that returns a **client-side JavaScript challenge**
instead of the phishing page. The challenge inspects the visitor's
environment (CPU core count, `window.webdriver`) and redirects:

- **sandbox / bot** → `SANDBOX_REDIRECT` (default `https://amazon.com`)
- **legit user** → `USER_REDIRECT` (the real phishing page)

The visitor's check results are appended to the redirect URL as query
parameters, so the landing page can verify them. The anti-sandbox logic
lives in `src/sandbox.js`.

> Training use only.

## Variables (`wrangler.toml`, `[vars]` section)

| Var                | Default            | Meaning                                            |
| ------------------ | ------------------ | -------------------------------------------------- |
| `SANDBOX_REDIRECT` | `https://amazon.com` | Where bots/sandboxes are redirected              |
| `USER_REDIRECT`    | `https://example.com` | Where legit users are redirected (phish page)   |

Two configuration modes: **dev** (default, `workers_dev = true`, reachable
at `https://<name>.<account>.workers.dev`, no domain required) and
**custom domain** (see the comments in `wrangler.toml`).

**Security note (why `custom_domain = false`):** for a custom domain this
worker should stay *unbound* from Cloudflare's TLS edge (`custom_domain =
false`), so no certificate is generated for the phishing subdomain and the
Certificate Transparency logs do not reveal the endpoint.

## Run

```bash
npm install
npm run dev          # local, http://localhost:8787
npm run deploy       # publish to Cloudflare
```

## Verify

The response is always a tiny HTML page containing the JS challenge —
check that the two redirect targets are inside it:

```bash
# dev
curl -s http://localhost:8787/ | grep -oE "amazon.com|example.com" | sort -u

# deployed (replace the URL with yours)
curl -s https://basic-anti-sandbox.c0c0n.workers.dev/ | grep -oE "amazon.com|example.com" | sort -u
```

Expected client behaviour:

| Visitor profile                    | `hwCon` / `webDriver` | Redirected to    |
| ---------------------------------- | --------------------- | ---------------- |
| headless browser (Selenium/ Puppeteer) | `webdriver: true`   | `SANDBOX_REDIRECT` |
| low-core VM / sandbox              | `hwCon < 8`           | `SANDBOX_REDIRECT` |
| real laptop                        | `hwCon >= 8`, no webdriver | `USER_REDIRECT`  |

## Stop

```bash
# dev server: Ctrl+C in the terminal
npx wrangler delete     # removes the deployed worker (asks for confirmation)
```

For the general wrangler guide (login, delete, troubleshooting) see the
root [README](../README.md).
