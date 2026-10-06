# Site Cloner

A Cloudflare Worker that acts as a **live mirror** of a target site: every
request arriving on your domain is proxied to the target (default `bbc.com`)
and all occurrences of the target domain in the response (body and headers)
are rewritten back to your domain. The visitor stays inside "your" site.

> Training use only: point `TARGET_DOMAIN` only at sites you are allowed to test.

## Variables (`wrangler.toml`, `[vars]` section)

| Var             | Default   | Meaning                                       |
| --------------- | --------- | --------------------------------------------- |
| `TARGET_DOMAIN` | `bbc.com` | The site to mirror                            |
| `HTTP_SCHEME`   | `http://` | Scheme used when contacting the target        |

Two configuration modes: **dev** (default, `workers_dev = true`, reachable at
`https://<name>.<account>.workers.dev`, no domain required) and
**custom domain** (see the comments in `wrangler.toml`; requires a domain
registered on Cloudflare, otherwise the deploy fails).

**Subdomain note:** with a custom domain, subdomains of the attacker domain
mirror the matching target subdomain (`india.misconfigured.email` →
`india.bbc.com`), provided the DNS records for those subdomains point at the
worker. In workers.dev mode the worker's subdomains are not served by
Cloudflare (only the `<worker>.<account>.workers.dev` host), so links to the
target's subdomains may fail in the browser. Use custom domain mode for a
complete mirror.

## Run

```bash
npm install
npm run dev          # local, http://localhost:8787
npm run deploy       # publish to Cloudflare
```

Quick test after deploy (replace the URL with yours):

```bash
curl -sI https://mirrorman.c0c0n.workers.dev/ | grep -i "^HTTP"   # want 200
curl -s  https://mirrorman.c0c0n.workers.dev/ | grep -c "bbc.com" # want 0
```

## Stop

```bash
# dev server: Ctrl+C in the terminal
npx wrangler delete     # removes the deployed worker (asks for confirmation)
```

For the general wrangler guide (login, delete, troubleshooting) see the
root [README](../README.md).
