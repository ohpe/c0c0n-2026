# Cloudflare Workers Training

Training materials for Cloudflare Workers: each subfolder is a self-contained
worker. Every worker ships with a short `README.md` (what it does, how to run
and stop it). Everything that applies to **all** workers is documented here.

## Prerequisites

- Node.js + npm
- A Cloudflare account (a registered domain is **NOT** required — see
  [Dev mode](#dev-mode-vs-custom-domain-mode) below)

## Getting started with a worker

```bash
cd <worker-folder>
npm install
npm run dev        # local dev server on http://localhost:8787
npm run deploy     # deploy to Cloudflare
```

The deploy prints the live URL, e.g.
`https://<worker-name>.<your-account>.workers.dev`.

## Dev mode vs custom domain mode

Each `wrangler.toml` / `wrangler.jsonc` contains two clearly marked blocks:

- **DEV MODE (default)** — `workers_dev = true` (or the absence of `routes`).
  The worker is deployed to `https://<name>.<account>.workers.dev`. This works
  even if your Cloudflare account has no domain registered, so it is the
  mode to use during the lab.
- **CUSTOM DOMAIN MODE (optional, commented out)** — an active `routes`
  section. Uncomment it only if you own a domain registered on Cloudflare,
  and replace `your-domain.com` with your own. With the `routes` section
  active and no matching domain in your account, `wrangler deploy` fails.

**Subdomain limitation in dev mode.** Cloudflare routes only the exact
`<worker>.<account>.workers.dev` host (plus `www.`) to a worker. Any other
subdomain of the workers.dev host is never handled by the edge: the TLS
handshake fails and the request does not reach your code. Consequence for
mirror/proxy workers in dev mode: URLs that point at subdomains of the
target domain cannot be rewritten to a working workers.dev host, so links
to those subdomains may fail in the browser. Custom domains do not have
this limitation (wildcard/explicit DNS records pointing the subdomains at
the worker work as expected).

## Authentication

```bash
npx wrangler login      # open a browser and log in (run once per machine)
npx wrangler whoami     # show the authenticated account(s)
npx wrangler logout     # clear the token (for shared machines)
```

## Stop / cleanup

```bash
# stop the local dev server
#   Ctrl+C in the terminal running `npm run dev`
#   optionally remove local emulation state:
rm -rf .wrangler

# delete a single deployment (keep the worker)
npx wrangler deployments list
npx wrangler deployments delete <deployment-id>

# delete the worker entirely
npx wrangler delete              # asks for confirmation (type y)
printf 'y\n' | npx wrangler delete   # non-interactive
```

`npx wrangler delete --dry-run` previews the deletion; `--force` is needed
only if other workers depend on the one being deleted.

## Watching logs

```bash
npx wrangler dev    # local logs in the terminal
npx wrangler tail   # live logs of the deployed worker (Ctrl+C to stop)
```

Useful when debugging a deployed worker: `npx wrangler tail` shows every
request and its console output (e.g. the `targetURL` for the proxy workers).

## Troubleshooting

| Symptom                                  | Cause / fix                                                                                                          |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `Authentication error [code: 10000]`     | Stale wrangler account cache. Delete `node_modules/.cache/wrangler`, then re-run `npx wrangler deploy`.              |
| Deploy targets the wrong account         | Same as above — `node_modules/.cache/wrangler/wrangler-account.json` caches the account. Remove it and retry.        |
| `zone ... does not exist` / deploy fails | The `routes` section is active but the domain is not in your account. Switch to dev mode (comment `routes`, set `workers_dev`). |
| `530` / `1016` ("Origin DNS error")      | A proxy worker reached a non-resolvable target. Check the target domain vars and inspect the `targetURL` with `npx wrangler tail`. |
| Right after deploy the URL 404s/530s     | Version propagation takes up to a minute. Wait and retry.                                                            |

## Resources

- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers)
- [Cloudflare Workers Tutorials](https://developers.cloudflare.com/workers/tutorials)
- [Cloudflare Workers Examples](https://developers.cloudflare.com/workers/examples)
