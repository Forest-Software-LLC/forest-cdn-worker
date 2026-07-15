# forest-cdn-worker

A [Cloudflare Worker](https://developers.cloudflare.com/workers/) that gates access to a
package-tarball CDN with short-lived, signed download URLs. Public assets pass straight
through; anything under `/private/` must present a valid HMAC signature and an unexpired
timestamp.

## How it works

The Worker sits in front of the Forest CDN and inspects each request:

- **Public paths** — any request whose path does **not** start with `/private/` is proxied
  through untouched.
- **Private paths** — requests under `/private/` must include two query parameters:

  | Parameter   | Description                                              |
  | ----------- | -------------------------------------------------------- |
  | `expires`   | Unix timestamp (seconds) after which the link is invalid |
  | `signature` | Hex-encoded HMAC-SHA256 of the signed string (see below) |

  A request is served only if **all** of the following hold, otherwise it is rejected with
  `403`:

  1. Both `expires` and `signature` are present.
  2. `expires` is in the future.
  3. `signature` matches an HMAC-SHA256 (computed with `crypto.subtle`) of the signed string.

### The signed string

The signature covers exactly:

```
<pathname>?expires=<expires>
```

for example `/private/pkg/left-pad-1.3.0.tgz?expires=1770000000`. The HMAC uses SHA-256 with
a shared secret (`WORKER_SIG_KEY`) and is hex-encoded. Only `pathname` and `expires` are part
of the signed payload. Any additional query parameters are ignored when verifying.

The `forest-trust-gateway` produces the signature and uses the **same** `WORKER_SIG_KEY`.

### Example

```
GET /private/abcdef87654322.tgz?expires=1770000000&signature=9f86d0818...
```

| Response          | Meaning                                            |
| ----------------- | -------------------------------------------------- |
| origin response   | Signature valid and link not expired — asset served |
| `403` Missing …   | `expires` or `signature` absent                    |
| `403` Link expired| `expires` is in the past                           |
| `403` Invalid …   | Signature did not verify                            |

## Getting started

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) and the bundled
  [Wrangler](https://developers.cloudflare.com/workers/wrangler/) CLI

### Install

```bash
npm install
```

### Configure the signing secret

`WORKER_SIG_KEY` is a [secret](https://developers.cloudflare.com/workers/configuration/secrets/),
not a plaintext var. Set it for local development and for your deployed Worker:

```bash
# Local dev — create a .dev.vars file (git-ignored) containing:
# WORKER_SIG_KEY=your-shared-secret

# Production
npx wrangler secret put WORKER_SIG_KEY
```

Use the same value on the service that signs your URLs.

### Run locally

```bash
npm run dev      # starts wrangler dev at http://localhost:8787
```

### Deploy

```bash
npm run deploy   # wrangler deploy
```

## Scripts

| Command              | Description                                               |
| -------------------- | -------------------------------------------------------- |
| `npm run dev`        | Run the Worker locally with Wrangler                     |
| `npm run deploy`     | Deploy the Worker to Cloudflare                          |
| `npm test`           | Run the Vitest suite (Workers pool)                      |
| `npm run cf-typegen` | Regenerate the `Env` types after editing bindings        |

Bindings and configuration live in [`wrangler.jsonc`](wrangler.jsonc).

## License

[MIT](LICENSE) © Forest Software LLC
