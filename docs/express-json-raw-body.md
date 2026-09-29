# express.json() breaks Stripe and GitHub webhook HMAC

`express.json()` (and `bodyParser.json()`, and Next.js `req.json()`) turn the body into an object. Your handler is happier. The signature check is dead.

Stripe, GitHub, Slack, Shopify, Clerk, and Svix HMAC the **bytes on the wire**. Spaces, key order, and a trailing newline are part of the seal. `JSON.stringify(JSON.parse(body))` is a different string. The header will never match.

## What you see

Stripe / stripe-node:

```
No signatures found matching the expected signature for payload
Are you passing the raw request body you received from Stripe?
```

GitHub: `X-Hub-Signature-256` compares false. Slack: `invalid_signature`. Shopify: HMAC validation failed.

doorbell-js does not guess. If the Express body is already an object, it says the body was parsed and points at `express.raw()` or `preserveRawBody`.

## Keep json() for the rest of the app

```js
import express from 'express'
import { doorbell, preserveRawBody } from 'doorbell-js'

const app = express()
app.use(express.json({ verify: preserveRawBody }))

app.post('/webhooks/stripe', doorbell({
  stripe: { secret: process.env.STRIPE_WEBHOOK_SECRET, onAny: async () => {} },
}).express)
```

`verify` runs on the raw buffer before parse. doorbell HMAC that copy.

## Or isolate the route

```js
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), hooks.express)
app.use(express.json())
```

Order matters. If `app.use(express.json())` is above the webhook, the raw parser never sees the bytes.

## Next.js

App Router: pass the `Request` through. Do not `await req.json()`.

```js
export const POST = doorbell({ stripe: { secret: process.env.STRIPE_WEBHOOK_SECRET, onAny: async () => {} } })
```

Pages Router: `bodyParser: false` on that API route, then read the stream.

## Fastify and Hono

Fastify: `addContentTypeParser('application/json', { parseAs: 'buffer' }, captureFastifyBuffer)` then `hooks.fastify`. Hono already has the raw `Request`.

## Related

- [Stripe webhook signature in Node.js](stripe-webhook-signature-nodejs.md)
- [FAQ](faq.md)
- [README](../README.md)
