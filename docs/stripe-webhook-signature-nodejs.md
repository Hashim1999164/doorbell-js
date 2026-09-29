# Stripe webhook signature verification in Node.js

Stripe signs each webhook with HMAC-SHA256 over `timestamp + '.' + raw body`. The header looks like `t=1710000000,v1=hex`. If those bytes change before you check the header, you get:

```
No signatures found matching the expected signature for payload
```

That sentence is from stripe-node `constructEvent`. doorbell-js hits the same math, then tells you what you fed it.

## The three inputs

1. The **raw request body**. Not `req.body` after `express.json()`. Not `await req.json()` in Next.js.
2. The **`Stripe-Signature` header**.
3. The **endpoint signing secret**. It starts with `whsec_`. It is not `sk_live_` or `sk_test_`.

The Dashboard secret and the `stripe listen` secret both start with `whsec_`. They are different keys. A CLI event will not verify with the Dashboard secret.

## Next.js App Router

```js
import { doorbell } from 'doorbell-js'

export const POST = doorbell({
  stripe: {
    secret: process.env.STRIPE_WEBHOOK_SECRET,
    on: {
      'checkout.session.completed': async (event) => {
        await fulfill(event.payload)
      },
    },
  },
})
```

Do not call `req.json()` first. The exported function *is* the route.

## Express

`express.json()` before the webhook route is the usual footgun. Two ways out:

```js
import express from 'express'
import { doorbell, preserveRawBody } from 'doorbell-js'

const app = express()
app.use(express.json({ verify: preserveRawBody }))

const hooks = doorbell({
  stripe: {
    secret: process.env.STRIPE_WEBHOOK_SECRET,
    on: { 'checkout.session.completed': async (event) => fulfill(event.payload) },
  },
})

app.post('/webhooks/stripe', hooks.express)
```

Or mount the webhook on `express.raw({ type: 'application/json' })` and keep `express.json()` off that path. Longer note: [express.json and webhook HMAC](express-json-raw-body.md).

## doorbell vs constructEvent

stripe-node decodes the body to a UTF-8 string, then HMAC. doorbell HMAC the bytes that arrived, then copies them so a shared Express Buffer cannot move.

A payload with a stray `0xFF` byte can verify in one library and fail in the other. If you need to agree with `constructEvent` on dirty bytes, you already have a worse problem than which library you picked.

Stripe-node only rejects timestamps that are too old. A timestamp two minutes in the future still verifies. doorbell matches that.

## Secret lint

doorbell refuses `sk_live_`, `sk_test_`, `pk_*`, and `rk_*` at boot. If you stuffed the API key into `STRIPE_WEBHOOK_SECRET`, you find out when the process starts, not after the tenth unpaid invoice.

## Related

- [FAQ](faq.md)
- [express.json raw body](express-json-raw-body.md)
- [doorbell-js README](../README.md)
