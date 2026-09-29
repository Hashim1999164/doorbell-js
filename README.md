# doorbell

Stripe knocks on your server. GitHub knocks. Slack knocks.

You should not be writing HMAC code at 1am for the fifth time this year.

```sh
npm i doorbell-js
```

## Next.js

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

That function *is* the route. Do not call `req.json()`. The whole point is the raw bytes.

## Express

Express will eat the body if you let it. This route needs `express.raw`.

```js
import express from 'express'
import { doorbell } from 'doorbell-js'

const app = express()
const hooks = doorbell({
  github: {
    secret: process.env.GITHUB_WEBHOOK_SECRET,
    on: {
      'issues.opened': async (event) => {
        console.log('issue', event.id)
      },
    },
  },
})

app.post(
  '/webhooks/github',
  express.raw({ type: 'application/json' }),
  hooks.express,
)
```

If you put `express.json()` first, doorbell will tell you. In English.

## Who can knock

| Provider | Notes |
| --- | --- |
| Stripe | `whsec_...` is the HMAC key as text. Not the API key. |
| GitHub | Secret from the webhook settings. Ping is answered for you. |
| Slack | Signing secret, not the bot token. URL verification is answered for you. |
| Shopify | HMAC in `X-Shopify-Hmac-Sha256` |
| Svix / Clerk / Resend | Standard Webhooks. Secret is `whsec_` plus base64 key bytes. Different from Stripe. |
| Linear, Paddle | Hex / `ts;h1` as their docs say |
| Meta | POST is signed. GET `hub.challenge` needs `verifyToken` |
| Twilio | Needs the public URL Twilio called |

Put the name in the path (`/webhooks/stripe`) or send the usual headers and doorbell will sniff.

Clerk and Resend look identical on the wire. If you take both, use the path.

## What it will not do for you

It will not 500 on an event type you did not subscribe to. Stripe retries 5xx. You would get a week of `customer.updated` noise. Unknown types return 200.

It will not 200 on a handler crash. That one *should* retry.

Same event id twice returns 200 and skips the handler.

Default replay window is 5 minutes.

## Tests

```js
import { signStripe } from 'doorbell-js'

const body = '{"id":"evt_test","type":"ping"}'
const header = await signStripe(body, process.env.STRIPE_WEBHOOK_SECRET, Math.floor(Date.now() / 1000))
```

## License

MIT. Hashim Khan.
