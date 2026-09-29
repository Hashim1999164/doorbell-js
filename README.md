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

If `express.json()` already runs for the rest of the app, keep the bytes:

```js
import express from 'express'
import { doorbell, preserveRawBody } from 'doorbell-js'

const app = express()
app.use(express.json({ verify: preserveRawBody }))

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

app.post('/webhooks/github', hooks.express)
```

Or give that route `express.raw({ type: 'application/json' })` and skip the global parser.

If you parsed the body and did not keep the bytes, doorbell tells you. In English.

Fastify people: `addContentTypeParser('application/json', { parseAs: 'buffer' }, captureFastifyBuffer)` then `hooks.fastify`.

## The part people get wrong

Stripe signs `timestamp + '.' + raw bytes`.

Not the JSON object. Not `JSON.stringify(JSON.parse(body))`. Not a UTF-8 round trip of those bytes.

stripe-node itself decodes the body to a string before HMAC. That is how a payload with a stray 0xFF byte verifies in one library and fails in another. doorbell HMAC the bytes that arrived. Then it copies them, so a shared Buffer from Express cannot change under the check.

If a proxy or `express.json()` rewrites whitespace, the seal check fails forever and you will think the secret is wrong.

`whsec_` is also not one thing. Stripe uses the whole string as the HMAC key. Svix / Clerk / Resend strip `whsec_` and base64-decode the rest. Same prefix, different math. Mix them up and every request looks forged.

Compare the digest bytes, not the header string. `===` on hex is how you leak the secret one character at a time.

## Time

HMAC first, then the clock. stripe-node does it that way. A wrong secret on an old event says the signature is wrong, not that the timestamp is old.

Stripe-node only rejects events that are too old. A Stripe timestamp two minutes in the future still verifies. doorbell matches that, because your handler should not disagree with `constructEvent`.

Slack, Svix, Clerk, Resend, Paddle, and Linear reject both too old and too new. Linear needs `webhookTimestamp` in the signed JSON. A timestamp from next week is how you stash a signed body and replay it when the clock catches up.

If more than one provider sniffs the same request, doorbell refuses it. A proxy that tacks on `Stripe-Signature` next to a real GitHub hook will not silently verify as Stripe and fail the HMAC. Put the name in the path (`/webhooks/github`). Path wins over headers. A path with `.` or `..` (including `%2e%2e`) is refused. Express `originalUrl` can still carry those. `new URL` would turn `/webhooks/github/../stripe` into Stripe. The Fetch `Request` URL is already resolved, so this check is for the Express and Fastify paths.

Shopify HMAC is the body only. `X-Shopify-Triggered-At` is not signed, so doorbell does not clock on it. An attacker who captured a valid body can set that header to now.

GitHub HMAC is the body only. `X-GitHub-Delivery` and `X-GitHub-Event` are not signed. Doorbell keys GitHub/Shopify/Meta retries on a hash of the raw bytes, not those headers. If the signed JSON looks like a ping, push, issues, pull_request, or gollum, `event.type` comes from that JSON. Unknown GitHub shapes are type `github`. `on['member']` does not run on a captured wiki body. A delete body labelled create is refused.

Shopify is the same trap. `X-Shopify-Topic` is not signed. An order body is type `orders`, not `orders/paid`. GDPR bodies with `orders_requested` / `orders_to_redact` are those types. `shop/redact` is only when the JSON is exactly `shop_id` and `shop_domain`. Other bodies are type `shopify`. `on['app/uninstalled']` does not run from that header. Use `on.orders`, `on.shopify`, or `onAny` and read the payload.

Stripe Connect: `event.account` is the `account` field on the signed JSON. `Stripe-Account` is not in the HMAC, so it is ignored.

Slack `event_callback` is typed from the inner `event.type` in the JSON (`event_callback.message`). That inner object is signed. The Slack retry headers are not.

A missing signature header still runs HMAC, so that path is not faster than a bad one.

Default window is 5 minutes. Fix NTP. Do not turn this off in production.

## Headers

Signature headers that contain a newline or that are bigger than 8KB are refused before parse. Sixteen v1 signatures is enough. More than that is someone burning CPU.

Meta `hub.verify_token` is hashed, then compared in constant time, so a short guess is not a shorter compare. Slack URL verification still waits for HMAC. There is no unsigned POST shortcut.

GitHub and Meta need `sha256=` on the signature header. Bare hex is refused. Standard Webhooks only uses `v1` signatures. A `v0` leftover is ignored, not treated as a MAC.

## Who can knock

| Provider | Notes |
| --- | --- |
| Stripe | Endpoint signing secret. Not `sk_live_`. Future timestamps allowed, old ones not. |
| GitHub | Webhook Secret field. Ping is the signed `zen` field. Known shapes take `event.type` from the JSON. Unknown shapes are type `github`. Not a PAT. |
| Slack | Signing Secret. URL verification is answered after HMAC. `event_callback.message` comes from the signed inner event. Not `xoxb-`. |
| Shopify | `X-Shopify-Hmac-Sha256` over the body. Topic is not signed. An order body is type `orders`. GDPR shapes come from the JSON. Other bodies are type `shopify`. |
| Svix / Clerk / Resend | Standard Webhooks. Path required if you take more than one. Both-way clock. |
| Linear, Paddle | Hex / `ts;h1`. Linear requires `webhookTimestamp` in the signed JSON. |
| Meta | POST signed. Sniffs `X-Hub-Signature-256` without requiring the old sha1 header. GET `hub.challenge` needs `verifyToken` |
| Twilio | Auth token plus the public URL Twilio called. Trailing slash on that URL is tried both ways. |

## What it will not do for you

Unknown event types return 200. Stripe retries 5xx. You do not want a week of `customer.updated`.

A handler crash returns 500 so the sender retries.

Same signed body twice returns 200 and skips the work. For Stripe that is `event.id`. For GitHub and Shopify it is a hash of the bytes, because their id headers are unsigned. Two copies at once wait on the first one. A stuck inflight claim expires after a minute so the next delivery is not wedged. If this process is still running that work, the slot stays pinned until it finishes. Timeout plus one minute is not enough if the handler is slower than that.

Default body cap is 5MB. The fetch path stops reading once the cap is hit, so a 50MB POST is not fully buffered then rejected. Each stream chunk is copied, because some runtimes reuse the same Uint8Array for the next read. A lying Content-Length does not 413 a body that still fits. `handlerTimeoutMs` returns 500 so the sender retries. It does not abort the handler. Abort after a write is how a late throw drops inflight and Stripe fulfills twice. The inflight slot stays until that work actually finishes. If it later succeeds, the retry is a duplicate. If it later throws, the retry can run.

## Tests

```js
import { signStripe } from 'doorbell-js'

const body = '{"id":"evt_test","type":"ping"}'
const header = await signStripe(body, process.env.STRIPE_WEBHOOK_SECRET, Math.floor(Date.now() / 1000))
```

## License

MIT. Hashim Khan.
