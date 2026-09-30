# doorbell-js

**Webhook signature verification for Node.js.** One handler for Stripe, GitHub, Slack, Shopify, Clerk, Svix, Resend, Linear, Paddle, Meta, and Twilio.

HMAC the raw bytes Stripe actually signed. Not `JSON.parse`. Not `JSON.stringify`. That is the whole library.

```sh
npm i doorbell-js
```

Site: [hashim1999164.github.io/doorbell-js](https://hashim1999164.github.io/doorbell-js/)

[Stripe webhook signature](#verify-a-stripe-webhook-in-nextjs) · [GitHub HMAC](#verify-a-github-webhook-in-express) · [express.json raw body](docs/express-json-raw-body.md) · [FAQ](docs/faq.md) · [Why constructEvent fails](docs/stripe-webhook-signature-nodejs.md)

## Verify a Stripe webhook in Next.js

`export const POST = doorbell(...)` is the App Router route. Do not call `req.json()`. `constructEvent` needs the same raw body Stripe hashed.

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

If you already have `express.json()` for the rest of the app, keep the bytes with `preserveRawBody`. Full writeup: [Stripe webhook signature verification in Node.js](docs/stripe-webhook-signature-nodejs.md).

## Verify a GitHub webhook in Express

GitHub sends `X-Hub-Signature-256`. The HMAC is over the body only. `X-GitHub-Event` is not signed.

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

Or give that route `express.raw({ type: 'application/json' })` and skip the global parser. If the body was already parsed, doorbell says so in English. [Why express.json breaks webhook HMAC](docs/express-json-raw-body.md).

Fastify: `addContentTypeParser('application/json', { parseAs: 'buffer' }, captureFastifyBuffer)` then `hooks.fastify`. Hono: `hooks.hono`.

## Why Stripe says no signatures found

The Stripe Dashboard error is:

`No signatures found matching the expected signature for payload`

Almost always one of these:

1. `express.json()`, `bodyParser`, or `req.json()` ran first. The HMAC is over the exact bytes on the wire, including spaces.
2. You used `sk_live_` / `sk_test_` instead of the endpoint signing secret (`whsec_`).
3. You used the Stripe CLI secret on a Dashboard endpoint, or the other way around. Both start with `whsec_`. They are different keys.
4. A proxy rewrote whitespace.

doorbell HMAC the copy of the bytes, then parse. stripe-node `constructEvent` decodes the body to a string first. A payload with a stray `0xFF` byte can verify in one library and fail in the other.

[Longer version with Express and Next.js](docs/stripe-webhook-signature-nodejs.md).

## The part people get wrong

Stripe signs `timestamp + '.' + raw bytes`.

Not the JSON object. Not `JSON.stringify(JSON.parse(body))`. Not a UTF-8 round trip of those bytes.

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

`Origin` and `Referer` are refused. Browsers send them. Stripe does not. Set `allowOrigin` / `allowReferer` if a proxy adds them. `X-HTTP-Method-Override` is refused so a POST cannot skip HMAC and hit the Meta handshake. `Content-Encoding: gzip` is refused. HMAC is over the bytes we read, not the decompressed JSON.

Unsigned headers still cost RAM. The default header budget is 32KB (`maxHeaderBytes`).

Express does not take `req.get('host')`. That follows `trust proxy` and `X-Forwarded-Host`. doorbell reads the `Host` header. Twilio URLs are `https` unless the host is loopback. Set `publicUrl` to the URL Twilio called. `http` to a public host needs `allowInsecureTwilioUrl`.

`text/html` is refused. Fetch sets `text/plain` on a string body. That is fine. JSON providers also take `application/json`.

`pathOnly: true` means the URL has to name the provider. Signature headers are not a name.

## After HMAC

The body still has to be a JSON object. A signed `"true"` or a JSON array is not an event. Nesting, key count, and one string field have a budget (`maxJsonDepth`, `maxJsonKeys`, `maxJsonString`) so a signed nest bomb does not blow the stack in your handler. A UTF-8 BOM is stripped for parse only. The HMAC still ran on the raw bytes, BOM included.

Event ids longer than 256 characters, or with a character that is not `[a-zA-Z0-9._:-]`, become a hash of the body. The store will not take `evt foo/../bar` as a Redis key. Event types longer than 128 characters, or with a control character, become `unknown`.

A signing secret shorter than 8 characters is refused at boot. A secret with a newline or NUL was pasted wrong. GitHub lets you type `x`. That is not a secret. Eight rotation secrets is enough. The in-memory store drops the oldest unpinned slot at 50,000 unique ids. Extra retries of one inflight id share 64 waiter slots.

## Webhook providers

| Provider | Header | Notes |
| --- | --- | --- |
| [Stripe](docs/stripe-webhook-signature-nodejs.md) | `Stripe-Signature` | Endpoint signing secret. Not `sk_live_`. Future timestamps allowed, old ones not. |
| GitHub | `X-Hub-Signature-256` | Webhook Secret field. Ping is the signed `zen` field. Known shapes take `event.type` from the JSON. |
| Slack | `X-Slack-Signature` | Signing Secret. URL verification is answered after HMAC. Not `xoxb-`. |
| Shopify | `X-Shopify-Hmac-Sha256` | Topic is not signed. An order body is type `orders`. |
| Svix / Clerk / Resend | `svix-signature` | Standard Webhooks. Path required if you take more than one. Both-way clock. |
| Linear, Paddle | `Linear-Signature` / `Paddle-Signature` | Linear requires `webhookTimestamp` in the signed JSON. |
| Meta | `X-Hub-Signature-256` | GET `hub.challenge` needs `verifyToken`. |
| Twilio | `X-Twilio-Signature` | Auth token plus the public URL Twilio called. `http` is only localhost. Set `publicUrl`. |

## doorbell vs stripe-node vs rolling your own

| | doorbell-js | stripe-node `constructEvent` | `crypto.createHmac` in the route |
| --- | --- | --- | --- |
| Stripe | yes | yes | if you get the prefix right |
| GitHub, Slack, Shopify, Clerk | yes | no | one more function each |
| HMAC input | raw bytes | UTF-8 string | whatever you passed |
| `express.json()` already ran | tells you | "no signatures found" | silent fail |
| Timing-safe compare | digest bytes | yes | easy to `===` hex |
| Next.js App Router | the export is the route | you still need the raw body | you still need the raw body |

## What it will not do for you

Unknown event types return 200. Stripe retries 5xx. You do not want a week of `customer.updated`.

A handler crash returns 500 so the sender retries.

Same signed body twice returns 200 and skips the work. For Stripe that is `event.id`. For GitHub and Shopify it is a hash of the bytes, because their id headers are unsigned. Two copies at once wait on the first one. A stuck inflight claim expires after a minute so the next delivery is not wedged. If this process is still running that work, the slot stays pinned until it finishes.

Default body cap is 5MB. The fetch path stops reading once the cap is hit. `handlerTimeoutMs` returns 500 so the sender retries. It does not abort the handler.

## Tests

```js
import { signStripe } from 'doorbell-js'

const body = '{"id":"evt_test","type":"ping"}'
const header = await signStripe(body, process.env.STRIPE_WEBHOOK_SECRET, Math.floor(Date.now() / 1000))
```

## FAQ

Common errors live in [docs/faq.md](docs/faq.md). Short version:

**No signatures found matching the expected signature for payload.** The body was parsed, or the `whsec_` is the wrong one. [Stripe writeup](docs/stripe-webhook-signature-nodejs.md).

**Webhook signature verification failed.** Same family. Print the secret prefix. If it is `sk_`, that is the API key.

**GitHub X-Hub-Signature-256 missing.** The webhook has no Secret set. Empty secret means anyone can POST.

**Slack invalid_signature.** Need `X-Slack-Signature` and `X-Slack-Request-Timestamp`. The Signing Secret, not the bot token.

## License

MIT. Hashim Khan. [github.com/Hashim1999164/doorbell-js](https://github.com/Hashim1999164/doorbell-js)
