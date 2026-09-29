# GitHub webhook HMAC in Node.js (X-Hub-Signature-256)

GitHub signs the **raw body** with HMAC-SHA256. The header is `sha256=` plus hex. There is no timestamp in the HMAC.

`X-GitHub-Event` and `X-GitHub-Delivery` are not signed. Anyone who captured a valid body can change those headers. doorbell-js does not dispatch `on.gollum` because a header said gollum. If the signed JSON looks like a push, it is a push.

## Secret field, not a PAT

The key is the string from the webhook **Secret** box. `GITHUB_TOKEN`, `ghp_`, and `github_pat_` are the wrong thing. doorbell refuses those at boot.

If `X-Hub-Signature-256` is missing, the hook was saved with an empty secret. Anyone can POST.

GitHub still sends the old `X-Hub-Signature` (sha1). doorbell wants `sha256=`. Bare hex is refused.

## Express

```js
import express from 'express'
import { doorbell, preserveRawBody } from 'doorbell-js'

const app = express()
app.use(express.json({ verify: preserveRawBody }))

app.post('/webhooks/github', doorbell({
  github: {
    secret: process.env.GITHUB_WEBHOOK_SECRET,
    on: {
      'issues.opened': async (event) => console.log(event.id),
    },
  },
}).express)
```

Same raw-body rule as Stripe. [express.json() note](express-json-raw-body.md).

## Ping

A GitHub ping is the signed `zen` field. Setting `X-GitHub-Event: ping` on a captured push body does not skip your handler.

## Idempotency

Because the delivery id is unsigned, doorbell keys retries on a hash of the raw bytes, not `X-GitHub-Delivery`.

## Related

- [FAQ](faq.md)
- [README](../README.md)
