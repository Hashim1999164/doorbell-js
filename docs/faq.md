# doorbell-js FAQ

Webhook signature errors, raw body, and the usual secret mixups. Library: [doorbell-js](https://github.com/Hashim1999164/doorbell-js).

## No signatures found matching the expected signature for payload

Stripe said the HMAC did not match. The body changed, or the secret is wrong.

- `express.json()` or `req.json()` ran first. [Raw body note](express-json-raw-body.md).
- Secret is `sk_live_...`. You want `whsec_...` from the webhook endpoint, not the API key.
- Dashboard `whsec_` used on a `stripe listen` event, or the other way around.

[Stripe webhook signature verification in Node.js](stripe-webhook-signature-nodejs.md).

## Webhook signature verification failed

Same family as above. Print the first six characters of the secret. `sk_` is the API key. `whsec_` is the webhook secret.

## Are you passing the raw request body you received from Stripe?

Yes, that is the question. If anything parsed or pretty-printed the JSON, the answer is no.

## GitHub webhook secret vs GITHUB_TOKEN

`X-Hub-Signature-256` uses the string from the webhook **Secret** field. A PAT or `GITHUB_TOKEN` will never verify. doorbell refuses `ghp_` and `github_pat_` at boot.

If the header is missing, the webhook has no secret set. Anyone can POST.

## Slack invalid_signature / Signing Secret vs bot token

Need `X-Slack-Signature` and `X-Slack-Request-Timestamp`. The Signing Secret is on the app Basic Information page. It is not `xoxb-`. doorbell refuses Slack tokens at boot.

URL verification (`url_verification`) is answered after HMAC. There is no unsigned POST shortcut.

## Shopify HMAC validation failed

`X-Shopify-Hmac-Sha256` is Base64 over the raw body. Topic, shop domain, and `X-Shopify-Triggered-At` are not in that HMAC. doorbell does not clock on the unsigned timestamp.

`X-Shopify-Topic` is not signed. An order body is type `orders`, not `orders/paid`.

## Clerk / Svix / Resend signature failed

Standard Webhooks. Headers are `svix-id`, `svix-timestamp`, `svix-signature` (or the unbranded `webhook-*` names). The secret starts with `whsec_`, then the bytes after that are base64. That is not how Stripe uses `whsec_`.

If you configured more than one of Clerk, Resend, and Svix, put the name in the path (`/webhooks/clerk`). They look the same on the wire.

## Linear replay / missing webhookTimestamp

Linear HMAC is the body. The replay clock is `webhookTimestamp` **inside** the signed JSON. doorbell refuses a body without that field. A captured payload cannot be posted forever.

## Twilio signature did not match

Twilio HMAC-SHA1 is `public URL + sorted form fields`. `req.url` on localhost is not the URL Twilio called. Pass `publicUrl`. Trailing slash is tried both ways.

## Next.js Stripe webhook 400

You called `req.json()` or the Pages body parser. Use the App Router export, or disable `bodyParser` and read the raw stream.

## Can I use PUT?

Stripe and GitHub POST. doorbell returns 405 on PUT unless `allowPut` is on.

## Does Origin work?

Browsers send `Origin`. Stripe does not. doorbell refuses it so a form on another site never reaches HMAC. Set `allowOrigin` if a proxy adds the header.

## License

MIT. [Hashim1999164/doorbell-js](https://github.com/Hashim1999164/doorbell-js)
