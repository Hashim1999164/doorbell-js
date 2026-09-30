# Changelog

## 1.12.0

Express `req.get('host')` follows `trust proxy`. That is `X-Forwarded-Host`. Twilio HMAC includes the public URL, so a forwarded Host would verify a different URL than the one Twilio signed, or `http` when the box is behind TLS. doorbell reads the `Host` header only. It uses `https` unless the host is localhost, `127.0.0.1`, or `::1`. `http` to a public host is refused unless `allowInsecureTwilioUrl` is on. Set `publicUrl` in production.

`Referer` is refused like `Origin`. Unsigned header bytes have a budget (`maxHeaderBytes`). A signing secret with a NUL or other control character is refused at boot. After HMAC, one JSON string still has a size cap (`maxJsonString`). Event ids that are not `[a-zA-Z0-9._:-]` become a body fingerprint so a Redis key cannot be `stripe:evt foo/../bar`. Event types longer than 128 characters, or with a control character, become `unknown`. Concurrent retries of one inflight id share a waiter cap (`maxStoreWaiters`) instead of growing an array forever.

## 1.11.0

`pathOnly` refuses to pick a provider from signature headers. The path has to name who knocked.

PUT is 405 unless `allowPut` is on. `Content-Encoding` other than identity is refused so HMAC is not run on gzip of the JSON Stripe signed. `Origin` is refused (browsers send it, Stripe does not). `X-HTTP-Method-Override` is refused so POST cannot turn into a Meta GET handshake. A huge URL is refused.

JSON after HMAC has to be an object, not `"true"` or an array. Nest depth and key count have a budget. A UTF-8 BOM is stripped for parse only. The HMAC still sees the raw bytes. Event ids longer than 256 characters become a body fingerprint so the store cannot be keyed on a 10k string.

Signing secrets shorter than 8 characters are refused at boot. Eight rotation secrets is the default cap. The in-memory store evicts oldest unpinned slots at 50,000.

Fetch string bodies send `text/plain`. That is allowed. `text/html` is not.

## 1.10.0

A path with `.` or `..` (including `%2e%2e`) is refused. `new URL` would turn `/webhooks/github/../stripe` into Stripe and run the wrong provider.

Standard Webhooks only takes `v1` signatures. The leftover `v1` token and `v0` parts are not MACs. GitHub and Meta need `sha256=` on the header. Bare hex is refused.

Meta sniffs sha256 without requiring the old sha1 header. The GET handshake hashes both tokens before compare so a short guess is not a shorter compare. GitHub ping is the `zen` key, even if the string is empty. Shopify `shop/redact` is only the two GDPR keys. Discussion comes from the signed JSON.

## 1.9.0

Two signature header families on one request no longer pick the first sniff hit. Extra `Stripe-Signature` on a GitHub hook is ambiguous unless the path names the provider.

Linear without `webhookTimestamp` in the signed JSON is refused. That field is the replay clock. Missing used to mean forever.

Slack `event_callback` takes `event.type` from the signed inner object. Shopify GDPR shapes (`orders_requested`, `orders_to_redact`, shop_id + shop_domain) take type from the JSON. Stripe Connect `event.account` is the signed `account` field, not `Stripe-Account`. Fetch copies each stream chunk so a reused buffer cannot rewrite the body after HMAC.

GitHub `commit_comment` comes from `commit_id` in the JSON.

## 1.8.0

Unknown GitHub and Shopify shapes no longer take `event.type` from unsigned headers. A captured wiki body labelled `member` does not run `on.member`. A captured uninstall body labelled `customers/data_request` does not run that handler. Those are type `github` / `shopify`. Gollum is inferred from `pages`.

Inflight pin happens in `claim`, so expiry cannot steal the slot before `pin()`.

The fetch path does not 413 on Content-Length. It caps on bytes actually read. Twilio parse keeps duplicate form keys the HMAC saw. Paddle header values keep text after the first `=`.

## 1.7.0

Inflight expiry still stole the slot while a timed out handler was writing. Pin the claim until that work commits or drops.

GitHub `event.type` for known shapes comes from the signed JSON, including create vs delete. Shopify order bodies are type `orders`. `on['orders/paid']` does not run from the unsigned topic header.

## 1.6.0

Timeout was still aborting the handler. A handler that already wrote the DB then saw AbortError, dropped inflight, and Stripe retried into a second fulfill. 1.6.0 returns 500 to the sender and leaves the work running. Late success commits. Late throw drops.

GitHub and Shopify now infer the event family from the signed JSON first. If the body looks like a push or an order, an unsigned header like `gollum` or `app/uninstalled` is refused. Bodies that do not look like those families stay fail-open after HMAC.

## 1.5.0

A handler timeout no longer drops the inflight claim while that work is still running. Stripe retry used to start a second handler. Now the slot stays until the first work settles: success commits (retry is a duplicate), throw drops (retry can run). Inflight hold is at least one minute, or `handlerTimeoutMs` plus one minute.

The fetch path stops reading at `maxBodyBytes`. The cap is checked before copying the buffer.

GitHub ping, push, issues, pull_request, and a few other common events have to match the signed JSON. Shopify `orders/`, `checkouts/`, and `products/` topics do the same. Unknown events stay fail-open after HMAC.

Unix timestamps have to be a digit string. Base64 signatures that Node would still decode with junk in them are rejected.

## 1.4.0

GitHub, Shopify, and Meta HMAC the body only. Delivery id, webhook-id, and triggered-at are not in that HMAC, so they are not a clock and not an idempotency key. Those providers key retries on a fingerprint of the raw bytes.

Linear keys on `webhookId` from the signed JSON. Two Issue.create events are two events.

GitHub ping is the signed `zen` field. Setting `X-GitHub-Event: ping` on a captured push body does not skip your handler.

JSON.parse drops `__proto__` and constructor objects. Express header arrays for GitHub/Shopify keep the first value. Stripe signature arrays still comma-join, because that is how Stripe sends v1 list.

## 1.3.0

HMAC first, then the clock, the way stripe-node does. A missing header still burns HMAC so it is not a faster path. Inflight idempotency claims expire. Shopify checks `X-Shopify-Triggered-At` when it is present. Twilio tries the public URL with and without a trailing slash.

## 1.2.0

Stripe clock matches stripe-node: too old fails, future timestamps pass. Slack, Svix, Paddle, Linear reject both directions.

Copy the body before HMAC so a shared Buffer cannot move. Refuse signature headers with newlines or a silly size. Compare Meta handshake tokens in constant time. Slack challenge only after HMAC. Fastify helper copies the buffer.

## 1.1.0

HMAC over prefix + raw bytes, never a UTF-8 round trip. Compare digests, not header strings. Keep Express bytes with preserveRawBody. Refuse API keys at boot. Body cap, handler timeout, Fastify and Hono adapters.

## 1.0.1

HMAC works on Node 18.

## 1.0.0

First cut. Stripe, GitHub, Slack, Shopify, Svix/Clerk/Resend, Linear, Paddle, Meta handshake, Twilio.
