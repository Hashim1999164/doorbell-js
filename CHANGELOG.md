# Changelog

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
