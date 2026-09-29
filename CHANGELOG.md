# Changelog

## 1.2.0

Stripe clock matches stripe-node: too old fails, future timestamps pass. Slack, Svix, Paddle, Linear reject both directions.

Copy the body before HMAC so a shared Buffer cannot move. Refuse signature headers with newlines or a silly size. Compare Meta handshake tokens in constant time. Slack challenge only after HMAC. Fastify helper copies the buffer.

## 1.1.0

HMAC over prefix + raw bytes, never a UTF-8 round trip. Compare digests, not header strings. Keep Express bytes with preserveRawBody. Refuse API keys at boot. Body cap, handler timeout, Fastify and Hono adapters.

## 1.0.1

HMAC works on Node 18.

## 1.0.0

First cut. Stripe, GitHub, Slack, Shopify, Svix/Clerk/Resend, Linear, Paddle, Meta handshake, Twilio.
