export class DoorbellError extends Error {
  readonly code: string
  readonly hint: string | undefined
  readonly status: number

  constructor(
    message: string,
    opts: { code: string; hint?: string; status?: number; cause?: unknown },
  ) {
    super(message, opts.cause !== undefined ? { cause: opts.cause } : undefined)
    this.name = 'DoorbellError'
    this.code = opts.code
    this.hint = opts.hint
    this.status = opts.status ?? 400
  }

  toText(): string {
    if (this.hint) return `${this.message}\n\n${this.hint}`
    return this.message
  }
}

export function parsedBodyError(): DoorbellError {
  return new DoorbellError(
    'This body was already parsed. Signature checks need the raw bytes.',
    {
      code: 'parsed_body',
      status: 400,
      hint: [
        'express.json(), bodyParser, and req.json() all chew the body first.',
        'The HMAC is over the exact bytes on the wire, including spaces and newlines.',
        '',
        'Express:',
        "  app.post('/webhooks', express.raw({ type: 'application/json' }), handler.express)",
        '',
        'Next.js App Router: pass the Request through. Do not call req.json() first.',
        '  export const POST = doorbell({ ... })',
      ].join('\n'),
    },
  )
}

export function missingSecretError(provider: string): DoorbellError {
  return new DoorbellError(`No signing secret for ${provider}.`, {
    code: 'missing_secret',
    status: 500,
    hint: `Set it at boot, not inside the request. ${secretHint(provider)}`,
  })
}

export function secretHint(provider: string): string {
  switch (provider) {
    case 'stripe':
      return 'Stripe wants the endpoint signing secret. It starts with whsec_. It is not the API key (sk_live_...).'
    case 'github':
      return 'GitHub wants the string from the webhook Secret field. Not a PAT. Not GITHUB_TOKEN.'
    case 'slack':
      return 'Slack wants the Signing Secret from the app Basic Information page. Not the bot token.'
    case 'shopify':
      return 'Shopify wants the app client secret, or the webhook signing secret, depending on how you registered the hook.'
    case 'svix':
    case 'clerk':
    case 'resend':
      return 'This one is Standard Webhooks. The secret starts with whsec_ and the bytes after that are base64, unlike Stripe where the whole string is the HMAC key.'
    case 'twilio':
      return 'Twilio signs with the Auth Token. You also have to pass the public URL Twilio called, not req.url on localhost.'
    case 'meta':
      return 'Meta uses the App Secret for POST signatures, and a verify token you choose for the GET handshake.'
    default:
      return 'Use the webhook signing secret from that provider dashboard, not an API token.'
  }
}
