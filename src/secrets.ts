import { DoorbellError, secretHint } from './errors.js'
import type { ProviderName } from './providers/types.js'

export function lintSecret(provider: ProviderName, secret: string): void {
  const s = secret.trim()
  if (s.length === 0) return

  if (provider === 'stripe') {
    if (/^sk_(live|test)_/.test(s) || /^pk_(live|test)_/.test(s) || /^rk_(live|test)_/.test(s)) {
      throw new DoorbellError('That is a Stripe API key, not a webhook secret.', {
        code: 'wrong_secret',
        status: 500,
        hint: secretHint('stripe'),
      })
    }
    if (!s.startsWith('whsec_')) {
      throw new DoorbellError('Stripe webhook secrets start with whsec_.', {
        code: 'wrong_secret',
        status: 500,
        hint: secretHint('stripe'),
      })
    }
  }

  if (provider === 'github' && /^(ghp_|github_pat_|gho_|ghu_|ghs_)/.test(s)) {
    throw new DoorbellError('That is a GitHub token, not the webhook Secret field.', {
      code: 'wrong_secret',
      status: 500,
      hint: secretHint('github'),
    })
  }

  if (provider === 'slack' && /^(xox[bpasr]-|xapp-)/.test(s)) {
    throw new DoorbellError('That is a Slack token, not the Signing Secret.', {
      code: 'wrong_secret',
      status: 500,
      hint: secretHint('slack'),
    })
  }

  if ((provider === 'svix' || provider === 'clerk' || provider === 'resend') && /^sk_(live|test)_/.test(s)) {
    throw new DoorbellError('That looks like a Stripe secret key, not a Standard Webhooks secret.', {
      code: 'wrong_secret',
      status: 500,
      hint: secretHint(provider),
    })
  }
}
