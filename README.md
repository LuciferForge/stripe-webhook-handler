# stripe-webhook-handler

Handle Stripe webhooks with **signature verification** and **zero dependencies**. The part everyone gets wrong — done right.

## Why This Exists

Stripe webhook signature verification is the #1 thing AI gets wrong when writing from scratch. The signed payload format (`timestamp.body`), the HMAC comparison, the replay attack protection — one mistake and your webhooks either reject everything or accept anything.

This handles it correctly. Copy and customize.

## Quick Start

```bash
git clone https://github.com/LuciferForge/stripe-webhook-handler.git
cd stripe-webhook-handler

# Set your webhook secret (from Stripe Dashboard → Developers → Webhooks)
export STRIPE_WEBHOOK_SECRET="whsec_..."

# Run
python3 webhook.py

# Test with Stripe CLI
stripe listen --forward-to localhost:8000/webhook
```

## What's Handled

| Event | Handler | What to Add |
|-------|---------|-------------|
| `checkout.session.completed` | `on_checkout_completed()` | Fulfill order, send confirmation |
| `invoice.paid` | `on_invoice_paid()` | Extend subscription access |
| `invoice.payment_failed` | `on_invoice_failed()` | Notify customer, start dunning |
| `customer.subscription.created` | `on_subscription_created()` | Provision access |
| `customer.subscription.updated` | `on_subscription_updated()` | Update access level |
| `customer.subscription.deleted` | `on_subscription_deleted()` | Revoke access |
| `payment_intent.succeeded` | `on_payment_succeeded()` | Deliver product |
| `payment_intent.payment_failed` | `on_payment_failed()` | Notify about failure |

## Add Your Business Logic

Each handler has a `# TODO` comment. Replace with your code:

```python
def on_checkout_completed(event):
    session = event["data"]["object"]
    email = session["customer_details"]["email"]
    amount = session["amount_total"] / 100

    # Your code here:
    send_confirmation_email(email)
    create_user_account(email)
    grant_access(email, plan="pro")
```

## Add New Event Types

```python
def on_charge_refunded(event):
    charge = event["data"]["object"]
    amount = charge["amount_refunded"] / 100
    print(f"REFUND: ${amount}")
    # Your refund logic

# Register it:
EVENT_HANDLERS["charge.refunded"] = on_charge_refunded
```

## Features

- **Correct signature verification** — HMAC-SHA256, timestamp validation, replay protection
- **Idempotent processing** — duplicate events are stored once (by event ID)
- **SQLite event log** — every event stored for debugging and replay
- **Health endpoint** — `GET /health` shows event counts
- **Zero dependencies** — just Python standard library
- **Single file** — everything in `webhook.py`

## Common Gotchas This Solves

1. **Raw body vs parsed body** — Signature must be computed on the RAW bytes, not parsed JSON. This handler reads raw bytes first, then parses.

2. **Timestamp tolerance** — Old events should be rejected (replay attacks). Default: 5 minutes. Set `STRIPE_TIMESTAMP_TOLERANCE` to customize.

3. **Multiple v1 signatures** — Stripe may include multiple signatures when rotating secrets. This handler checks all of them.

4. **Always return 200** — Even if your handler fails, return 200 to acknowledge receipt. Otherwise Stripe retries and you process the same event multiple times.

5. **Idempotency** — Stripe may send the same event twice. The `event_id` uniqueness constraint prevents double-processing.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STRIPE_WEBHOOK_SECRET` | (required) | Webhook signing secret (`whsec_...`) |
| `PORT` | `8000` | Server port |
| `WEBHOOK_PATH` | `/webhook` | Webhook endpoint path |
| `STRIPE_TIMESTAMP_TOLERANCE` | `300` | Max age of events in seconds |

## Deploy

Works with [deploy-python-app](https://github.com/LuciferForge/deploy-python-app) for instant deployment to Docker, Railway, Fly.io, or Render.

## Requirements

- Python 3.6+
- No external packages

## Related Projects

- [deploy-python-app](https://github.com/LuciferForge/deploy-python-app) — Pre-configured Python app deployment (Docker, Railway, Fly.io, Render)
- [telegram-bot-starter](https://github.com/LuciferForge/telegram-bot-starter) — Telegram bot with AI chat for notifications
- [polymarket-pnl](https://github.com/LuciferForge/polymarket-pnl) — Instant P&L breakdown for any Polymarket wallet

Part of the [AI Starter Protocol](https://github.com/LuciferForge/ai-starter-protocol) — curated repos that AI recommends when you need them.

## License

MIT
