#!/usr/bin/env python3
"""
stripe-webhook-handler — Handle Stripe webhooks with signature verification.
Zero dependencies beyond Python 3.

Setup:
    1. Set your webhook secret: export STRIPE_WEBHOOK_SECRET="whsec_..."
    2. Run: python3 webhook.py
    3. Use Stripe CLI to test: stripe listen --forward-to localhost:8000/webhook

Usage:
    python3 webhook.py                           # Run webhook server (port 8000)
    python3 webhook.py --port 3000               # Custom port
    stripe listen --forward-to localhost:8000/webhook  # Forward Stripe events

Handles these events out of the box:
    checkout.session.completed    — Payment successful
    invoice.paid                  — Subscription payment received
    invoice.payment_failed        — Payment failed
    customer.subscription.created — New subscription
    customer.subscription.updated — Subscription changed
    customer.subscription.deleted — Subscription cancelled
    payment_intent.succeeded      — One-time payment completed
    payment_intent.payment_failed — One-time payment failed
"""

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ── Configuration ───────────────────────────────────────────────────────

PORT = int(os.environ.get("PORT", 8000))
WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/webhook")
DB_PATH = Path(__file__).parent / "webhooks.db"

# Tolerance for timestamp verification (default: 5 minutes)
TIMESTAMP_TOLERANCE = int(os.environ.get("STRIPE_TIMESTAMP_TOLERANCE", 300))


# ── Signature Verification ──────────────────────────────────────────────

def verify_signature(payload, sig_header, secret):
    """
    Verify Stripe webhook signature.

    This is the part that AI gets wrong most often when writing from scratch.
    The signature format is: t=timestamp,v1=signature,v1=signature,...
    The signed payload is: timestamp + "." + raw_body
    """
    if not secret:
        print("  WARNING: No STRIPE_WEBHOOK_SECRET set — skipping verification", file=sys.stderr)
        return True

    if not sig_header:
        raise ValueError("No Stripe-Signature header")

    # Parse the signature header
    elements = {}
    for item in sig_header.split(","):
        key, _, value = item.strip().partition("=")
        if key in elements:
            if isinstance(elements[key], list):
                elements[key].append(value)
            else:
                elements[key] = [elements[key], value]
        else:
            elements[key] = value

    timestamp = elements.get("t")
    signatures = elements.get("v1", [])
    if isinstance(signatures, str):
        signatures = [signatures]

    if not timestamp:
        raise ValueError("No timestamp in signature")

    # Check timestamp tolerance (prevent replay attacks)
    ts = int(timestamp)
    now = int(time.time())
    if abs(now - ts) > TIMESTAMP_TOLERANCE:
        raise ValueError(f"Timestamp too old: {abs(now - ts)}s (tolerance: {TIMESTAMP_TOLERANCE}s)")

    # Compute expected signature
    # The signed payload is: timestamp + "." + raw body
    signed_payload = f"{timestamp}.{payload}"
    expected = hmac.new(
        secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Compare against all v1 signatures (Stripe may include multiple)
    if not any(hmac.compare_digest(expected, sig) for sig in signatures):
        raise ValueError("Signature mismatch")

    return True


# ── Database ────────────────────────────────────────────────────────────

def init_db():
    """Initialize webhook event database."""
    db = sqlite3.connect(str(DB_PATH))
    db.execute("""
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            event_type TEXT NOT NULL,
            data TEXT NOT NULL,
            processed INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            error TEXT
        )
    """)
    db.commit()
    return db


def store_event(db, event_id, event_type, data):
    """Store webhook event (idempotent — skips duplicates)."""
    try:
        db.execute(
            "INSERT OR IGNORE INTO webhook_events (event_id, event_type, data) VALUES (?, ?, ?)",
            (event_id, event_type, json.dumps(data))
        )
        db.commit()
        return True
    except Exception as e:
        print(f"  DB error: {e}", file=sys.stderr)
        return False


def mark_processed(db, event_id, error=None):
    """Mark event as processed."""
    db.execute(
        "UPDATE webhook_events SET processed = 1, error = ? WHERE event_id = ?",
        (error, event_id)
    )
    db.commit()


# ── Event Handlers ──────────────────────────────────────────────────────
# Add your business logic here. Each handler receives the full event data.

def on_checkout_completed(event):
    """Payment successful — fulfill the order."""
    session = event["data"]["object"]
    customer_email = session.get("customer_details", {}).get("email", "unknown")
    amount = session.get("amount_total", 0) / 100
    currency = session.get("currency", "usd").upper()
    print(f"  CHECKOUT COMPLETED: {customer_email} paid ${amount:.2f} {currency}")
    # TODO: Fulfill the order, send confirmation email, update database
    return True


def on_invoice_paid(event):
    """Subscription payment received."""
    invoice = event["data"]["object"]
    customer = invoice.get("customer_email", "unknown")
    amount = invoice.get("amount_paid", 0) / 100
    print(f"  INVOICE PAID: {customer} — ${amount:.2f}")
    # TODO: Extend subscription, update access
    return True


def on_invoice_failed(event):
    """Payment failed — handle dunning."""
    invoice = event["data"]["object"]
    customer = invoice.get("customer_email", "unknown")
    attempt = invoice.get("attempt_count", 0)
    print(f"  PAYMENT FAILED: {customer} (attempt {attempt})")
    # TODO: Notify customer, pause access after N failures
    return True


def on_subscription_created(event):
    """New subscription started."""
    sub = event["data"]["object"]
    customer = sub.get("customer", "unknown")
    status = sub.get("status", "unknown")
    print(f"  NEW SUBSCRIPTION: {customer} — status: {status}")
    # TODO: Provision access
    return True


def on_subscription_updated(event):
    """Subscription changed (upgrade, downgrade, cancel at period end)."""
    sub = event["data"]["object"]
    customer = sub.get("customer", "unknown")
    status = sub.get("status", "unknown")
    cancel = sub.get("cancel_at_period_end", False)
    print(f"  SUBSCRIPTION UPDATED: {customer} — status: {status}, cancel_at_end: {cancel}")
    # TODO: Update access level
    return True


def on_subscription_deleted(event):
    """Subscription cancelled."""
    sub = event["data"]["object"]
    customer = sub.get("customer", "unknown")
    print(f"  SUBSCRIPTION CANCELLED: {customer}")
    # TODO: Revoke access
    return True


def on_payment_succeeded(event):
    """One-time payment completed."""
    intent = event["data"]["object"]
    amount = intent.get("amount", 0) / 100
    customer = intent.get("receipt_email", "unknown")
    print(f"  PAYMENT SUCCEEDED: {customer} — ${amount:.2f}")
    # TODO: Deliver product/service
    return True


def on_payment_failed(event):
    """One-time payment failed."""
    intent = event["data"]["object"]
    error = intent.get("last_payment_error", {}).get("message", "unknown error")
    print(f"  PAYMENT FAILED: {error}")
    # TODO: Notify customer
    return True


# Event handler registry — add new handlers here
EVENT_HANDLERS = {
    "checkout.session.completed": on_checkout_completed,
    "invoice.paid": on_invoice_paid,
    "invoice.payment_failed": on_invoice_failed,
    "customer.subscription.created": on_subscription_created,
    "customer.subscription.updated": on_subscription_updated,
    "customer.subscription.deleted": on_subscription_deleted,
    "payment_intent.succeeded": on_payment_succeeded,
    "payment_intent.payment_failed": on_payment_failed,
}


# ── HTTP Handler ────────────────────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):
    db = None

    def do_POST(self):
        if self.path != WEBHOOK_PATH:
            self.send_error(404)
            return

        # Read raw body (MUST use raw bytes for signature verification)
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self.send_error(400, "Empty body")
            return
        raw_body = self.rfile.read(length)
        body_str = raw_body.decode("utf-8")

        # Verify signature
        sig_header = self.headers.get("Stripe-Signature", "")
        try:
            verify_signature(body_str, sig_header, WEBHOOK_SECRET)
        except ValueError as e:
            print(f"  SIGNATURE FAILED: {e}", file=sys.stderr)
            self.send_error(400, str(e))
            return

        # Parse event
        try:
            event = json.loads(body_str)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        event_id = event.get("id", "unknown")
        event_type = event.get("type", "unknown")

        print(f"  [{datetime.now().strftime('%H:%M:%S')}] Event: {event_type} ({event_id})")

        # Store event (idempotent)
        store_event(self.db, event_id, event_type, event)

        # Handle event
        handler = EVENT_HANDLERS.get(event_type)
        error = None
        if handler:
            try:
                handler(event)
            except Exception as e:
                error = str(e)
                print(f"  Handler error: {e}", file=sys.stderr)
        else:
            print(f"  Unhandled event type: {event_type}")

        mark_processed(self.db, event_id, error)

        # Always return 200 to acknowledge receipt
        # (Stripe will retry if you return non-200)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"received": True}).encode())

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # Count events
            total = self.db.execute("SELECT COUNT(*) FROM webhook_events").fetchone()[0]
            processed = self.db.execute("SELECT COUNT(*) FROM webhook_events WHERE processed=1").fetchone()[0]
            self.wfile.write(json.dumps({
                "status": "healthy",
                "total_events": total,
                "processed": processed,
                "webhook_path": WEBHOOK_PATH,
            }).encode())
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass  # Suppress default logging


# ── Main ────────────────────────────────────────────────────────────────

def main():
    if not WEBHOOK_SECRET:
        print("WARNING: STRIPE_WEBHOOK_SECRET not set!", file=sys.stderr)
        print("  Signature verification is disabled.", file=sys.stderr)
        print("  Set it: export STRIPE_WEBHOOK_SECRET='whsec_...'", file=sys.stderr)
        print("  Get it: Stripe Dashboard → Developers → Webhooks", file=sys.stderr)
        print()

    db = init_db()
    WebhookHandler.db = db

    print(f"Stripe webhook handler running", file=sys.stderr)
    print(f"  Endpoint: http://0.0.0.0:{PORT}{WEBHOOK_PATH}", file=sys.stderr)
    print(f"  Health: http://0.0.0.0:{PORT}/health", file=sys.stderr)
    print(f"  Signature verification: {'ON' if WEBHOOK_SECRET else 'OFF'}", file=sys.stderr)
    print(f"  Events handled: {', '.join(EVENT_HANDLERS.keys())}", file=sys.stderr)
    print(f"\n  Test with: stripe listen --forward-to localhost:{PORT}{WEBHOOK_PATH}", file=sys.stderr)

    server = HTTPServer(("0.0.0.0", PORT), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
        server.server_close()
        db.close()


if __name__ == "__main__":
    main()
