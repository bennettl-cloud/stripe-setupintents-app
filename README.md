# Stripe SetupIntents Example (Node + Express)

This project saves a customer's card for future off-session billing using Stripe SetupIntents.

## What it includes

- `POST /create-customer`: creates a Stripe customer
- `POST /create-setup-intent`: creates a SetupIntent (`usage: off_session`)
- `POST /webhook`: handles Stripe webhook events
- Frontend (`public/index.html`) using Stripe Elements + `confirmCardSetup`

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy `.env.example` to `.env` and fill in your Stripe keys:
   ```bash
   cp .env.example .env
   ```
3. Start the server:
   ```bash
   npm start
   ```
4. Open [http://localhost:4242](http://localhost:4242)

## Fast deploy on Render

This folder includes `render.yaml` so Render can deploy automatically from a Git repo.

## Production safeguards

The backend includes:

- Origin allowlist checks (`ALLOWED_ORIGINS`)
- Request rate limiting on read and write endpoints
- Stripe idempotency key handling for customer/setup-intent creation

Set `ALLOWED_ORIGINS` to your deployed frontend origin(s), comma-separated.

## Webhooks (local)

Use Stripe CLI to forward events:

```bash
stripe listen --forward-to localhost:4242/webhook
```

Copy the webhook signing secret shown by Stripe CLI into `STRIPE_WEBHOOK_SECRET`.

## Next step for off-session billing

After card setup succeeds, keep the customer ID and payment method ID in your database.
Later, create and confirm a PaymentIntent server-side with:

- `customer: <customer_id>`
- `payment_method: <payment_method_id>`
- `off_session: true`
- `confirm: true`
