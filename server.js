require("dotenv").config();

const express = require("express");
const path = require("path");
const Stripe = require("stripe");

const app = express();
const port = process.env.PORT || 4242;

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("Missing STRIPE_SECRET_KEY in environment.");
}

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

app.post("/create-customer", async (req, res) => {
  try {
    const { email, name } = req.body || {};
    const customer = await stripe.customers.create({
      email,
      name
    });
    res.json({ customerId: customer.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/create-setup-intent", async (req, res) => {
  try {
    const { customerId } = req.body || {};
    if (!customerId) {
      return res.status(400).json({ error: "Missing customerId." });
    }

    const setupIntent = await stripe.setupIntents.create({
      customer: customerId,
      payment_method_types: ["card"],
      usage: "off_session"
    });

    res.json({
      clientSecret: setupIntent.client_secret,
      setupIntentId: setupIntent.id
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/config", (req, res) => {
  if (!process.env.STRIPE_PUBLISHABLE_KEY) {
    return res.status(500).json({ error: "Missing STRIPE_PUBLISHABLE_KEY in environment." });
  }
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;

    try {
      if (webhookSecret) {
        event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
      } else {
        event = JSON.parse(req.body.toString("utf8"));
      }
    } catch (err) {
      console.error("Webhook signature verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    switch (event.type) {
      case "setup_intent.succeeded": {
        const setupIntent = event.data.object;
        console.log("SetupIntent succeeded:", setupIntent.id);
        break;
      }
      case "setup_intent.setup_failed": {
        const setupIntent = event.data.object;
        console.log("SetupIntent failed:", setupIntent.id);
        break;
      }
      case "payment_method.attached": {
        const paymentMethod = event.data.object;
        console.log("PaymentMethod attached:", paymentMethod.id);
        break;
      }
      default:
        console.log("Unhandled event type:", event.type);
    }

    return res.json({ received: true });
  }
);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
