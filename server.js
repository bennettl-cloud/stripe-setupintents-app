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

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

app.post("/create-customer", async (req, res) => {
  try {
    const customer = await stripe.customers.create();
    res.json({ customerId: customer.id });
  } catch (err) {
    res.status(400).json({ error: "Could not create customer." });
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
      automatic_payment_methods: { enabled: false },
      payment_method_types: ["card"],
      usage: "off_session"
    });

    res.json({
      clientSecret: setupIntent.client_secret,
      setupIntentId: setupIntent.id
    });
  } catch (err) {
    res.status(400).json({ error: "Could not create SetupIntent." });
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
      return res.status(400).send("Webhook signature verification failed.");
    }

    switch (event.type) {
      case "setup_intent.succeeded": {
        break;
      }
      case "setup_intent.setup_failed": {
        break;
      }
      case "payment_method.attached": {
        break;
      }
      default:
        break;
    }

    return res.json({ received: true });
  }
);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
