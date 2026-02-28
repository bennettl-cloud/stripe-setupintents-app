require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const path = require("path");
const rateLimit = require("express-rate-limit");
const Stripe = require("stripe");

const app = express();
const port = process.env.PORT || 4242;
const isProduction = process.env.NODE_ENV === "production";
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("Missing STRIPE_SECRET_KEY in environment.");
}
if (!process.env.STRIPE_PUBLISHABLE_KEY) {
  throw new Error("Missing STRIPE_PUBLISHABLE_KEY in environment.");
}
if (isProduction && allowedOrigins.length === 0) {
  throw new Error("Missing ALLOWED_ORIGINS in production.");
}

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

const readLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Try again later." }
});

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Try again later." }
});

function requireAllowedOrigin(req, res, next) {
  const origin = req.headers.origin;
  if (!origin) {
    return next();
  }
  if (allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Idempotency-Key,X-Idempotency-Key");
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  return next();
}

function getIdempotencyKey(req, prefix) {
  const providedKey = req.get("Idempotency-Key") || req.get("X-Idempotency-Key");
  if (providedKey && /^[a-zA-Z0-9:._-]{8,255}$/.test(providedKey)) {
    return `${prefix}:${providedKey}`;
  }
  if (isProduction) {
    return null;
  }
  const fallback = crypto
    .createHash("sha256")
    .update(`${prefix}:${JSON.stringify(req.body || {})}`)
    .digest("hex");
  return `${prefix}:${fallback}`;
}

app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
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
    case "setup_intent.succeeded":
    case "setup_intent.setup_failed":
    case "payment_method.attached":
    default:
      break;
  }

  return res.json({ received: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.use(readLimiter);
app.use(express.json({ limit: "50kb" }));
app.use(requireAllowedOrigin);
app.use(["/create-customer", "/create-setup-intent"], writeLimiter);

app.post("/create-customer", async (req, res) => {
  try {
    const idempotencyKey = getIdempotencyKey(req, "customer");
    if (!idempotencyKey) {
      return res.status(400).json({ error: "Missing Idempotency-Key header." });
    }
    const customer = await stripe.customers.create({}, { idempotencyKey });
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
    const idempotencyKey = getIdempotencyKey(req, "setup_intent");
    if (!idempotencyKey) {
      return res.status(400).json({ error: "Missing Idempotency-Key header." });
    }

    const setupIntent = await stripe.setupIntents.create({
      customer: customerId,
      automatic_payment_methods: { enabled: false },
      payment_method_types: ["card"],
      usage: "off_session"
    }, { idempotencyKey });

    res.json({
      clientSecret: setupIntent.client_secret,
      setupIntentId: setupIntent.id
    });
  } catch (err) {
    res.status(400).json({ error: "Could not create SetupIntent." });
  }
});

app.get("/config", (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
