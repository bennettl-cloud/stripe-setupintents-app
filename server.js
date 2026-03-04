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
const chargeApiKeys = (process.env.CHARGE_API_KEYS || "")
  .split(",")
  .map((key) => key.trim())
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
if (isProduction && chargeApiKeys.length === 0) {
  throw new Error("Missing CHARGE_API_KEYS in production.");
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
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Idempotency-Key,X-Idempotency-Key,Authorization,X-Charge-Key"
  );
  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }
  return next();
}

function requireChargeApiKey(req, res, next) {
  const authHeader = req.get("Authorization") || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const providedKey = (req.get("X-Charge-Key") || bearerToken || "").trim();

  if (!providedKey) {
    return res.status(401).json({ error: "Missing charge API key." });
  }
  if (!chargeApiKeys.includes(providedKey)) {
    return res.status(403).json({ error: "Invalid charge API key." });
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
app.use(["/create-customer", "/create-setup-intent", "/charge-off-session"], writeLimiter);

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

app.post("/charge-off-session", requireChargeApiKey, async (req, res) => {
  try {
    const { customerId, paymentMethodId, amount, currency = "usd", description } = req.body || {};
    if (!customerId || !paymentMethodId || !amount) {
      return res
        .status(400)
        .json({ error: "Missing required fields: customerId, paymentMethodId, amount." });
    }

    const parsedAmount = Number(amount);
    if (!Number.isInteger(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "amount must be a positive integer in cents." });
    }

    const idempotencyKey = getIdempotencyKey(req, "off_session_charge");
    if (!idempotencyKey) {
      return res.status(400).json({ error: "Missing Idempotency-Key header." });
    }

    const customer = await stripe.customers.retrieve(customerId);
    if (!customer || customer.deleted) {
      return res.status(400).json({ error: "Invalid customerId." });
    }

    const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);
    const paymentMethodCustomerId =
      typeof paymentMethod.customer === "string"
        ? paymentMethod.customer
        : paymentMethod.customer && paymentMethod.customer.id;
    if (paymentMethod.type !== "card" || paymentMethodCustomerId !== customerId) {
      return res.status(400).json({ error: "Payment method does not belong to customer." });
    }

    const paymentIntent = await stripe.paymentIntents.create(
      {
        amount: parsedAmount,
        currency: String(currency).toLowerCase(),
        customer: customerId,
        payment_method: paymentMethodId,
        off_session: true,
        confirm: true,
        description: description || undefined
      },
      { idempotencyKey }
    );

    return res.json({
      paymentIntentId: paymentIntent.id,
      status: paymentIntent.status
    });
  } catch (err) {
    return res.status(400).json({ error: "Could not create off-session charge." });
  }
});

app.get("/config", (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
