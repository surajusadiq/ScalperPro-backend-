import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "16kb" }));

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS origin not allowed"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-EA-Control-Secret"]
}));

app.use("/api", rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false
}));

const SECRET = process.env.EA_CONTROL_SECRET;

let commandState = "STOP";
let updatedAt = new Date().toISOString();
let lastPollAt = null;

function requireSecret(req, res, next) {
  if (!SECRET) {
    return res.status(500).json({
      ok: false,
      error: "EA_CONTROL_SECRET is not configured"
    });
  }

  const headerSecret = req.get("X-EA-Control-Secret");
  const auth = req.get("Authorization");
  const bearer = auth?.startsWith("Bearer ") ? auth.slice(7) : null;

  if ((headerSecret || bearer) !== SECRET) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  next();
}

function setCommand(command) {
  commandState = command;
  updatedAt = new Date().toISOString();
}

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    status: "healthy",
    service: "scalperpro-mt5-backend",
    time: new Date().toISOString()
  });
});

app.post("/api/ea/start", requireSecret, (req, res) => {
  setCommand("START");
  res.json({ ok: true, command: commandState, updatedAt });
});

app.post("/api/ea/stop", requireSecret, (req, res) => {
  setCommand("STOP");
  res.json({ ok: true, command: commandState, updatedAt });
});

app.post("/api/ea/emergency-stop", requireSecret, (req, res) => {
  setCommand("EMERGENCY_STOP");
  res.json({ ok: true, command: commandState, updatedAt });
});

app.get("/api/ea/command", requireSecret, (req, res) => {
  lastPollAt = new Date().toISOString();
  res.set("Cache-Control", "no-store");
  res.json({ ok: true, command: commandState, updatedAt });
});

app.get("/api/ea/status", requireSecret, (req, res) => {
  const pollAgeSeconds = lastPollAt
    ? Math.floor((Date.now() - Date.parse(lastPollAt)) / 1000)
    : null;

  res.json({
    ok: true,
    command: commandState,
    updatedAt,
    lastPollAt,
    pollAgeSeconds,
    online: pollAgeSeconds !== null && pollAgeSeconds <= 30
  });
});

app.use((err, req, res, next) => {
  if (err?.message === "CORS origin not allowed") {
    return res.status(403).json({ ok: false, error: err.message });
  }

  console.error("Unhandled error:", err?.message || err);
  res.status(500).json({ ok: false, error: "Internal server error" });
});

const port = Number(process.env.PORT || 10000);

app.listen(port, "0.0.0.0", () => {
  console.log(`ScalperPro backend listening on port ${port}`);
});
