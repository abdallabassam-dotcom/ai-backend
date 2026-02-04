import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import { createClient } from "@supabase/supabase-js";
import pkg from "pg";
import crypto from "crypto";

dotenv.config();

const { Pool } = pkg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const app = express();

// IMPORTANT for cookies across Vercel <-> Railway
app.set("trust proxy", 1);

app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "x-device-fingerprint",
    "x-admin-key"
  ],
  methods: ["GET", "POST", "OPTIONS"]
}));
app.options("*", cors());

app.use(express.json());
app.use(cookieParser());

// Supabase Admin client (server-only)
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// -------- helpers --------

async function getUserFromBearer(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return null;

  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user; // { id, email, ... }
}

function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
}

function getIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.toString().split(",")[0].trim();
  return req.socket.remoteAddress || "";
}

function ensureDeviceCookie(req, res) {
  let deviceId = req.cookies.device_id;
  if (!deviceId) {
    deviceId = crypto.randomBytes(16).toString("hex");
    res.cookie("device_id", deviceId, {
      httpOnly: true,
      sameSite: "none",
      secure: true
    });
  }
  return deviceId;
}

// -------- routes --------

app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

// 1) Admin generates trial code (single-use)
app.post("/admin/generate-trial-code", requireAdmin, async (req, res) => {
  try {
    const days = Number(req.body?.days ?? 7);
    const expiresInDays = Number(req.body?.expires_in_days ?? 30);

    const code = "TRIAL-" + crypto.randomBytes(4).toString("hex").toUpperCase();

    await pool.query(
      `insert into trial_codes (code, used, duration_days, expires_at)
       values ($1, false, $2, now() + ($3 || ' days')::interval)`,
      [code, days, expiresInDays]
    );

    res.json({ code, days });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed to generate code" });
  }
});

// 2) User redeems trial code => activates 7 days + limits
app.post("/redeem-trial-code", async (req, res) => {
  try {
    const user = await getUserFromBearer(req);
    if (!user) return res.status(401).json({ error: "Not logged in" });

    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: "code is required" });

    // atomic consume
    const used = await pool.query(
      `update trial_codes
       set used=true, used_by=$1, used_at=now()
       where code=$2
         and used=false
         and (expires_at is null or expires_at > now())
       returning duration_days`,
      [user.id, code]
    );

    if (used.rows.length === 0) {
      return res.status(400).json({ error: "Invalid/used/expired code" });
    }

    const durationDays = used.rows[0].duration_days ?? 7;

    // upsert user
    await pool.query(
      `insert into users (id, email)
       values ($1, $2)
       on conflict (id) do update set email=excluded.email`,
      [user.id, user.email]
    );

    // activate trial (device_limit=1, ip_limit=1)
    await pool.query(
      `insert into subscriptions (user_id, plan, active, start_at, end_at, ip_limit, device_limit, is_trial)
       values ($1, 'trial', true, now(), now() + ($2 || ' days')::interval, 1, 1, true)
       on conflict (user_id) do update
         set plan='trial',
             active=true,
             start_at=now(),
             end_at=now() + ($2 || ' days')::interval,
             ip_limit=1,
             device_limit=1,
             is_trial=true`,
      [user.id, durationDays]
    );

    res.json({ success: true, trial_days: durationDays });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "redeem failed" });
  }
});

// 3) Middleware: check subscription + device+ip limits
async function requireActiveSubAndLimits(req, res, next) {
  const user = await getUserFromBearer(req);
  if (!user) return res.status(401).json({ error: "Not logged in" });

  const fingerprint = req.headers["x-device-fingerprint"]?.toString() || "";
  if (!fingerprint) return res.status(400).json({ error: "Missing fingerprint" });

  const deviceId = ensureDeviceCookie(req, res);
  const ip = getIp(req);

  const sub = await pool.query(
    `select active, end_at, device_limit, ip_limit
     from subscriptions
     where user_id=$1`,
    [user.id]
  );

  if (sub.rows.length === 0 || !sub.rows[0].active) {
    return res.status(403).json({ error: "No active subscription" });
  }

  const endAt = sub.rows[0].end_at;
  if (!endAt || new Date(endAt).getTime() < Date.now()) {
    return res.status(403).json({ error: "Trial/plan expired" });
  }

  const deviceLimit = Number(sub.rows[0].device_limit ?? 0);
  const ipLimit = Number(sub.rows[0].ip_limit ?? 0);

  // device check
  const existingDevice = await pool.query(
    `select id from user_devices where user_id=$1 and device_id=$2`,
    [user.id, deviceId]
  );

  if (existingDevice.rows.length === 0) {
    const count = await pool.query(
      `select count(*)::int as c from user_devices where user_id=$1`,
      [user.id]
    );
    if (count.rows[0].c >= deviceLimit) {
      return res.status(403).json({ error: "Device limit reached" });
    }

    await pool.query(
      `insert into user_devices (user_id, device_id, fingerprint, ip, last_seen)
       values ($1,$2,$3,$4,now())`,
      [user.id, deviceId, fingerprint, ip]
    );
  } else {
    await pool.query(
      `update user_devices
       set last_seen=now(), fingerprint=$3, ip=$4
       where user_id=$1 and device_id=$2`,
      [user.id, deviceId, fingerprint, ip]
    );
  }

  // ip limit check (unique ips in last 24h)
  if (ipLimit > 0) {
    const ips = await pool.query(
      `select count(distinct ip)::int as c
       from user_devices
       where user_id=$1
         and last_seen > now() - interval '24 hours'`,
      [user.id]
    );
    if (ips.rows[0].c > ipLimit) {
      return res.status(403).json({ error: "IP limit reached" });
    }
  }

  req.user = user;
  next();
}

// 4) Chat (currently just confirms access; AI later)
app.post("/chat", requireActiveSubAndLimits, async (req, res) => {
  res.json({ reply: "✅ الشات مفتوح (Trial/Active). جاهزين نضيف الذكاء الاصطناعي بعدين." });
});

// 5) (Optional) upgrade to paid manually (for later)
app.post("/admin/mark-paid", requireAdmin, async (req, res) => {
  const { user_id, days } = req.body || {};
  if (!user_id) return res.status(400).json({ error: "user_id required" });

  const dur = Number(days ?? 30);

  await pool.query(
    `insert into subscriptions (user_id, plan, active, start_at, end_at, ip_limit, device_limit, is_trial)
     values ($1, 'paid', true, now(), now() + ($2 || ' days')::interval, 2, 2, false)
     on conflict (user_id) do update
       set plan='paid',
           active=true,
           start_at=now(),
           end_at=now() + ($2 || ' days')::interval,
           ip_limit=2,
           device_limit=2,
           is_trial=false`,
    [user_id, dur]
  );

  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
