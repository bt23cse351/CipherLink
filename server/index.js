import express from "express";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cors from "cors";
import helmet from "helmet";
import { Server } from "socket.io";

const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 3000);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.disable("x-powered-by");
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || !CLIENT_ORIGIN || origin === CLIENT_ORIGIN) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  }
}));

// Small in-memory rate limiter. For production use a shared store and proper abuse controls.
const buckets = new Map();
function rateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const bucket = buckets.get(key) || { start: now, count: 0 };
  if (now - bucket.start > 60_000) { bucket.start = now; bucket.count = 0; }
  bucket.count += 1;
  buckets.set(key, bucket);
  if (bucket.count > 180) return res.status(429).json({ error: "Rate limit exceeded" });
  next();
}
app.use(rateLimit);

const users = new Map();      // username -> public keys + socket id
const messages = new Map();   // recipient -> encrypted envelopes
const io = new Server(server, {
  cors: { origin: CLIENT_ORIGIN || true },
  maxHttpBufferSize: 64 * 1024
});

const usernamePattern = /^[a-zA-Z0-9_-]{3,24}$/;
function validPublicKey(value) {
  return typeof value === "string" && value.length >= 32 && value.length <= 256;
}
function validEnvelope(m) {
  return m && typeof m === "object" &&
    usernamePattern.test(m.from || "") &&
    usernamePattern.test(m.to || "") &&
    typeof m.nonce === "string" && m.nonce.length <= 128 &&
    typeof m.ciphertext === "string" && m.ciphertext.length <= 16_000 &&
    typeof m.signature === "string" && m.signature.length <= 256 &&
    Number.isFinite(m.timestamp) &&
    typeof m.senderBoxPublicKey === "string" &&
    typeof m.senderSignPublicKey === "string";
}

io.on("connection", (socket) => {
  let currentUser = null;
  let socketCount = 0;
  let windowStart = Date.now();

  socket.on("register", (payload = {}) => {
    const username = String(payload.username || "");
    const boxPublicKey = payload.boxPublicKey;
    const signPublicKey = payload.signPublicKey;
    if (!usernamePattern.test(username) || !validPublicKey(boxPublicKey) || !validPublicKey(signPublicKey)) {
      socket.emit("registered", { ok: false, error: "Use a 3–24 character username and valid public keys." });
      return;
    }
    // Demo policy: one active socket per username. This is not account authentication.
    currentUser = username;
    users.set(username, { username, boxPublicKey, signPublicKey, socketId: socket.id });
    socket.emit("registered", { ok: true, username });
    io.emit("directory_updated", Array.from(users.values(), u => ({
      username: u.username, boxPublicKey: u.boxPublicKey, signPublicKey: u.signPublicKey
    })));
  });

  socket.on("send_message", (envelope) => {
    const now = Date.now();
    if (now - windowStart > 10_000) { windowStart = now; socketCount = 0; }
    socketCount += 1;
    if (socketCount > 40) {
      socket.emit("error_message", { error: "Too many messages; slow down." });
      return;
    }
    if (!currentUser || !validEnvelope(envelope) || envelope.from !== currentUser) {
      socket.emit("error_message", { error: "Not registered or invalid message envelope." });
      return;
    }
    const sender = users.get(currentUser);
    const recipient = users.get(envelope.to);
    if (!recipient) {
      socket.emit("error_message", { error: "Recipient is not online / registered." });
      return;
    }
    // Bind public signing key in envelope to the currently registered key.
    if (envelope.senderSignPublicKey !== sender.signPublicKey ||
        envelope.senderBoxPublicKey !== sender.boxPublicKey) {
      socket.emit("error_message", { error: "Sender key mismatch." });
      return;
    }
    const safeEnvelope = {
      id: String(envelope.id || ""),
      from: envelope.from,
      to: envelope.to,
      nonce: envelope.nonce,
      ciphertext: envelope.ciphertext,
      signature: envelope.signature,
      timestamp: envelope.timestamp,
      senderBoxPublicKey: envelope.senderBoxPublicKey,
      senderSignPublicKey: envelope.senderSignPublicKey
    };
    const list = messages.get(envelope.to) || [];
    list.push(safeEnvelope);
    messages.set(envelope.to, list.slice(-200));
    io.to(recipient.socketId).emit("message", safeEnvelope);
    socket.emit("sent", { id: safeEnvelope.id });
  });

  socket.on("disconnect", () => {
    if (currentUser && users.get(currentUser)?.socketId === socket.id) {
      users.delete(currentUser);
      io.emit("directory_updated", Array.from(users.values(), u => ({
        username: u.username, boxPublicKey: u.boxPublicKey, signPublicKey: u.signPublicKey
      })));
    }
  });
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "CipherLink relay", timestamp: new Date().toISOString() }));
app.get("/api/users", (_req, res) => res.json(Array.from(users.values(), u => ({
  username: u.username, boxPublicKey: u.boxPublicKey, signPublicKey: u.signPublicKey
}))));
app.get("/api/keys/:username", (req, res) => {
  const u = users.get(req.params.username);
  if (!u) return res.status(404).json({ error: "User not found / offline" });
  res.json({ username: u.username, boxPublicKey: u.boxPublicKey, signPublicKey: u.signPublicKey });
});
app.get("/api/messages/:username", (req, res) => {
  const username = req.params.username;
  if (!usernamePattern.test(username)) return res.status(400).json({ error: "Invalid username" });
  // This endpoint returns ciphertext only. Demo limitation: no authenticated authorization.
  res.json(messages.get(username) || []);
});

const dist = path.resolve(__dirname, "../client/dist");
app.use(express.static(dist));
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/") || req.path === "/health") return next();
  res.sendFile(path.join(dist, "index.html"), err => { if (err) next(); });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`CipherLink relay listening on port ${PORT}`);
});
