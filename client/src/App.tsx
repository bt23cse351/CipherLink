import { useEffect, useMemo, useRef, useState } from "react";
import sodium from "libsodium-wrappers-sumo";
import { io, Socket } from "socket.io-client";

type PublicUser = { username: string; boxPublicKey: string; signPublicKey: string };
type Envelope = {
  id: string; from: string; to: string; nonce: string; ciphertext: string; signature: string;
  timestamp: number; senderBoxPublicKey: string; senderSignPublicKey: string;
};
type ChatMessage = { id: string; from: string; to: string; text: string; time: number; status: string; raw?: Envelope };

const serverUrl = (import.meta as any).env.VITE_SERVER_URL || window.location.origin;
const b64 = (bytes: Uint8Array) => sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
const unb64 = (value: string) => sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
const storageKey = (username: string) => `cipherlink-demo-keys:${username}`;

export default function App() {
  const [username, setUsername] = useState("");
  const [loggedIn, setLoggedIn] = useState("");
  const [users, setUsers] = useState<PublicUser[]>([]);
  const [recipient, setRecipient] = useState("");
  const [draft, setDraft] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState("Connecting to relay…");
  const [securityLog, setSecurityLog] = useState<string[]>(["Waiting for a secure session."]);
  const [rawView, setRawView] = useState<Envelope | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const keysRef = useRef<any>(null);
  const usersRef = useRef<PublicUser[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { usersRef.current = users; }, [users]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const appendLog = (line: string) => setSecurityLog(prev => [`${new Date().toLocaleTimeString()} — ${line}`, ...prev].slice(0, 12));

  useEffect(() => {
    let active = true;
    const socket = io(serverUrl, { transports: ["websocket", "polling"] });
    socketRef.current = socket;
    socket.on("connect", () => { if (active) setStatus("Relay connected"); });
    socket.on("disconnect", () => { if (active) setStatus("Relay disconnected"); });
    socket.on("connect_error", () => { if (active) setStatus("Connection error — check server URL"); });
    socket.on("directory_updated", (list: PublicUser[]) => setUsers(list));
    socket.on("registered", (result: {ok: boolean; error?: string; username?: string}) => {
      if (!result.ok) { setStatus(result.error || "Registration failed"); return; }
      setLoggedIn(result.username || "");
      setStatus(`Registered as ${result.username}`);
      appendLog("Public keys registered with relay.");
    });
    socket.on("error_message", (result: {error: string}) => { setStatus(result.error); appendLog(`Relay: ${result.error}`); });
    socket.on("message", async (envelope: Envelope) => {
      try {
        await sodium.ready;
        const sender = usersRef.current.find(u => u.username === envelope.from);
        if (!sender || sender.signPublicKey !== envelope.senderSignPublicKey ||
            sender.boxPublicKey !== envelope.senderBoxPublicKey) {
          throw new Error("Sender public key is not in the current directory.");
        }
        const signedBytes = unb64(envelope.ciphertext);
        const signatureOK = sodium.crypto_sign_verify_detached(
          unb64(envelope.signature), signedBytes, unb64(sender.signPublicKey)
        );
        if (!signatureOK) throw new Error("Signature invalid: message may have been altered.");
        const plaintext = sodium.crypto_box_open_easy(
          signedBytes, unb64(envelope.nonce), unb64(sender.boxPublicKey), keysRef.current.box.privateKey
        );
        const text = sodium.to_string(plaintext);
        setMessages(prev => [...prev, { id: envelope.id, from: envelope.from, to: envelope.to, text, time: envelope.timestamp, status: "Verified ✓", raw: envelope }]);
        appendLog(`Signature verified and message decrypted from ${envelope.from}.`);
        setRawView(envelope);
      } catch (error) {
        const msg = error instanceof Error ? error.message : "Unknown verification error";
        appendLog(`REJECTED message from ${envelope.from}: ${msg}`);
        setMessages(prev => [...prev, { id: envelope.id || crypto.randomUUID(), from: envelope.from, to: envelope.to, text: "[Message rejected: verification/decryption failed]", time: Date.now(), status: "Rejected", raw: envelope }]);
      }
    });
    return () => { active = false; socket.disconnect(); };
  }, []);

  const availableRecipients = useMemo(() => users.filter(u => u.username !== loggedIn), [users, loggedIn]);

  async function register() {
    const clean = username.trim();
    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(clean)) {
      setStatus("Username must be 3–24 letters, numbers, _ or -."); return;
    }
    await sodium.ready;
    let keys: any;
    try {
      const saved = localStorage.getItem(storageKey(clean));
      if (saved) {
        const parsed = JSON.parse(saved);
        keys = {
          box: { publicKey: unb64(parsed.boxPublicKey), privateKey: unb64(parsed.boxPrivateKey) },
          sign: { publicKey: unb64(parsed.signPublicKey), privateKey: unb64(parsed.signPrivateKey) }
        };
      } else {
        const box = sodium.crypto_box_keypair();
        const sign = sodium.crypto_sign_keypair();
        keys = { box, sign };
        localStorage.setItem(storageKey(clean), JSON.stringify({
          boxPublicKey: b64(box.publicKey), boxPrivateKey: b64(box.privateKey),
          signPublicKey: b64(sign.publicKey), signPrivateKey: b64(sign.privateKey)
        }));
      }
    } catch {
      setStatus("Could not load local demo keys. Clear this browser's CipherLink demo key for this username and retry."); return;
    }
    keysRef.current = keys;
    setUsername(clean);
    socketRef.current?.emit("register", {
      username: clean, boxPublicKey: b64(keys.box.publicKey), signPublicKey: b64(keys.sign.publicKey)
    });
    appendLog("Local demo keys loaded/generated. Private keys remain in this browser profile (demo storage only).");
  }

  async function sendMessage() {
    const text = draft.trim();
    if (!loggedIn || !recipient || !text || !keysRef.current) return;
    const target = users.find(u => u.username === recipient);
    if (!target) { setStatus("Recipient is not online."); return; }
    await sodium.ready;
    try {
      const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
      const plaintext = sodium.from_string(text);
      const ciphertext = sodium.crypto_box_easy(
        plaintext, nonce, unb64(target.boxPublicKey), keysRef.current.box.privateKey
      );
      const signature = sodium.crypto_sign_detached(ciphertext, keysRef.current.sign.privateKey);
      const envelope: Envelope = {
        id: crypto.randomUUID(), from: loggedIn, to: recipient,
        nonce: b64(nonce), ciphertext: b64(ciphertext), signature: b64(signature),
        timestamp: Date.now(), senderBoxPublicKey: b64(keysRef.current.box.publicKey),
        senderSignPublicKey: b64(keysRef.current.sign.publicKey)
      };
      socketRef.current?.emit("send_message", envelope);
      setMessages(prev => [...prev, { id: envelope.id, from: loggedIn, to: recipient, text, time: envelope.timestamp, status: "Sent (relay ack pending)", raw: envelope }]);
      setRawView(envelope);
      setDraft("");
      appendLog(`Encrypted locally for ${recipient}; only envelope sent to relay.`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Encryption failed");
    }
  }

  const selectedRaw = rawView;
  return <main className="app-shell">
    <header className="topbar">
      <div className="brand-mark">C<span>L</span></div>
      <div className="brand"><h1>CipherLink</h1><p>END-TO-END ENCRYPTED MESSAGING LAB</p></div>
      <div className={`connection ${status.includes("connected") || status.startsWith("Registered") ? "online" : ""}`}><i />{status}</div>
    </header>

    {!loggedIn ? <section className="login-card">
      <div className="eyebrow">PRIVATE BY DESIGN · EDUCATIONAL DEMO</div>
      <h2>Secure conversations<br/><em>start at the endpoint.</em></h2>
      <p className="muted">Choose a demo username. Your browser creates encryption and signing keys locally.</p>
      <label htmlFor="username">Username</label>
      <div className="login-row"><input id="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="e.g. sender01" onKeyDown={e => e.key === "Enter" && register()} /><button onClick={register}>Create / Join <span>→</span></button></div>
      <div className="warning">Demo only: usernames are not authenticated accounts. Never enter real secrets.</div>
    </section> : <div className="dashboard">
      <aside className="sidebar">
        <div className="section-label">IDENTITY</div>
        <div className="identity"><div className="avatar">{loggedIn.slice(0,1).toUpperCase()}</div><div><strong>{loggedIn}</strong><small>Local keys active</small></div><span className="verified-dot">●</span></div>
        <div className="section-label contacts-label">ONLINE RECIPIENTS <span>{availableRecipients.length}</span></div>
        {availableRecipients.length === 0 ? <p className="empty">Open another browser profile and join with a different username.</p> : availableRecipients.map(u => <button key={u.username} className={`contact ${recipient === u.username ? "active" : ""}`} onClick={() => setRecipient(u.username)}><div className="avatar small">{u.username.slice(0,1).toUpperCase()}</div><div><strong>{u.username}</strong><small>Public keys available</small></div><span className="presence" /></button>)}
        <div className="sidebar-note"><span>⌑</span><p>Messages are encrypted in your browser before they reach the relay.</p></div>
      </aside>

      <section className="chat-panel">
        <div className="chat-heading"><div><div className="section-label">SECURE CHANNEL</div><h2>{recipient || "Select a recipient"}</h2></div><div className="e2e-pill"><span>⌑</span> E2E DEMO</div></div>
        <div className="notice"><span>✓</span><p><strong>Client-side encryption enabled.</strong> Verify key fingerprints out-of-band before trusting identities.</p></div>
        <div className="messages">
          {messages.filter(m => (m.from === loggedIn && m.to === recipient) || (m.from === recipient && m.to === loggedIn)).map(m => <div key={m.id} className={`message-row ${m.from === loggedIn ? "mine" : ""}`}><div className="bubble"><div className="bubble-meta">{m.from} · {new Date(m.time).toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})}</div><p>{m.text}</p><div className="bubble-status">{m.status}</div><button className="tiny-link" onClick={() => m.raw && setRawView(m.raw)}>View encrypted envelope</button></div></div>)}
          {(!recipient || messages.filter(m => (m.from === loggedIn && m.to === recipient) || (m.from === recipient && m.to === loggedIn)).length === 0) && <div className="empty-state"><div className="lock-art">⌑</div><h3>Your conversation is private in transit</h3><p>Select an online recipient and send a test message to inspect the encryption flow.</p></div>}
          <div ref={bottomRef} />
        </div>
        <div className="composer"><textarea value={draft} onChange={e => setDraft(e.target.value)} placeholder={recipient ? "Write an encrypted message…" : "Select a recipient first"} disabled={!recipient} onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void sendMessage(); } }} /><button disabled={!recipient || !draft.trim()} onClick={() => void sendMessage()}>Encrypt & Send <span>↗</span></button></div>
        <div className="composer-foot"><span>↳ Plaintext stays in the sending browser until encryption</span><span>AES-256-GCM is not used here; libsodium crypto_box is used.</span></div>
      </section>

      <aside className="inspector">
        <div className="inspector-head"><div><div className="section-label">SECURITY CENTER</div><h3>Live inspection</h3></div><span className="live-tag">LIVE</span></div>
        <div className="cia-card"><div className="cia-icon">◈</div><div><strong>Confidentiality</strong><p>Encrypted payload</p></div><span className="state">ACTIVE</span></div>
        <div className="cia-card"><div className="cia-icon green">✓</div><div><strong>Integrity</strong><p>Ed25519 signature check</p></div><span className="state">CHECKED</span></div>
        <div className="cia-card"><div className="cia-icon purple">⌁</div><div><strong>Availability</strong><p>Relay health endpoint</p></div><span className="state neutral">BEST EFFORT</span></div>
        <div className="inspector-section"><div className="section-label">ENCRYPTED ENVELOPE</div>{selectedRaw ? <><div className="hash-box"><span>NONCE</span><code>{selectedRaw.nonce.slice(0, 34)}…</code></div><div className="hash-box"><span>CIPHERTEXT</span><code>{selectedRaw.ciphertext.slice(0, 82)}{selectedRaw.ciphertext.length > 82 ? "…" : ""}</code></div><div className="hash-box"><span>SIGNATURE</span><code>{selectedRaw.signature.slice(0, 50)}…</code></div><button className="outline-button" onClick={() => navigator.clipboard?.writeText(JSON.stringify(selectedRaw, null, 2))}>Copy envelope JSON</button></> : <p className="muted small-text">Send or receive a message to inspect its encrypted envelope.</p>}</div>
        <div className="inspector-section"><div className="section-label">SECURITY EVENT LOG</div><div className="event-log">{securityLog.map((line, i) => <div className="event" key={`${line}-${i}`}><span className="event-dot" /><p>{line}</p></div>)}</div></div>
        <div className="fingerprint"><div className="section-label">DEMO KEY NOTICE</div><p>Directory keys are not independently authenticated. Compare fingerprints over a separate trusted channel.</p></div>
      </aside>
    </div>}
    <footer><span>© CipherLink Security Lab</span><span>Educational prototype · Not independently audited</span><span><i className="footer-dot" /> Relay: {serverUrl}</span></footer>
  </main>;
}
