# CipherLink — End-to-End Encrypted Messaging Demo

CipherLink is an educational, full-stack messaging project for demonstrating the **CIA triad** with client-side cryptography. It supports two browser sessions, live message delivery, a ciphertext relay server, message authentication, and a small security-test suite.

> **Security status:** This is a student/demo foundation, not an audited messenger and not suitable for sensitive or production communications. It does **not** implement the Signal Protocol, Double Ratchet, forward secrecy, multi-device key management, or a hardened identity-verification workflow. Do not describe it as “military-grade” or “100% secure.”

## Features

- React + TypeScript frontend and Node.js/Express + Socket.IO relay.
- Browser-side encryption/decryption using `libsodium-wrappers`.
- `crypto_box_easy` (X25519-based authenticated public-key encryption) with a fresh random nonce per message.
- Ed25519 signatures over message metadata and ciphertext; receiver verifies the signature against the sender's registered public signing key.
- Relay stores and forwards ciphertext, nonce, public-key metadata, and signature—not plaintext.
- Message tampering and invalid-signature checks.
- Demo usernames and public-key directory.
- Health endpoint, basic HTTP security headers, and simple in-memory per-IP rate limiting.
- Unit tests for cryptographic round-trip, tampering, and signature verification.

## Architecture

```text
Sender browser
  ├─ compose plaintext
  ├─ encrypt with recipient public encryption key + sender secret encryption key
  ├─ sign envelope with sender secret signing key
  └─ send envelope over TLS/WSS
          |
          v
CipherLink relay (server)
  ├─ checks envelope shape and size
  ├─ rate-limits socket events
  ├─ stores/forwards encrypted envelope only
  └─ cannot decrypt without recipient secret key
          |
          v
Receiver browser
  ├─ verifies sender signature using sender public signing key
  ├─ decrypts using recipient secret encryption key + sender public encryption key
  └─ displays plaintext only after verification and successful decryption
```

## Requirements

- Node.js 20 or newer (Node 22 LTS recommended)
- npm
- A modern browser

## Run locally

From the repository root:

```bash
npm install
npm --prefix server install
npm --prefix client install
npm run dev
```

Open `http://localhost:5173` in two separate browser profiles or windows. Register two different usernames, then send a message from one to the other.

For a production build:

```bash
npm run build
npm start
```

The server serves `client/dist` when it exists. Visit `http://localhost:3000`.

## Test

```bash
npm test
```

Tests cover encryption/decryption, ciphertext tampering, and signature rejection. These are focused demo tests, not a security audit or full penetration test.

## CIA triad demonstration

### Confidentiality
Send a message, then inspect the server-side message envelope / relay logs. The relay receives ciphertext and metadata, not the original plaintext. The server still sees usernames, timing, message sizes, and public keys.

### Integrity
The sender signs the envelope and the receiver verifies it. Altering the ciphertext or signature should cause verification/decryption to fail. A valid signature only proves possession of the corresponding signing key; it does not prove a real-world identity unless users verify key fingerprints out-of-band.

### Availability
`GET /health` reports whether the server is responding. Rate limiting and size limits reduce some abuse. They do not prevent DDoS, outages, malicious hosting providers, or data loss. This starter uses in-memory state, so restart clears users and messages.

## Cloud deployment (Render example)

1. Push this repository to GitHub.
2. In Render, create a **Web Service** connected to the repository.
3. Set **Build Command** to:
   ```bash
   npm install && npm --prefix server install && npm --prefix client install && npm run build
   ```
4. Set **Start Command** to:
   ```bash
   npm start
   ```
5. Use Node 20+ and deploy. Render supplies `PORT`; the server binds to `0.0.0.0`.
6. Open the HTTPS URL. Socket.IO automatically uses secure WebSockets on HTTPS.
7. Test from two separate browsers/devices.

For other providers, deploy the Node server and static frontend together, or host the frontend separately and set `VITE_SERVER_URL` to the server URL. Configure CORS explicitly if you split the services.

## API / socket events

HTTP:
- `GET /health` — health status.
- `GET /api/users` — public user directory.
- `GET /api/messages/:username` — encrypted message history addressed to that username.
- `GET /api/keys/:username` — registered public keys.

Socket.IO:
- `register` — username and public keys.
- `send_message` — encrypted envelope.
- `message` — incoming encrypted envelope.
- `registered` — registration result.
- `error_message` — readable validation/error response.

## Important security limitations

- **Not audited.** Have an independent security professional review it before any real-world use.
- **No forward secrecy.** If a recipient's long-term secret key is compromised, recorded messages may be exposed.
- **No key transparency / trusted identity verification.** The server controls the public-key directory; a malicious server could substitute keys. Compare key fingerprints through a separate trusted channel.
- **Demo key persistence.** Private keys are kept in browser `localStorage` for convenience. This is vulnerable to XSS and device/profile compromise. Do not reuse real secrets.
- **No robust account authentication.** Usernames are not passwords; anyone can claim a username. This is a classroom demo only.
- **In-memory storage.** Data disappears on restart; no durable database, backups, or multi-instance coordination.
- **Metadata remains visible.** The relay sees sender/recipient names, public keys, timestamps, IP addresses, and traffic sizes.
- **No anti-spam identity, group messaging, attachment encryption, or message deletion guarantees.**
- **No post-quantum protection.** X25519 is not post-quantum.
- **Browser supply-chain risk.** The website delivering JavaScript could be modified by a compromised host. E2EE cannot protect against a compromised endpoint.

## Suggested next steps for a production-grade system

Use a reviewed implementation of the Signal Protocol (including Double Ratchet and authenticated prekeys), authenticated user accounts, key transparency or out-of-band fingerprint verification, secure key storage, persistent database with retention controls, abuse prevention, monitoring, backups, dependency scanning, threat modeling, and an external security audit. Do not design a new protocol.

## License

MIT for educational use. Third-party dependencies retain their own licenses.
