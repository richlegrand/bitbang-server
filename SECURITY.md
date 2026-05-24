# BitBang Security Considerations

## Overview

BitBang achieves **trustless signaling** — the protocol is secure even if the signaling server is adversarial.

This document covers two areas:
1. **Peer-to-Peer Security** — How browser/CLI connects to device securely
2. **Network Security** — How device networks protect against rogue servers

---

# Part 1: Peer-to-Peer Security

## Trust Chain

A BitBang connection involves three parties: the device (listener), the browser/CLI (connector), and the signaling server.

```
Browser ←── TLS+CA ──→ bitba.ng ←── TLS+CA ──→ Device
                           │
                    Verifies hash(pubkey) == UID
                    Routes by UID
                           │
Browser ←─────────── DTLS (P2P) ───────────→ Device
```

1. **Browser → Signaling:** TLS with CA-verified certificate
2. **Device → Signaling:** TLS with CA-verified certificate
3. **UID binding:** Server verifies `hash(pubkey) == UID` on device register, so a device can only claim a UID derived from its own pubkey
4. **SDP exchange:** Travels over #1 and #2
5. **Data channel:** DTLS, verified end-to-end by browser/device via bidirectional verify

The server enforces the UID-to-pubkey binding for routing integrity. It does **not** challenge the device to prove possession of the private key — that proof happens end-to-end via bidirectional verify on the WebRTC data channel.

## Threat Models

| Threat | Description |
|--------|-------------|
| **Impersonation** | Attacker claims someone else's UID |
| **Wire MITM** | Attacker intercepts signaling traffic |
| **Rogue signaling server** | Signaling server operator attacks users |

## The Rogue Relay Attack

WebRTC's security model explicitly assumes trusted signaling. From RFC 8827:

> "Even if HTTPS is used, the signaling server can potentially mount a man-in-the-middle attack unless implementations have some mechanism for independently verifying keys."

A rogue signaling server can insert itself into the data path by rewriting DTLS fingerprints and ICE candidates in the SDP:

```
Browser ←── DTLS(R) ──→ Rogue ←── DTLS(R) ──→ Device
                          │
                    Terminates both
                    DTLS sessions.
                    Sees all traffic.
```

The rogue becomes an actual relay. Both peers establish valid DTLS connections — but to the rogue, not to each other.

## BitBang's Solution: Bidirectional Verification

Every BitBang connection includes bidirectional verification. This is not optional — it's the protocol baseline.

The UID is derived from the device's public key: `UID = hash(pubkey)`. This creates a verifiable binding that the signaling server cannot forge.

### Connection Flow

```
Browser                    Rogue                     Device
───────                    ─────                     ──────
Open WS, send "request" ──►
                           ─────────────────────────► (device builds offer)
                           ◄───────────────────────── Sends offer (SDP)
Server attaches the device's registered pubkey A to
the relayed offer — no extra round trip.
◄────────────────────────── Offer + pubkey A

Verify: hash(A) == UID ✓

Generate random nonce N
createAnswer() — now knows
own DTLS fingerprint B

Encrypt with pubkey A:
  { my_dtls_fingerprint B, nonce N } ───────►  (rides on the answer)
                           Can't decrypt, forwards blob
                           ────────────────────────► Decrypt with privkey A
                                                     Got: { fingerprint B, nonce N }

                                                     Check: peer fingerprint
                                                     I see (in SDP) == B?
                                                     Peer I see = R (Rogue)
                                                     R ≠ B
                                                     MISMATCH → close DTLS,
                                                                 send nothing

                                                     (If fingerprint matches:)
                                                     Send hash(N) over DTLS
                                                     as verify_nonce_hash
                                                     (first stream-0 frame)
                           ◄────────────────────────
◄──────────────────────────
Verify: hash(N) matches
        what I sent?
If yes → device proved it
         decrypted the payload
If no → reject
```

### Why It Works

- **Rogue can't substitute pubkey** — browser verifies `hash(pubkey) == UID`
- **Rogue can't decrypt payload** — doesn't have device's private key
- **Rogue can't modify encrypted fingerprint** — would break decryption
- **Device verifies browser** — fingerprint in encrypted payload must match actual peer
- **Browser verifies device** — nonce response proves device decrypted the payload

### Result

Browser proves the DTLS path to device (fingerprint). Device proves identity to browser (nonce response). Both happen automatically, every connection.

### Why SDP Is Left Unprotected

SDP (Session Description Protocol) carries connection metadata through the signaling server — ICE candidates, DTLS fingerprints, media capabilities. A natural question: shouldn't we sign or encrypt the SDP to prevent tampering?

We explicitly don't. SDP is treated as untrusted input.

**What a rogue server can do to SDP:**
- Substitute fingerprints
- Modify ICE candidates
- Replace the entire SDP

**What happens if it does:**

```
Rogue substitutes fingerprints in SDP:
  Browser SDP: fingerprint B → fingerprint R
  Device SDP:  fingerprint D → fingerprint R

Result:
  Browser ←DTLS(R)→ Rogue ←DTLS(R)→ Device

But:
  Encrypted payload contains fingerprint B (untampered)
  Device decrypts, sees B
  Device's actual peer has fingerprint R
  B ≠ R → reject
```

**The model:**

| Data | Trust level | Purpose |
|------|-------------|---------|
| SDP | Untrusted | Routing hints (how to connect) |
| Encrypted payload | Trusted | Identity binding (verify who you connected to) |

SDP tells you how to reach someone. The encrypted payload verifies you reached the right someone. If SDP is tampered with, connections either fail (wrong ICE candidates) or get rejected (fingerprint mismatch).

**Why this is cleaner:**

Signing SDP would add complexity:
- Device signs SDP with private key
- Browser verifies signature before using SDP
- Need to handle signature format, key distribution, replay protection

Instead, we assume SDP is adversarial and verify after the fact. This is simpler and equally secure — the verification happens regardless of whether SDP was tampered with.

A security reviewer would likely approve: the protocol assumes signaling is hostile and verifies end-to-end.

### Removing the Server-Side Challenge

Earlier versions of BitBang had the signaling server issue a random nonce to every connecting device and require the device to sign it with its private key before accepting the registration. With bidirectional verify in place this challenge is redundant — a browser will already reject any session where the device can't decrypt the encrypted payload, so an imposter that doesn't hold the private key cannot complete a real session no matter what the signaling server believed at registration time.

Removing the server challenge has one small consequence worth naming: an attacker can claim *someone else's* UID at the signaling server by presenting that party's (public) public key in the register message. The server still enforces `UID == hash(pubkey)`, so the attacker has to use the real pubkey — they can't make up a UID/pubkey pair. The attacker now appears registered under the victim's UID, but every browser that tries to connect to that UID will fail closed at bidirectional verify because the attacker can't decrypt the browser's payload. The trade-off is acceptable: simpler protocol, no exploitable failure mode, only a minor UID-squatting nuisance that an honest device can resolve by reconnecting (the registry preempts older connections).

### Encryption Scheme

The encrypted payload uses **RSA-OAEP with SHA-256** to wrap the JSON `{fingerprint, nonce, code}` (where `code` is the 11-char base64url access code from the URL fragment; see "URL Structure and Split Identity" below). This works for RSA-2048+ device keys.

The protocol layer (UID derivation, signature verification) also accepts ECDSA P-256 and Ed25519 device keys, but bidirectional verify is currently RSA-only. A device that registers with an ECDSA or Ed25519 key cannot participate in the encrypted-payload exchange until the corresponding ECIES (ECDH + HKDF + AES-GCM) and X25519 paths are implemented. Adding those is a documented follow-up — see "Implementation Notes" below.

## URL Structure and Split Identity

### The Problem

The signaling server brokers all connections. It sees every UID. Without additional protection, the server could connect to any device it routes for — it knows all the addresses.

### Split Identity

BitBang URLs contain two components:

```
https://bitba.ng/<UID>#<code>
                 └─128 bits─┘ └─64 bits─┘
                 (22 base64url) (11 base64url)
```

| Component | Bits | Purpose | Seen by server? |
|-----------|------|---------|-----------------|
| UID | 128 | Identity (routing) | Yes |
| Code | 64 | Authorization | No (fragment) |

Both are encoded as **base64url without padding** (alphabet
`[A-Za-z0-9_-]`). The format is URL-safe end-to-end (no percent-encoding
in either the path or the fragment), stdlib in every relevant language
(Python `base64.urlsafe_b64encode`, Go `base64.RawURLEncoding`, JS a
short wrapper over `btoa()`), and roughly 35% shorter than the same
bit count rendered as hex.

The fragment (`#`) is never sent to the server. Server routes by UID but can't see the code.

**Result:** Server is a dumb pipe. It can route connections but can't use them.

### Completing the Trustless Story

| Property | How |
|----------|-----|
| Server can't MITM | Bidirectional verification |
| Server can't read traffic | DTLS encryption |
| Server can't connect | Split identity (code in fragment) |

Split identity is the third leg. The server brokers all connections but is powerless to exploit that position.

### Security Analysis

**128-bit UID:**

| Attack | Resistance |
|--------|------------|
| Preimage (find keypair matching UID) | 2^128 — infeasible |
| Birthday collision | ~2^64 devices before concern — far beyond any realistic deployment |

**64-bit code:**

| Attempts | Time at 2 sec/attempt | Notes |
|----------|----------------------|-------|
| 2^64 | ~1.2 trillion years | Device rate-limits per IP |

Code brute force is online only — device controls the rate. At 2 seconds per WebRTC handshake, even with massive parallelism, 64 bits is so far beyond practical attack that the device-side rate limit on bad-code attempts is the operative bound, not the bit length.

### Browser IP in Connection Request

The signaling server includes the browser's IP address in the connection request forwarded to the device:

```
{
  uid: "...",
  encrypted_payload: "...",  ← server can't read (pubkey-encrypted)
  browser_ip: "1.2.3.4"      ← server provides
}
```

**Why this matters:**

The device needs the browser IP *before* the DTLS handshake completes — for rate-limiting bad code attempts. The timing:

```
1. Browser connects to signaling server    ← server has browser IP
2. Browser sends encrypted payload (code)
3. Device decrypts, checks code            ← need IP here for rate limiting
4. If code OK → DTLS handshake completes   ← device sees IP here, too late
```

For TURN-relayed connections, the device would see the TURN server's IP in DTLS, not the browser's. Signaling server provides the true origin.

**Use cases:**

| Use | How |
|-----|-----|
| Rate limit code attempts | 3 failures from same IP → temporary block |
| Geo-blocking | Reject IPs from unwanted regions |
| Logging/audit | Who attempted connection |

**Trust consideration:** Device trusts server to report accurate IP. But server can't forge the encrypted payload, so worst case is wrong IP in logs — not a security breach.

### URL Structure with Flags

Query string for server-visible flags, fragment for secrets:

```
https://bitba.ng/<UID>?norelay&debug#<code>
                      └─ server sees ─┘ └─ server doesn't see
```

| Component | Seen by server | Examples |
|-----------|----------------|----------|
| Path (UID) | Yes | Routing |
| Query string | Yes | norelay, debug |
| Fragment (code) | No | Access authorization |

PIN remains out-of-band (entered in UI), providing defense in depth against URL leaks.

## Additional Security Options

### PIN (Authorization)

PIN adds authorization on top of identity verification — controls who can connect, not whether the connection is secure.

PIN is exchanged as a typed control frame on the WebRTC data channel after bidirectional verify succeeds and before any application traffic. The signaling server never sees PIN attempts because the frame is inside DTLS.

```
After data channel opens:
  Device → Browser: verify_nonce_hash   (always — bidirectional verify)
  Browser verifies hash(nonce) matches expected
  Browser → Device: connect             (path, caps, version)
  Device → Browser: auth_required       (if PIN configured)
  Browser → Device: auth                (PIN entered by user)
  Device → Browser: auth_result         (success or failure)
  Application traffic flows
```

Each frame is a stream-0 SYN with a JSON payload. PIN handling shares the same envelope shape as the verify frame and any future SAS confirmation — a single "control frame on stream 0" code path on both sides.

| | Without PIN | With PIN |
|---|-------------|----------|
| Rogue-proof | Yes | Yes |
| URL leak = full access | Yes | No |

### SAS Code Exchange (Human Verification)

For highest security, both sides can compute a code from their DTLS fingerprints:

```
code = truncate(hash(sort(localFingerprint, peerFingerprint)))
```

This is the Short Authentication String (SAS) pattern from ZRTP (RFC 6189), created by Phil Zimmermann (PGP).

Users compare codes verbally: "I see 1234" / "I see 1234" — if they match, connection is verified. A rogue relay produces mismatched codes.

If implemented as a connection gate, SAS would flow as a `verify_sas_confirm` control frame on stream 0, alongside the verify and PIN frames — same envelope, same code path.

**Advantage:** Human-verifiable, no trust in code.
**Disadvantage:** Requires operator confirmation.

### UID#fragment Scheme (Alternative)

The URL fragment (after `#`) is never sent to the server:

```
https://bitba.ng/8f3a7b...#<secret>
                         ↑
                         Never sent to server
```

Device generates secret S, includes it in fragment. Browser extracts S, uses it to encrypt SDP.

**Advantage:** Rogue-proof without operator confirmation.
**Disadvantage:** URL leak = full access (combine with PIN to mitigate).

## Scheme Comparison

| Scheme | Device operator confirms? | Rogue-proof? | URL leak = full access? |
|--------|---------------------------|--------------|------------------------|
| UID only | No | No | Yes |
| UID + PIN | No | No | No |
| **UID + encrypted fingerprint (baseline)** | **No** | **Yes** | **Yes** |
| **UID + encrypted fingerprint + PIN** | **No** | **Yes** | **No** |
| UID + SAS (fingerprint code) | Yes | Yes | Yes |
| UID#fragment | No | Yes | Yes |

## Why Trustless Signaling Matters

Most P2P systems trust the signaling server:
- **WebRTC apps:** Trust the signaling server
- **Tailscale:** Trust Tailscale's coordination servers
- **Signal:** Trust Signal's servers for key distribution

BitBang's trustless signaling enables:
- **Self-hosting** without security expertise
- **Ubiquitous hosting** without vetting providers
- **Portable identity** — UID is self-sovereign, not server-assigned
- **Commodity pricing** through competition

### Trust Summary

| Layer | What it does | Who we trust |
|-------|--------------|--------------|
| TLS to signaling server | Protects wire | Certificate authority |
| UID = hash(pubkey) | Binds identity | Math |
| Encrypted fingerprint | Device verifies browser | Device's private key |
| Nonce response | Browser verifies device | Device's private key |
| DTLS | Encrypts data channel | Verified fingerprint |

No trust in signaling server required. Verification is bidirectional.

---

## Implementation Notes

### Wire Shape

#### Device pubkey rides on the offer

The signaling server attaches `ice_servers`, `turn_unavailable`, `device_name`, and `device_pubkey` to the offer it relays from the device to the browser:

```json
{
  "type": "offer",
  "client_id": "<id>",
  "sdp": "...",
  "device_pubkey": "<base64 SPKI DER>",
  "ice_servers": [...],
  "turn_unavailable": false
}
```

The browser checks `hash(device_pubkey) == uid` *before* calling `setRemoteDescription` and aborts otherwise. This costs the browser no extra round trip — the pubkey arrives exactly when it's needed, just before the answer is built. A rogue signaling server cannot substitute a different key without failing the hash check.

#### Browser → Device: encrypted_request rides on the SDP answer

The browser is the answerer in BitBang's WebRTC flow (the device offers streams). After `createAnswer()` / `setLocalDescription(answer)` the browser knows its own DTLS fingerprint, so this is when the encrypted payload is generated and shipped alongside the SDP:

```json
{
  "type": "answer",
  "client_id": "<id>",
  "sdp": "...",
  "encrypted_request": "<base64 ciphertext>"
}
```

The ciphertext wraps:

```json
{
  "fingerprint": "<browser DTLS sha-256 fingerprint, uppercase colon-separated>",
  "nonce": "<base64 16 random bytes>"
}
```

#### Device → Browser: verify_nonce_hash (first stream-0 frame)

Sent as the first SYN frame on stream 0 immediately when the data channel opens:

```json
{ "type": "verify_nonce_hash", "hash": "<base64 sha256(nonce)>" }
```

The browser refuses to send anything else (including the `connect` handshake) until this frame is received and the hash matches `sha256(nonce)` for the nonce it generated.

#### PIN, SAS, future verifications

Stay on stream 0 with the same envelope shape. PIN flows as `auth_required` / `auth` / `auth_result` frames; a future SAS confirmation would be a `verify_sas_confirm` frame. The browser-side verify gate and the device-side control handler share a single code path for all of them.

### Encrypted Fingerprint Payload (Go device, RSA-OAEP/SHA-256)

```go
type ConnectionRequest struct {
    Fingerprint string `json:"fingerprint"`
    Nonce       string `json:"nonce"`
    Code        string `json:"code"`
}

// Browser-side: generate nonce and encrypt with device's RSA pubkey.
nonce := make([]byte, 16)
rand.Read(nonce)
payload, _ := json.Marshal(ConnectionRequest{
    Fingerprint: localDTLSFingerprint,
    Nonce:       base64.StdEncoding.EncodeToString(nonce),
    Code:        accessCodeFromURLFragment,
})
encrypted, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, devicePubkey, payload, nil)
```

Note: this is RSA-OAEP only. Devices registered with ECDSA P-256 or Ed25519 keys cannot participate in bidirectional verify until ECIES / X25519 paths are added.

### Device Verification (Go)

```go
// Decrypt with the device's private key.
decrypted, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encrypted, nil)
var req ConnectionRequest
json.Unmarshal(decrypted, &req)

// Check the access code first — a wrong code should never leak whether
// the fingerprint matched. Constant-time compare against the code that
// was persisted alongside the private key.
if subtle.ConstantTimeCompare([]byte(req.Code), []byte(deviceAccessCode)) != 1 {
    return errors.New("bad access code")
}

// Confirm the fingerprint in the encrypted payload matches the one the
// SDP delivered. A rogue relay would have rewritten the SDP fingerprint
// and would mismatch here — at which point we close the connection and
// send no verify_nonce_hash frame, which the browser will treat as a
// failed verification.
sdpFingerprint := extractFingerprint(peerConnection.RemoteDescription().SDP)
if req.Fingerprint != sdpFingerprint {
    return errors.New("fingerprint mismatch — possible MITM")
}

// On data channel open, send the nonce hash as the first stream-0 frame.
nonceBytes, _ := base64.StdEncoding.DecodeString(req.Nonce)
nonceHash := sha256.Sum256(nonceBytes)
sendVerifyNonceHashFrame(dc, base64.StdEncoding.EncodeToString(nonceHash[:]))
```

### Browser Verification (JavaScript)

```javascript
// Generate nonce and encrypt connection request with device pubkey.
// `code` is the URL fragment (window.location.hash.slice(1)) — never
// sent to the signaling server because browsers don't transmit fragments.
async function encryptConnectionRequest(pubkeyDER, fingerprint, code) {
    const pubkey = await crypto.subtle.importKey(
        'spki',
        pubkeyDER,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );

    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const payload = JSON.stringify({
        fingerprint,
        nonce: btoa(String.fromCharCode(...nonce)),
        code,
    });
    const encrypted = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        pubkey,
        new TextEncoder().encode(payload)
    );
    return { encrypted, nonce };
}

// Verify device's nonce-hash control frame
async function verifyNonceResponse(nonce, receivedHashB64) {
    const expected = await crypto.subtle.digest('SHA-256', nonce);
    const expectedB64 = btoa(String.fromCharCode(...new Uint8Array(expected)));
    return receivedHashB64 === expectedB64;
}

// Extract fingerprint from SDP
function extractFingerprint(sdp) {
    const match = sdp.match(/a=fingerprint:sha-256 ([A-F0-9:]+)/i);
    return match ? match[1].toUpperCase() : null;
}
```

### Fingerprint-Derived Code (SAS)

```go
// After DTLS established
local := extractFingerprint(localSDP)
remote := extractFingerprint(remoteSDP)

// Sort for consistency (both sides compute same order)
pair := []string{local, remote}
sort.Strings(pair)

// Hash and truncate to 4 digits
hash := sha256.Sum256([]byte(pair[0] + pair[1]))
code := binary.BigEndian.Uint32(hash[:4]) % 10000

fmt.Printf("Verification code: %04d\n", code)
```

---

# Part 2: Network Security

## The Problem

Device networks add complexity. Point-to-point connections verify directly, but networks route through the server via MQTT pub/sub.

```
Device claims membership in network N with token T
Server routes: device subscribes to /network/N/*
Other devices: trust server's routing decisions
```

A rogue server could let anyone join any network. Server controls pub/sub ACLs. This is a trustless hole.

## Simple Solution: Symmetric Network Key

All network members share a symmetric key K. Payloads are encrypted.

```
Topic: /network/<network_id>/device/<uid>/...   ← plaintext, server routes
Payload: encrypt(actual_data, K)                 ← encrypted
```

**Rogue server can:**
- Withhold messages (DoS)
- Replay old messages
- See metadata (topics, timing, size)

**Rogue server can't:**
- Read payloads (no K)
- Forge messages (no K)

## Token and Invitation

The network access token is a signed struct — only the network owner can create it:

```
Token (signed by network owner's private key):
{
  uid: target device,
  network_id: N,
  permissions: { ... },
  expiry: timestamp
}
```

Token is small and stored by the device.

### Server Verification

When a device joins a network, it presents its token to the server. The server verifies:

1. Signature is valid (signed by network owner's pubkey)
2. Token hasn't expired
3. UID in token matches claiming device

If valid, server adds device to network table and allows subscription to `/network/N/*`.

This prevents arbitrary devices from joining networks — the server enforces membership, not just the peers. The network owner's pubkey is registered with the server when the network is created.

### Invitation

The invitation delivers the token plus the symmetric key:

```
Invitation (encrypted with invitee's device pubkey):
{
  token: { uid, network_id, permissions, expiry, signature },
  K: <symmetric key>
}
```

Only the invitee can decrypt. Server can relay the invitation but can't read it.

**Device receives invitation:**
1. Decrypt with device private key
2. Present token to server → server adds to network table
3. Store token (credential)
4. Store K (for payload encryption)
5. Discard invitation wrapper

This follows the same pattern as TLS: asymmetric encryption to exchange a symmetric key, then symmetric encryption for bulk data.

## What This Achieves

| Property | How |
|----------|-----|
| Only owner can invite | Only owner can sign tokens |
| Invitation is targeted | Encrypted to invitee's pubkey |
| Server can't read invitation | Encrypted |
| Server can't read messages | Payload encrypted with K |
| Server can't forge messages | No K |
| Members can verify each other | Check token signature against network owner's pubkey |

## Limitations

This isn't fully trustless — server still controls routing and can DoS. But it protects confidentiality and authenticity, which covers the main concerns.

Fully trustless MQTT would require signing every message with sender's private key, receivers verifying signature plus token. Expensive for high-frequency data. The symmetric key approach is a pragmatic middle ground.

---

## Key Management: Derivation, Not Storage

A fundamental problem with network ownership: where do you store the network private keys?

| Approach | Problem |
|----------|---------|
| Server stores keys | Server compromise = all networks compromised |
| User stores keys | Backup burden, device loss = key loss |
| Password manager | Extra dependency, sync issues |

BitBang's answer: don't store keys. Derive them.

### Passkey + PRF (Highly Preferred, Possibly Required)

WebAuthn PRF extension derives deterministic secrets from a passkey:

```
seed = PRF(passkey, "network:home-sensors")
keypair = Ed25519(seed)
network_id = hash(pubkey)
```

Same passkey, same salt → same keypair, every time, on any device.

**User identity:**
```
user_id = hash(credential_id)
Server stores: user_id → network list
```

No password. No password hash. Server stores only a public identifier and network names.

**Recovery:** Passkeys sync via Google/Apple accounts. User recovers Google/Apple account → passkeys restore automatically. "Forgot password" doesn't exist because there's no password. Recovery UX is normal.

| Platform | PRF Support |
|----------|-------------|
| Android (Chrome, Edge, Samsung) | Best — works by default with Google Password Manager |
| Desktop (all major browsers) | Good |
| iOS | Limited — platform authenticator (Face ID/iCloud) only |

**Why requiring passkeys isn't unreasonable:**

| Concern | Answer |
|---------|--------|
| Browser support | Universal now |
| Recovery | Google/Apple handles it |
| UX | Familiar (biometrics) |
| Cross-device | Passkeys sync |

### Username + Password (Alternative)

For environments where passkeys aren't available, a traditional username/password scheme:

```
user_id = hash(username)
Server stores: user_id, hash(password), network list
```

**Key derivation:**
```
seed = HKDF(password, username, "network:home-sensors")
keypair = Ed25519(seed)
```

Password never transmitted raw — client hashes before sending. But server stores password hash for login verification.

**Security comparison:**

| | Passkey | Password |
|---|---------|----------|
| Server stores password hash | No | Yes |
| Breach → crackable credentials | No | Yes |
| Network keys safe from breach | Yes (PRF never on server) | No (password crackable) |
| Recovery | Google/Apple account | Impossible |

**Drawbacks of password path:**

1. **No recovery.** Password is identity. Server can't help — it never had the raw password. "Forgot password" = start over.

2. **Crackable.** Server breach exposes password hashes. Weak passwords cracked offline → attacker derives network keys.

3. **Password manager required.** Without one, user burden is high and security suffers.

4. **Same security as traditional accounts.** No worse, but no better. The "accountless" benefit disappears.

**If offering password path:**

- Require strong passwords (length, complexity)
- Document clearly: no recovery possible
- Recommend password manager
- Present as fallback, not primary

### One Passkey, Unlimited Networks

Regardless of path, a single identity can derive unlimited network keypairs:

```
PRF(passkey, "network:home-sensors") → network 1 keypair
PRF(passkey, "network:cabin")        → network 2 keypair
PRF(passkey, "network:workshop")     → network 3 keypair
```

Or with password:
```
HKDF(password, username, "network:home-sensors") → network 1 keypair
HKDF(password, username, "network:cabin")        → network 2 keypair
```

No "add network to account." Just name a network — the keypair is derived deterministically.

### What bitba.ng Stores

**Passkey path:**

| Data | Stored? | Sensitive? |
|------|---------|------------|
| user_id (hash of credential_id) | Yes | No |
| Network names | Yes | No |
| Network ID → owner pubkey | Yes | No |
| Member UIDs | Yes | No |
| Password hash | No | — |
| Private keys | No | — |
| Encryption key K | No | — |

**Password path:**

| Data | Stored? | Sensitive? |
|------|---------|------------|
| user_id (hash of username) | Yes | No |
| hash(password) | Yes | Somewhat (crackable) |
| Network names | Yes | No |
| Everything else | Same as above | |

### Why This Matters for Trustless Signaling

Trustless signaling means: don't trust the server.

With passkeys, key derivation completes the model. Server doesn't just *promise* not to see your keys — it *can't* see them. They're derived client-side via PRF and never transmitted.

With passwords, server stores a hash. If breached and cracked, attacker can derive network keys. The trustless property weakens.

| | Passkey | Password |
|---|---------|----------|
| Server compromise impact | Phonebook leak | Credential + key exposure |
| Trust model | "Trust math" | "Trust our hashing + your password strength" |

---

# (Unintentional) Lock-in

BitBang's architecture appears maximally portable:

| Component | Portable? |
|-----------|-----------|
| Protocol | Open, documented |
| Server | Self-hostable |
| Device identity | Self-sovereign (UID = hash(device pubkey)) |
| Server stores | Nothing sensitive |

The implication: users are free. No proprietary data formats. No vendor protocols. Switch anytime.

**The reality is different.**

Passkeys are origin-bound. A passkey created for bitba.ng only works on bitba.ng. The browser enforces this — it's a security feature, not a bug.

```
Passkey for bitba.ng     → credential_id_A → user_id_A → network keys
Passkey for self-hosted  → credential_id_B → user_id_B → different keys
```

User can't migrate to a self-hosted server and keep their networks. The network private keys are derived from the passkey. Different origin = different passkey = different keys = start over.

**What's portable vs what's not:**

| | Portable | Not portable |
|---|----------|--------------|
| Device identity | ✓ | |
| Network membership tokens | ✓ (signed, verifiable anywhere) | |
| User identity (passkey) | | ✗ (origin-bound) |
| Network ownership keys | | ✗ (derived from passkey) |

**Who enforces the lock-in:**

| Traditional IoT | BitBang |
|-----------------|---------|
| Server holds your data hostage | Browser holds your passkey hostage |
| Vendor's choice | W3C spec |
| Feels like lock-in | Feels like freedom |

**The irony:**

The trustless, open, nothing-sensitive-stored architecture creates lock-in as a side effect of browser security. It's not intentional — it's how passkeys work. But it's real.

Users perceive: "BitBang stores nothing about me. I could switch anytime."

Users experience: "My network keys are derived from a passkey bound to bitba.ng. Switching means starting over."

**Workarounds:**

- **Export derived network keys:** Once derived, network keys are just bytes. Client can export them for import on another server. This works — but user now has raw private keys to manage.
- **Passkey portability (future):** WebAuthn is adding credential portability, but this is a signed attestation ("this user was authenticated"), not the raw private key. It wouldn't help derive the same network keys on a new origin.
- **Password path:** Not origin-bound — same username + password on any server derives same keys. But passwords are crackable and less secure.

**Key export in practice:**

```
User clicks "Export network keys"
Browser shows:
  home-sensors: 7f3a2b... (Ed25519 private key)
  cabin: 9c1d4e...
  
User saves file, imports on self-hosted server
```

The keys are derived client-side. Nothing prevents exporting them except UX choices.

| | Don't export | Export |
|---|--------------|--------|
| User burden | None (derive on demand) | Manage a key file |
| Migration possible | No | Yes |
| Security | Keys never materialized as files | Keys exist as files somewhere |

The lock-in is soft, not hard. Migration requires exporting keys — inconvenient but possible. BitBang could offer this as a feature, or not. The architecture allows either choice.
