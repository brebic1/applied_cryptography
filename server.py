import asyncio
import json
import os
import hashlib
import hmac
import base64
import datetime
import websockets


R  = "\033[0m"         # reset
B  = "\033[1m"         # bold
DIM= "\033[2m"         # dim
CY = "\033[96m"        # cyan      — network / connection events
GR = "\033[92m"        # green     — success / auth OK
YL = "\033[93m"        # yellow    — key exchange / crypto info
MG = "\033[95m"        # magenta   — message relay
RD = "\033[91m"        # red       — errors / rejections
BL = "\033[94m"        # blue      — registration
WH = "\033[97m"        # white     — section headers
GY = "\033[90m"        # grey      — verbose hex dumps

SEP  = f"{GY}{'─'*70}{R}"
SEP2 = f"{GY}{'═'*70}{R}"

def ts() -> str:
    """Current timestamp string."""
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def log(colour: str, tag: str, msg: str):
    print(f"{DIM}{ts()}{R}  {colour}{B}[{tag:^18}]{R}  {msg}")

def log_sep(title: str = ""):
    if title:
        pad = (68 - len(title)) // 2
        print(f"\n{GY}{'─'*pad} {WH}{B}{title}{R} {GY}{'─'*pad}{R}")
    else:
        print(SEP)

def hex_preview(b64_str: str, label: str = "", maxbytes: int = 12) -> str:
    """Decode base64 and show first N bytes as hex — proves server sees raw bytes."""
    try:
        raw = base64.b64decode(b64_str)
        preview = raw[:maxbytes].hex()
        total = len(raw)
        return f"{GY}{label}[{total}B] {preview}…{R}"
    except Exception:
        return f"{GY}{label}<decode error>{R}"

USER_REGISTRY: dict[str, dict] = {}   # username → {salt, dk}
SESSIONS:      dict             = {}   # ws       → username
PUBLIC_KEYS:   dict[str, str]   = {}   # username → b64 pubkey
SEQ_COUNTERS:  dict[str, dict]  = {}   # recipient → {sender → last_seq}

PBKDF2_ITERS = 600_000
DK_LEN       = 32

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS, DK_LEN)

def verify_hmac_response(challenge: bytes, dk: bytes, response_b64: str) -> bool:
    expected = hmac.new(dk, challenge, hashlib.sha256).digest()
    try:
        received = b64d(response_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, received)


async def tx(ws, obj: dict):
    await ws.send(json.dumps(obj))

async def relay_to(username: str, raw_str: str):
    """Send raw JSON string to a specific authenticated user."""
    for w, u in SESSIONS.items():
        if u == username:
            try:
                await w.send(raw_str)
            except Exception:
                pass
            return


async def handle(ws):
    addr     = ws.remote_address
    username = None

    log_sep("NEW CONNECTION")
    log(CY, "NET", f"Client connected from {addr[0]}:{addr[1]}")

    try:

        raw  = await ws.recv()
        data = json.loads(raw)
        msg_type = data.get("type")

        log(CY, "NET", f"Received initial frame  type='{msg_type}'")

        if msg_type not in ("register", "login"):
            log(RD, "PROTO ERROR", f"Unexpected type '{msg_type}' — closing")
            await tx(ws, {"type": "auth_error", "message": "Expected register or login"})
            return

        username = data.get("username", "").strip()
        password = data.get("password", "")

        if msg_type == "register":
            log_sep("REGISTRATION")
            log(BL, "REGISTER", f"New account request for '{username}'")

            if not username or not password:
                log(RD, "REGISTER FAIL", "Empty username or password")
                await tx(ws, {"type": "auth_error", "message": "Username and password required"})
                return

            if username in USER_REGISTRY:
                log(RD, "REGISTER FAIL", f"Username '{username}' already taken")
                await tx(ws, {"type": "auth_error", "message": "Username already taken"})
                return

           
            salt = os.urandom(32)
            log(BL, "REGISTER", f"Generated salt (256-bit CSPRNG):  {GY}{salt.hex()}{R}")

           
            log(BL, "REGISTER", f"Running PBKDF2-HMAC-SHA256 ({PBKDF2_ITERS:,} iterations)…")
            dk = derive_key(password, salt)
            log(BL, "REGISTER", f"Derived key (stored hash):         {GY}{dk.hex()}{R}")
            log(BL, "REGISTER", f"{GR}Plaintext password is DISCARDED — only hash stored{R}")

            USER_REGISTRY[username] = {"salt": salt, "dk": dk}
            log(GR, "REGISTER OK", f"Account '{username}' created and stored in USER_REGISTRY")
            log_sep()

            await tx(ws, {"type": "register_ok", "message": f"Account created for {username}"})

           
            raw  = await ws.recv()
            data = json.loads(raw)
            if data.get("type") != "login" or data.get("username") != username:
                await tx(ws, {"type": "auth_error", "message": "Expected login after register"})
                return
            password = data.get("password", "")
            log(CY, "NET", f"Received login frame after registration for '{username}'")


        log_sep("PHASE 2 — AUTHENTICATION")
        log(YL, "AUTH", f"Login attempt for '{username}'")

        if username not in USER_REGISTRY:
            log(RD, "AUTH FAIL", f"Unknown user '{username}'")
            _ = derive_key("dummy", os.urandom(32))
            await tx(ws, {"type": "auth_error", "message": "Invalid credentials"})
            return

        if username in SESSIONS.values():
            log(RD, "AUTH FAIL", f"'{username}' already has an active session")
            await tx(ws, {"type": "auth_error", "message": "Already connected"})
            return

        record    = USER_REGISTRY[username]
        challenge = os.urandom(32)

        log(YL, "AUTH", f"Generated 256-bit random challenge: {GY}{challenge.hex()}{R}")
        log(YL, "AUTH", f"Sending challenge to client (single-use, prevents replay)")

        await tx(ws, {
            "type":      "auth_challenge",
            "challenge": b64e(challenge),
            "salt":      b64e(record["salt"])
        })


        raw  = await asyncio.wait_for(ws.recv(), timeout=15.0)
        data = json.loads(raw)

        if data.get("type") != "auth_response":
            log(RD, "AUTH FAIL", f"Expected 'auth_response', got '{data.get('type')}'")
            await tx(ws, {"type": "auth_error", "message": "Expected auth_response"})
            return

        client_hmac_b64 = data.get("response", "")
        log(YL, "AUTH", f"Received HMAC-SHA256 response from client: {GY}{client_hmac_b64[:32]}…{R}")

       
        log(YL, "AUTH", f"Re-running PBKDF2-HMAC-SHA256 ({PBKDF2_ITERS:,} iterations) for verification…")
        dk = derive_key(password, record["salt"])
        expected_hmac = hmac.new(dk, challenge, hashlib.sha256).digest()

        log(YL, "AUTH", f"Expected HMAC (server-computed): {GY}{expected_hmac.hex()}{R}")
        log(YL, "AUTH", f"Received HMAC (from client):     {GY}{b64d(client_hmac_b64).hex()}{R}")

        if not verify_hmac_response(challenge, dk, client_hmac_b64):
            log(RD, "AUTH FAIL", f"HMAC mismatch — invalid credentials for '{username}'")
            await tx(ws, {"type": "auth_error", "message": "Invalid credentials"})
            return

        log(GR, "AUTH OK", f"HMAC verified with hmac.compare_digest (constant-time) ✓")
        log(GR, "AUTH OK", f"'{username}' authenticated successfully")
        log(YL, "AUTH", f"{GR}Password was used only for PBKDF2 — never stored or forwarded{R}")

        SESSIONS[ws] = username
        SEQ_COUNTERS.setdefault(username, {})

        await tx(ws, {"type": "login_success", "message": f"Authenticated as {username}"})

        if PUBLIC_KEYS:
            log(YL, "KEY DIST", f"Sending {len(PUBLIC_KEYS)} existing public key(s) to '{username}'")
            for user, pk in PUBLIC_KEYS.items():
                log(YL, "KEY DIST", f"  → forwarding public key of '{user}' to '{username}'")
                await tx(ws, {"type": "public_key", "sender": user, "public_key": pk})
        else:
            log(YL, "KEY DIST", "No existing public keys to distribute (first user)")

        log_sep()

        async for raw in ws:
            try:
                data     = json.loads(raw)
                msg_type = data.get("type")
            except json.JSONDecodeError:
                log(RD, "PROTO ERROR", "Invalid JSON received — ignoring")
                continue

           
            if msg_type == "public_key":
                sender = data.get("sender", "?")
                pubkey_b64 = data.get("public_key", "")
                log_sep("PHASE 1 — KEY EXCHANGE")
                log(YL, "KEY EXCHANGE", f"Received X25519 public key from '{sender}'")
                log(YL, "KEY EXCHANGE", f"Public key (base64): {GY}{pubkey_b64[:44]}…{R}")
                log(YL, "KEY EXCHANGE", hex_preview(pubkey_b64, "Raw bytes preview: ", maxbytes=16))
                log(YL, "KEY EXCHANGE", f"{RD}Server stores this public key but CANNOT compute")
                log(YL, "KEY EXCHANGE", f"the shared ECDH secret — private keys never leave clients{R}")

                PUBLIC_KEYS[sender] = pubkey_b64

                
                other_peers = [u for u in SESSIONS.values() if u != sender]
                if other_peers:
                    log(YL, "KEY DIST", f"Broadcasting '{sender}' public key to {len(other_peers)} peer(s): {other_peers}")
                    for peer in other_peers:
                        await relay_to(peer, json.dumps(data))
                        log(YL, "KEY DIST", f"  → forwarded to '{peer}'")
                else:
                    log(YL, "KEY DIST", "No other peers online to broadcast to")

                log_sep()

            
            elif msg_type == "message":
                sender    = data.get("sender",    "?")
                recipient = data.get("recipient", "?")
                seq       = data.get("sequence",   0)
                nonce_b64 = data.get("nonce",      "")
                ciph_b64  = data.get("ciphertext", "")

                log_sep("PHASE 3 — MESSAGE RELAY")
                log(MG, "MESSAGE", f"From: '{sender}'  →  To: '{recipient}'  |  seq={seq}")

            
                if sender != SESSIONS.get(ws):
                    log(RD, "SECURITY", f"Sender spoofing detected! Claimed '{sender}' but ws belongs to '{SESSIONS.get(ws)}'")
                    await tx(ws, {"type": "error", "message": "Sender identity mismatch"})
                    continue

                log(MG, "MESSAGE", f"Sender identity verified ✓  ('{sender}' matches authenticated session)")

                
                if recipient not in SESSIONS.values():
                    log(RD, "MESSAGE", f"Recipient '{recipient}' is not connected — dropping")
                    await tx(ws, {"type": "error", "message": f"Recipient '{recipient}' not connected"})
                    continue

                log(MG, "MESSAGE", f"Recipient '{recipient}' is online ✓")

                
                last_seq = SEQ_COUNTERS.get(recipient, {}).get(sender, 0)
                log(MG, "REPLAY CHECK", f"Sequence: received={seq}  last_accepted={last_seq}")

                if seq <= last_seq:
                    log(RD, "REPLAY BLOCK", f"REPLAYED or OUT-OF-ORDER message dropped! seq={seq} ≤ last={last_seq}")
                    await tx(ws, {"type": "error", "message": "Replay attack detected — message dropped"})
                    continue

                SEQ_COUNTERS.setdefault(recipient, {})[sender] = seq
                log(MG, "REPLAY CHECK", f"Sequence accepted — counter updated to {seq} ✓")

                log(MG, "CIPHERTEXT", f"Nonce  (192-bit):  {hex_preview(nonce_b64,  '', maxbytes=24)}")
                log(MG, "CIPHERTEXT", f"Cipher (XSalsa20): {hex_preview(ciph_b64,   '', maxbytes=20)}")
                log(MG, "CIPHERTEXT", f"Ciphertext length: {GY}{len(base64.b64decode(ciph_b64))} bytes{R}")
                log(MG, "E2EE PROOF",
                    f"{RD}Server sees ONLY opaque ciphertext — no decryption key available.")
                log(MG, "E2EE PROOF",
                    f"NaCl box uses X25519 ECDH shared secret known only to sender+recipient.{R}")
                log(MG, "E2EE PROOF",
                    f"{RD}Even if server is compromised, messages remain confidential.{R}")
              
                await relay_to(recipient, raw)
                log(MG, "RELAY", f"Ciphertext forwarded verbatim to '{recipient}' — no modification ✓")
                log_sep()

            else:
                log(RD, "PROTO", f"Unknown message type '{msg_type}' — ignoring")

    except asyncio.TimeoutError:
        log(RD, "TIMEOUT", f"Auth timeout for '{username or addr[0]}'")
    except websockets.exceptions.ConnectionClosed as e:
        log(CY, "NET", f"Connection closed for '{username or addr[0]}'  code={e.code}")
    except Exception as e:
        log(RD, "ERROR", f"Unhandled exception: {e}")
        import traceback; traceback.print_exc()
    finally:
        if ws in SESSIONS:
            gone = SESSIONS.pop(ws)
            PUBLIC_KEYS.pop(gone, None)
            SEQ_COUNTERS.pop(gone, None)
            log_sep("DISCONNECT")
            log(CY, "NET", f"'{gone}' disconnected — session and keys purged from memory")
            log_sep()


async def main():
    print(f"\n{WH}{B}{'═'*70}{R}")
    print(f"{WH}{B}{'  NEXUS SECURE CHAT SERVER':^70}{R}")
    print(f"{WH}{B}{'═'*70}{R}")
    print(f"  {CY}Listening{R}    ws://localhost:6789")
    print(f"  {YL}Key Exchange{R} X25519 ECDH  (ephemeral, client-side only)")
    print(f"  {YL}Encryption{R}   XSalsa20-Poly1305  (NaCl box, AEAD)")
    print(f"  {YL}Auth{R}         PBKDF2-HMAC-SHA256  ({PBKDF2_ITERS:,} iterations)")
    print(f"  {YL}Challenge{R}    256-bit random nonce  (single-use)")
    print(f"  {YL}Replay{R}       Monotonic sequence numbers  (server-enforced)")
    print(f"  {RD}E2EE{R}         Server CANNOT decrypt messages  (no shared secret)")
    print(f"{WH}{B}{'═'*70}{R}\n")

    async with websockets.serve(handle, "localhost", 6789):
        await asyncio.Future()


asyncio.run(main())
