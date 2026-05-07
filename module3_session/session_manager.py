"""
=============================================================
MODULE 3: Secure Session Manager
Project: Secure Authentication Framework for Operating Systems
=============================================================
"""

import jwt
import uuid
import os
import time
import hashlib
from datetime import datetime, timedelta, timezone

# ─────────────────────────────────────────────
# SECTION 1: JWT TOKEN ENGINE
# ─────────────────────────────────────────────

class JWTTokenEngine:
    """
    Issues and verifies signed JWT tokens for authenticated sessions.
    Uses HS256 (HMAC-SHA256) signing — tokens are tamper-proof.
    """

    def __init__(self):
        # In production: load from environment variable, never hardcode
        self.secret_key = os.environ.get("AUTH_SECRET_KEY", os.urandom(32).hex())
        self.algorithm  = "HS256"
        self.access_expiry_minutes  = 30    # Short-lived access token
        self.refresh_expiry_days    = 7     # Longer refresh token

    def issue_access_token(self, username: str, role: str = "user") -> str:
        """
        Generate a short-lived access token (30 min).
        Payload contains: user identity, role, issue time, expiry, unique ID.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "jti"      : str(uuid.uuid4()),          # Unique token ID
            "sub"      : username,                    # Subject (user)
            "role"     : role,                        # user / admin / root
            "iat"      : now,                         # Issued at
            "exp"      : now + timedelta(minutes=self.access_expiry_minutes),
            "type"     : "access",
            "issuer"   : "SecureAuthOS"
        }
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token

    def issue_refresh_token(self, username: str) -> str:
        """
        Generate a long-lived refresh token (7 days).
        Used to obtain new access tokens without re-login.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "jti"   : str(uuid.uuid4()),
            "sub"   : username,
            "iat"   : now,
            "exp"   : now + timedelta(days=self.refresh_expiry_days),
            "type"  : "refresh",
            "issuer": "SecureAuthOS"
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> dict:
        """
        Decode and verify token signature + expiry.
        Returns payload dict on success, error dict on failure.
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": True}
            )
            return {"valid": True, "payload": payload, "error": None}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "payload": None, "error": "TOKEN_EXPIRED"}
        except jwt.InvalidTokenError as e:
            return {"valid": False, "payload": None, "error": f"INVALID_TOKEN: {e}"}

    def decode_without_verify(self, token: str) -> dict:
        """Decode token without verification — for inspection only."""
        return jwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=[self.algorithm]
        )


# ─────────────────────────────────────────────
# SECTION 2: TOKEN REVOCATION LIST
# ─────────────────────────────────────────────

class TokenRevocationList:
    """
    Maintains a denylist of invalidated tokens (logout / force-expire).
    In production: stored in Redis for fast O(1) lookups across servers.
    """

    def __init__(self):
        self._revoked = {}   # {jti: revocation_timestamp}

    def revoke(self, token: str, engine: JWTTokenEngine, reason: str = "logout"):
        """Add token to revocation list using its unique JTI."""
        try:
            payload = engine.decode_without_verify(token)
            jti = payload.get("jti")
            username = payload.get("sub")
            if jti:
                self._revoked[jti] = {
                    "revoked_at" : datetime.now(timezone.utc).isoformat(),
                    "username"   : username,
                    "reason"     : reason
                }
                print(f"[REVOKED] Token JTI={jti[:8]}... for user '{username}' | Reason: {reason}")
                return True
        except Exception as e:
            print(f"[ERROR] Could not revoke token: {e}")
        return False

    def is_revoked(self, token: str, engine: JWTTokenEngine) -> bool:
        """Check if token has been revoked before accepting it."""
        try:
            payload = engine.decode_without_verify(token)
            jti = payload.get("jti")
            return jti in self._revoked
        except Exception:
            return True  # Treat unreadable tokens as revoked

    def list_revoked(self):
        """Display all revoked tokens (for audit/admin view)."""
        print(f"\n  Revoked tokens ({len(self._revoked)} total):")
        for jti, info in self._revoked.items():
            print(f"  JTI: {jti[:8]}... | User: {info['username']} | "
                  f"Reason: {info['reason']} | At: {info['revoked_at']}")


# ─────────────────────────────────────────────
# SECTION 3: SESSION STORE
# ─────────────────────────────────────────────

class SessionStore:
    """
    Tracks all active sessions per user.
    Supports concurrent session limiting and forced logout.
    """

    def __init__(self, max_sessions_per_user: int = 3):
        self.max_sessions = max_sessions_per_user
        self.sessions = {}   # {username: [session_info]}

    def create_session(self, username: str, access_token: str,
                       refresh_token: str, ip: str = "127.0.0.1") -> str:
        """Register a new session after successful login."""
        session_id = hashlib.sha256(
            f"{username}{time.time()}{ip}".encode()
        ).hexdigest()[:16]

        session = {
            "session_id"    : session_id,
            "access_token"  : access_token[:20] + "...",  # Partial — never store full
            "ip_address"    : ip,
            "created_at"    : datetime.now(timezone.utc).isoformat(),
            "last_active"   : datetime.now(timezone.utc).isoformat(),
            "user_agent"    : "Linux/OS-Auth-Framework"
        }

        if username not in self.sessions:
            self.sessions[username] = []

        # Enforce session limit — remove oldest if over limit
        if len(self.sessions[username]) >= self.max_sessions:
            removed = self.sessions[username].pop(0)
            print(f"[LIMIT] Max sessions reached. Removed oldest session: {removed['session_id']}")

        self.sessions[username].append(session)
        print(f"[SESSION] Created session {session_id} for '{username}' from {ip}")
        return session_id

    def get_active_sessions(self, username: str) -> list:
        return self.sessions.get(username, [])

    def terminate_session(self, username: str, session_id: str) -> bool:
        if username not in self.sessions:
            return False
        before = len(self.sessions[username])
        self.sessions[username] = [
            s for s in self.sessions[username]
            if s["session_id"] != session_id
        ]
        terminated = len(self.sessions[username]) < before
        if terminated:
            print(f"[SESSION] Terminated session {session_id} for '{username}'")
        return terminated

    def terminate_all(self, username: str):
        """Force logout from all devices — used after password reset."""
        count = len(self.sessions.get(username, []))
        self.sessions[username] = []
        print(f"[SESSION] Terminated all {count} session(s) for '{username}'")


# ─────────────────────────────────────────────
# SECTION 4: PRIVILEGE LEVEL VALIDATOR
# ─────────────────────────────────────────────

class PrivilegeLevelValidator:
    """
    Validates user privilege before granting access to OS resources.
    Defends against privilege escalation attacks.
    """

    ROLE_HIERARCHY = {
        "guest"  : 0,
        "user"   : 1,
        "sudo"   : 2,
        "admin"  : 3,
        "root"   : 4
    }

    def can_access(self, user_role: str, required_role: str) -> bool:
        user_level     = self.ROLE_HIERARCHY.get(user_role, -1)
        required_level = self.ROLE_HIERARCHY.get(required_role, 99)
        allowed = user_level >= required_level
        icon = "✓" if allowed else "✗"
        print(f"  [{icon}] Role '{user_role}' (level {user_level}) "
              f"accessing '{required_role}' resource (level {required_level}) "
              f"→ {'ALLOWED' if allowed else 'DENIED'}")
        return allowed


# ─────────────────────────────────────────────
# SECTION 5: MAIN DEMO — Run This to Test
# ─────────────────────────────────────────────

def run_session_demo():
    print("\n" + "="*60)
    print("  SECURE AUTH FRAMEWORK — MODULE 3: SESSION MANAGER")
    print("="*60)

    engine    = JWTTokenEngine()
    revoke_list = TokenRevocationList()
    store     = SessionStore(max_sessions_per_user=3)
    priv      = PrivilegeLevelValidator()

    username = "devops_student"

    # ── Test 1: Token issuance ──
    print("\n--- TEST 1: JWT Token Issuance ---")
    access_token  = engine.issue_access_token(username, role="user")
    refresh_token = engine.issue_refresh_token(username)
    print(f"  Access token  : {access_token[:40]}...")
    print(f"  Refresh token : {refresh_token[:40]}...")

    # ── Test 2: Token verification ──
    print("\n--- TEST 2: Token Verification ---")
    result = engine.verify_token(access_token)
    print(f"  Valid         : {result['valid']}")
    if result["valid"]:
        p = result["payload"]
        print(f"  User          : {p['sub']}")
        print(f"  Role          : {p['role']}")
        print(f"  Issuer        : {p['issuer']}")
        print(f"  Token type    : {p['type']}")
        exp = datetime.fromtimestamp(p['exp'], tz=timezone.utc)
        print(f"  Expires at    : {exp.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # ── Test 3: Tampered token ──
    print("\n--- TEST 3: Tampered Token Detection ---")
    tampered = access_token[:-5] + "XXXXX"
    result   = engine.verify_token(tampered)
    print(f"  Tampered token valid : {result['valid']}")
    print(f"  Error                : {result['error']}")

    # ── Test 4: Session management ──
    print("\n--- TEST 4: Session Management ---")
    sid1 = store.create_session(username, access_token, refresh_token, "192.168.1.10")
    sid2 = store.create_session(username, access_token, refresh_token, "10.0.0.5")
    active = store.get_active_sessions(username)
    print(f"  Active sessions : {len(active)}")
    store.terminate_session(username, sid1)
    print(f"  After terminate : {len(store.get_active_sessions(username))} session(s)")

    # ── Test 5: Token revocation ──
    print("\n--- TEST 5: Token Revocation (Logout) ---")
    revoke_list.revoke(access_token, engine, reason="user_logout")
    is_rev = revoke_list.is_revoked(access_token, engine)
    print(f"  Token revoked   : {is_rev}")
    revoke_list.list_revoked()

    # ── Test 6: Privilege escalation defense ──
    print("\n--- TEST 6: Privilege Escalation Defense ---")
    priv.can_access("user",  "user")
    priv.can_access("user",  "admin")   # ← Should be DENIED
    priv.can_access("admin", "admin")
    priv.can_access("guest", "root")    # ← Should be DENIED
    priv.can_access("root",  "root")

    # ── Test 7: Force logout all sessions ──
    print("\n--- TEST 7: Force Logout All Sessions ---")
    store.create_session(username, access_token, refresh_token, "172.16.0.1")
    store.terminate_all(username)
    print(f"  Sessions after force logout : {len(store.get_active_sessions(username))}")

    print("\n[DONE] Module 3 Session Manager Demo Complete.\n")


if __name__ == "__main__":
    run_session_demo()