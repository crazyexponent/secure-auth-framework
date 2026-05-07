"""
=============================================================
MODULE 2: Secure Password Manager
Project: Secure Authentication Framework for Operating Systems
=============================================================
"""

import bcrypt
import re
import hashlib
import os
import json
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# SECTION 1: PASSWORD POLICY ENFORCER
# ─────────────────────────────────────────────

class PasswordPolicyEnforcer:
    """
    Enforces enterprise-grade password complexity rules.
    Prevents weak passwords before they ever reach the database.
    """

    # Common weak passwords — in production, load from HaveIBeenPwned API
    WEAK_PASSWORDS = {
        "password", "123456", "password123", "admin", "letmein",
        "qwerty", "abc123", "monkey", "master", "dragon",
        "welcome", "login", "pass", "test", "guest"
    }

    def __init__(self):
        self.min_length = 8
        self.max_length = 128
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digit = True
        self.require_special = True

    def check_strength(self, password: str) -> dict:
        """
        Evaluates password against all policy rules.
        Returns detailed report with pass/fail for each rule.
        """
        results = {
            "password": "*" * len(password),  # Never log raw passwords
            "passed": True,
            "score": 0,
            "issues": [],
            "checks": {}
        }

        # Rule 1: Length
        length_ok = self.min_length <= len(password) <= self.max_length
        results["checks"]["length"] = length_ok
        if length_ok:
            results["score"] += 20
        else:
            results["issues"].append(f"Must be {self.min_length}–{self.max_length} characters")

        # Rule 2: Uppercase
        upper_ok = bool(re.search(r'[A-Z]', password)) if self.require_uppercase else True
        results["checks"]["uppercase"] = upper_ok
        if upper_ok:
            results["score"] += 20
        else:
            results["issues"].append("Must contain at least one uppercase letter")

        # Rule 3: Lowercase
        lower_ok = bool(re.search(r'[a-z]', password)) if self.require_lowercase else True
        results["checks"]["lowercase"] = lower_ok
        if lower_ok:
            results["score"] += 20
        else:
            results["issues"].append("Must contain at least one lowercase letter")

        # Rule 4: Digit
        digit_ok = bool(re.search(r'\d', password)) if self.require_digit else True
        results["checks"]["digit"] = digit_ok
        if digit_ok:
            results["score"] += 20
        else:
            results["issues"].append("Must contain at least one digit")

        # Rule 5: Special character
        special_ok = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        results["checks"]["special_char"] = special_ok
        if special_ok:
            results["score"] += 20
        else:
            results["issues"].append("Must contain at least one special character (!@#$...)")

        # Rule 6: Breach check (common passwords list)
        not_common = password.lower() not in self.WEAK_PASSWORDS
        results["checks"]["not_common"] = not_common
        if not not_common:
            results["issues"].append("Password is in known weak password list")
            results["score"] = max(0, results["score"] - 40)

        # Rule 7: No repeated characters (aaaa, 1111)
        no_repeat = not bool(re.search(r'(.)\1{3,}', password))
        results["checks"]["no_repeated_chars"] = no_repeat
        if not no_repeat:
            results["issues"].append("Avoid repeating the same character 4+ times")
            results["score"] = max(0, results["score"] - 10)

        results["passed"] = len(results["issues"]) == 0
        results["strength_label"] = (
            "Weak" if results["score"] < 40 else
            "Fair" if results["score"] < 60 else
            "Good" if results["score"] < 80 else
            "Strong"
        )

        return results


# ─────────────────────────────────────────────
# SECTION 2: BCRYPT HASH ENGINE
# ─────────────────────────────────────────────

class PasswordHashEngine:
    """
    Handles secure password hashing using bcrypt with adaptive cost factor.
    bcrypt is resistant to GPU brute-force attacks unlike MD5/SHA1.
    """

    def __init__(self, cost_factor: int = 12):
        """
        cost_factor (work factor): Controls hashing time.
        12 = ~250ms per hash — recommended for 2024 production systems.
        Higher = slower for attackers, but also for users.
        """
        self.cost_factor = cost_factor

    def hash_password(self, raw_password: str) -> str:
        """
        Hash password with bcrypt.
        Salt is automatically embedded in the output hash.
        Format: $2b$12$[22-char salt][31-char hash]
        """
        password_bytes = raw_password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=self.cost_factor)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')

    def verify_password(self, raw_password: str, stored_hash: str) -> bool:
        """
        Safely verify password against stored hash.
        Uses constant-time comparison to prevent timing attacks.
        """
        try:
            return bcrypt.checkpw(
                raw_password.encode('utf-8'),
                stored_hash.encode('utf-8')
            )
        except Exception as e:
            print(f"[ERROR] Hash verification failed: {e}")
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """Check if hash uses outdated cost factor and needs upgrading."""
        return bcrypt.checkpw(b"dummy", stored_hash.encode()) if False else \
               stored_hash.startswith(f"$2b${self.cost_factor}$") is False


# ─────────────────────────────────────────────
# SECTION 3: PASSWORD HISTORY TRACKER
# ─────────────────────────────────────────────

class PasswordHistoryTracker:
    """
    Prevents users from reusing recent passwords.
    Stores hashed history only — raw passwords never stored.
    """

    def __init__(self, history_limit: int = 5):
        self.history_limit = history_limit
        self.user_history = {}  # {username: [hashed_passwords]}

    def add_to_history(self, username: str, hashed_password: str):
        if username not in self.user_history:
            self.user_history[username] = []

        self.user_history[username].insert(0, hashed_password)

        # Keep only last N passwords
        self.user_history[username] = self.user_history[username][:self.history_limit]

    def is_reused(self, username: str, new_password: str) -> bool:
        """Returns True if new password matches any of last N passwords."""
        if username not in self.user_history:
            return False

        for old_hash in self.user_history[username]:
            if bcrypt.checkpw(new_password.encode(), old_hash.encode()):
                return True
        return False


# ─────────────────────────────────────────────
# SECTION 4: PASSWORD EXPIRY MANAGER
# ─────────────────────────────────────────────

class PasswordExpiryManager:
    """
    Enforces mandatory password rotation every N days.
    Critical for OS-level accounts and admin users.
    """

    def __init__(self, expiry_days: int = 90):
        self.expiry_days = expiry_days
        self.user_expiry = {}

    def set_password_date(self, username: str):
        self.user_expiry[username] = datetime.now()

    def is_expired(self, username: str) -> bool:
        if username not in self.user_expiry:
            return True  # No record = treat as expired
        expiry_date = self.user_expiry[username] + timedelta(days=self.expiry_days)
        return datetime.now() > expiry_date

    def days_until_expiry(self, username: str) -> int:
        if username not in self.user_expiry:
            return 0
        expiry_date = self.user_expiry[username] + timedelta(days=self.expiry_days)
        delta = expiry_date - datetime.now()
        return max(0, delta.days)


# ─────────────────────────────────────────────
# SECTION 5: MAIN DEMO — Run This to Test
# ─────────────────────────────────────────────

def run_password_demo():
    print("\n" + "="*60)
    print("  SECURE AUTH FRAMEWORK — MODULE 2: PASSWORD MANAGER")
    print("="*60)

    policy    = PasswordPolicyEnforcer()
    hasher    = PasswordHashEngine(cost_factor=12)
    history   = PasswordHistoryTracker(history_limit=3)
    expiry_mgr = PasswordExpiryManager(expiry_days=90)

    username = "devops_student"

    # ── Test 1: Weak password ──
    print("\n--- TEST 1: Weak Password Check ---")
    weak_pw = "password123"
    result = policy.check_strength(weak_pw)
    print(f"  Password : {weak_pw}")
    print(f"  Strength : {result['strength_label']} ({result['score']}/100)")
    print(f"  Passed   : {result['passed']}")
    for issue in result["issues"]:
        print(f"  ✗ {issue}")

    # ── Test 2: Strong password ──
    print("\n--- TEST 2: Strong Password Check ---")
    strong_pw = "SecureOS@2024!"
    result = policy.check_strength(strong_pw)
    print(f"  Password : {strong_pw}")
    print(f"  Strength : {result['strength_label']} ({result['score']}/100)")
    print(f"  Passed   : {result['passed']}")
    for check, passed in result["checks"].items():
        icon = "✓" if passed else "✗"
        print(f"  {icon} {check}")

    # ── Test 3: Hash & Verify ──
    print("\n--- TEST 3: bcrypt Hash & Verify ---")
    print(f"  Hashing password with cost factor {hasher.cost_factor}...")
    hashed = hasher.hash_password(strong_pw)
    print(f"  Hash     : {hashed}")
    verify_ok = hasher.verify_password(strong_pw, hashed)
    verify_bad = hasher.verify_password("WrongPassword!", hashed)
    print(f"  Correct password match : {verify_ok}")
    print(f"  Wrong password match   : {verify_bad}")

    # ── Test 4: History Check ──
    print("\n--- TEST 4: Password Reuse Prevention ---")
    history.add_to_history(username, hashed)
    expiry_mgr.set_password_date(username)

    reused = history.is_reused(username, strong_pw)
    print(f"  Reuse of last password : {reused}  ← should be True")

    new_pw = "FreshPass@9999!"
    new_hashed = hasher.hash_password(new_pw)
    reused_new = history.is_reused(username, new_pw)
    print(f"  New unique password    : {not reused_new}  ← should be True")

    # ── Test 5: Expiry ──
    print("\n--- TEST 5: Password Expiry Status ---")
    days_left = expiry_mgr.days_until_expiry(username)
    expired   = expiry_mgr.is_expired(username)
    print(f"  Days until expiry : {days_left}")
    print(f"  Is expired        : {expired}")

    print("\n[DONE] Module 2 Password Manager Demo Complete.\n")


if __name__ == "__main__":
    run_password_demo()