"""
=============================================================
MODULE 1: Multi-Factor Authentication (MFA)
Project: Secure Authentication Framework for Operating Systems
=============================================================
"""

import pyotp
import time
import hashlib
import os
from datetime import datetime

# ─────────────────────────────────────────────
# SECTION 1: TOTP (Time-Based One-Time Password)
# ─────────────────────────────────────────────

class TOTPAuthenticator:
    """
    Implements RFC 6238 compliant TOTP authentication.
    Compatible with Google Authenticator and Authy apps.
    """

    def __init__(self, username: str):
        self.username = username
        self.secret = pyotp.random_base32()   # Unique secret per user
        self.totp = pyotp.TOTP(self.secret)
        self.failed_attempts = 0
        self.max_attempts = 3
        self.lockout_until = 0

    def get_provisioning_uri(self) -> str:
        """Returns QR-compatible URI for authenticator apps."""
        return self.totp.provisioning_uri(
            name=self.username,
            issuer_name="SecureAuthOS"
        )

    def generate_otp(self) -> str:
        """Generate current TOTP (valid for 30 seconds)."""
        return self.totp.now()

    def is_locked_out(self) -> bool:
        """Check if user is in lockout period after failed attempts."""
        if self.lockout_until > time.time():
            remaining = int(self.lockout_until - time.time())
            print(f"[LOCKED] Account locked. Try again in {remaining} seconds.")
            return True
        return False

    def verify_otp(self, user_otp: str) -> bool:
        """
        Verify OTP with rate limiting and brute-force protection.
        Allows 1 window of clock drift (±30 seconds).
        """
        if self.is_locked_out():
            return False

        # Validate OTP with 1 interval tolerance for clock skew
        is_valid = self.totp.verify(user_otp, valid_window=1)

        if is_valid:
            print(f"[SUCCESS] OTP verified for user: {self.username}")
            self.failed_attempts = 0  # Reset on success
            return True
        else:
            self.failed_attempts += 1
            print(f"[FAILED] Invalid OTP. Attempt {self.failed_attempts}/{self.max_attempts}")

            if self.failed_attempts >= self.max_attempts:
                self.lockout_until = time.time() + 30  # 30-second lockout
                print(f"[SECURITY] Max attempts reached. Account locked for 30 seconds.")
                self.failed_attempts = 0

            return False


# ─────────────────────────────────────────────
# SECTION 2: BACKUP CODE GENERATOR
# ─────────────────────────────────────────────

class BackupCodeManager:
    """
    Generates and manages single-use backup codes.
    Used when the primary MFA device is unavailable.
    """

    def __init__(self):
        self.codes = {}

    def generate_backup_codes(self, username: str, count: int = 5) -> list:
        """Generate cryptographically secure backup codes."""
        codes = []
        for _ in range(count):
            raw = os.urandom(8)
            code = hashlib.sha256(raw).hexdigest()[:10].upper()
            formatted = f"{code[:5]}-{code[5:]}"
            codes.append(formatted)

        # Store hashed versions only (never store raw codes)
        self.codes[username] = [
            hashlib.sha256(c.encode()).hexdigest() for c in codes
        ]

        return codes  # Show to user ONCE only

    def use_backup_code(self, username: str, code: str) -> bool:
        """Validate and consume a backup code (one-time use)."""
        if username not in self.codes:
            print("[ERROR] No backup codes found for this user.")
            return False

        hashed_input = hashlib.sha256(code.encode()).hexdigest()

        if hashed_input in self.codes[username]:
            self.codes[username].remove(hashed_input)  # Consume it
            remaining = len(self.codes[username])
            print(f"[SUCCESS] Backup code accepted. {remaining} codes remaining.")
            return True
        else:
            print("[FAILED] Invalid backup code.")
            return False


# ─────────────────────────────────────────────
# SECTION 3: MFA AUDIT LOGGER
# ─────────────────────────────────────────────

class MFAAuditLogger:
    """
    Logs all authentication events for security auditing.
    In production, this would write to /var/log/auth.log
    """

    def __init__(self):
        self.logs = []

    def log_event(self, username: str, event_type: str, success: bool, ip: str = "127.0.0.1"):
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "event": event_type,
            "status": "SUCCESS" if success else "FAILURE",
            "ip_address": ip
        }
        self.logs.append(entry)
        status_icon = "✓" if success else "✗"
        print(f"[AUDIT {status_icon}] {entry['timestamp']} | {username} | {event_type} | {entry['status']} | IP: {ip}")

    def print_audit_report(self):
        print("\n" + "="*60)
        print("           MFA AUDIT REPORT")
        print("="*60)
        for log in self.logs:
            print(f"  {log['timestamp']}  |  {log['username']:<12}  |  {log['event']:<20}  |  {log['status']}")
        print("="*60)


# ─────────────────────────────────────────────
# SECTION 4: MAIN DEMO — Run This to Test
# ─────────────────────────────────────────────

def run_mfa_demo():
    print("\n" + "="*60)
    print("   SECURE AUTH FRAMEWORK — MODULE 1: MFA DEMO")
    print("="*60)

    logger = MFAAuditLogger()
    backup_mgr = BackupCodeManager()

    # --- Demo User ---
    username = "devops_student"
    auth = TOTPAuthenticator(username)

    print(f"\n[SETUP] Registering user: {username}")
    print(f"[INFO]  Secret Key   : {auth.secret}")
    print(f"[INFO]  Provisioning : {auth.get_provisioning_uri()}\n")

    # --- Test 1: Valid OTP ---
    print("--- TEST 1: Valid OTP Verification ---")
    valid_otp = auth.generate_otp()
    print(f"[SIM] Generated OTP: {valid_otp}")
    result = auth.verify_otp(valid_otp)
    logger.log_event(username, "TOTP_VERIFY", result)

    # --- Test 2: Invalid OTP ---
    print("\n--- TEST 2: Invalid OTP (Brute Force Simulation) ---")
    for i in range(3):
        result = auth.verify_otp("000000")
        logger.log_event(username, "TOTP_VERIFY", result)

    # --- Test 3: Backup Codes ---
    print("\n--- TEST 3: Backup Code Generation & Use ---")
    codes = backup_mgr.generate_backup_codes(username)
    print(f"[INFO] Your backup codes (save these!):")
    for i, code in enumerate(codes, 1):
        print(f"       {i}. {code}")

    result = backup_mgr.use_backup_code(username, codes[0])
    logger.log_event(username, "BACKUP_CODE_USE", result)

    result = backup_mgr.use_backup_code(username, codes[0])  # Reuse attempt
    logger.log_event(username, "BACKUP_CODE_REUSE", result)

    # --- Audit Report ---
    logger.print_audit_report()

    print("\n[DONE] Module 1 MFA Demo Complete.\n")


if __name__ == "__main__":
    run_mfa_demo()