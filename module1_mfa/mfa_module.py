import pyotp
import time

class TOTPAuthenticator:
    def __init__(self, username):
        self.username = username
        self.secret = pyotp.random_base32()
        self.totp = pyotp.TOTP(self.secret)
        self.failed_attempts = 0
        self.locked_until = 0

    def generate_otp(self):
        return self.totp.now()

    def verify_otp(self, otp):
        if self.locked_until > time.time():
            print("Locked")
            return False

        if self.totp.verify(otp, valid_window=1):
            print("OTP Verified")
            self.failed_attempts = 0
            return True

        self.failed_attempts += 1
        print("Invalid OTP")

        if self.failed_attempts >= 3:
            self.locked_until = time.time() + 30
            self.failed_attempts = 0
            print("Account Locked")

        return False

class MFAAuditLogger:
    def log_event(self, user, event, success):
        print(f"[AUDIT] User: {user} | Event: {event} | Success: {success}")