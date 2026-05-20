from module1_mfa.mfa_module import TOTPAuthenticator, MFAAuditLogger
from module2_password.password_manager import PasswordHashEngine, PasswordPolicyEnforcer
from module3_session.session_manager import (
    JWTTokenEngine,
    SessionStore,
    PrivilegeLevelValidator
)

def run_framework_demo():
    print("\n" + "="*60)
    print("      SECURE AUTHENTICATION FRAMEWORK: FULL SYSTEM DEMO")
    print("="*60)

    logger = MFAAuditLogger()
    hasher = PasswordHashEngine()
    policy = PasswordPolicyEnforcer()

    session_engine = JWTTokenEngine()
    session_store = SessionStore()

    priv_val = PrivilegeLevelValidator()

    user = "lpu_student"
    real_password = "SecureOS@2026!"

    print(f"\n[PHASE 1] Registering User: {user}")

    if policy.check_strength(real_password)['passed']:

        hashed_pw = hasher.hash_password(real_password)

        auth = TOTPAuthenticator(user)

        print("✓ Password Policy Passed & Hashed with bcrypt")
        print(f"✓ MFA Secret Generated: {auth.secret}")

    print(f"\n[PHASE 2] Login Attempt")

    if hasher.verify_password(real_password, hashed_pw):

        print("✓ Password Verified. Challenging MFA...")

        otp = auth.generate_otp()

        if auth.verify_otp(otp):

            print("✓ MFA Verified.")

            print(f"\n[PHASE 3] Issuing Session Token")

            token = session_engine.issue_access_token(
                user,
                role="user"
            )

            print(f"✓ JWT Token Issued: {token[:30]}...")

            print(f"\n[PHASE 4] Security Defense")

            is_allowed = priv_val.can_access(
                user_role="user",
                required_role="root"
            )

            if not is_allowed:

                print("🚨 [BLOCKED] Privilege Escalation detected.")

                logger.log_event(
                    user,
                    "PRIVILEGE_ESCALATION_ATTACK",
                    False
                )

    print("\n" + "="*60)
    print("                SYSTEM AUDIT COMPLETE")
    print("="*60)

if __name__ == "__main__":
    run_framework_demo()