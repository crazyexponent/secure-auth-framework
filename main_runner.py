from module1_mfa.mfa_module import TOTPAuthenticator, MFAAuditLogger
from module2_password.password_manager import PasswordHashEngine, PasswordPolicyEnforcer
from module3_session.session_manager import SessionManager, PrivilegeValidator

def run_framework_demo():
    print("\n" + "="*60)
    print("      SECURE AUTHENTICATION FRAMEWORK: FULL SYSTEM DEMO")
    print("="*60)

    # Initialize Modules
    logger = MFAAuditLogger()
    hasher = PasswordHashEngine()
    policy = PasswordPolicyEnforcer()
    session_mgr = SessionManager(secret_key="SUPER_SECRET_OS_KEY")
    priv_val = PrivilegeValidator()

    user = "lpu_student"
    real_password = "SecureOS@2026!"
    
    # --- STEP 1: Registration Simulation ---
    print(f"\n[PHASE 1] Registering User: {user}")
    if policy.check_strength(real_password)['passed']:
        hashed_pw = hasher.hash_password(real_password)
        auth = TOTPAuthenticator(user)
        print("✓ Password Policy Passed & Hashed with bcrypt")
        print(f"✓ MFA Secret Generated: {auth.secret}")

    # --- STEP 2: Login & MFA Challenge ---
    print(f"\n[PHASE 2] Login Attempt")
    # Simulate user entering password
    if hasher.verify_password(real_password, hashed_pw):
        print("✓ Password Verified. Challenging MFA...")
        otp = auth.generate_otp()
        if auth.verify_otp(otp):
            print("✓ MFA Verified.")
            
            # --- STEP 3: Session & Privileges ---
            print(f"\n[PHASE 3] Issuing Session Token")
            token = session_mgr.create_session(user, role="user")
            print(f"✓ JWT Token Issued: {token[:30]}...")

            # --- STEP 4: Defense Demo (Privilege Escalation) ---
            print(f"\n[PHASE 4] Security Defense: Accessing Root Resources")
            # User role = 1, Root required = 4
            is_allowed = priv_val.check_access(user_role="user", required_role="root")
            if not is_allowed:
                print("🚨 [BLOCKED] Privilege Escalation attempt detected and denied.")
                logger.log_event(user, "PRIVILEGE_ESCALATION_ATTACK", False)

    print("\n" + "="*60)
    print("                SYSTEM AUDIT COMPLETE")
    print("="*60)

if __name__ == "__main__":
    run_framework_demo()