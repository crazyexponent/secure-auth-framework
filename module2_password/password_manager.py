import bcrypt
import re
from datetime import datetime, timedelta

class PasswordPolicyEnforcer:
    def check_strength(self, password):
        if len(password) < 8:
            return {'passed': False, 'msg': 'Too short'}
        if not re.search(r'[A-Z]', password):
            return {'passed': False, 'msg': 'No uppercase'}
        if not re.search(r'[a-z]', password):
            return {'passed': False, 'msg': 'No lowercase'}
        if not re.search(r'\d', password):
            return {'passed': False, 'msg': 'No number'}
        if not re.search(r'[!@#$%^&*]', password):
            return {'passed': False, 'msg': 'No special character'}
        return {'passed': True, 'msg': 'Strong'}

class PasswordHashEngine:
    def __init__(self, cost_factor=12):
        self.cost_factor = cost_factor

    def hash_password(self, password):
        return bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt(self.cost_factor)
        ).decode()

    def verify_password(self, password, hashed):
        return bcrypt.checkpw(
            password.encode(),
            hashed.encode()
        )