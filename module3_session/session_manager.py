import jwt
from datetime import datetime, timedelta

class JWTTokenEngine:
    def __init__(self):
        self.secret = "secret"

    def issue_access_token(self, user, role):
        d = {
            "user": user,
            "role": role,
            "exp": datetime.utcnow() + timedelta(minutes=30)
        }
        return jwt.encode(d, self.secret, algorithm="HS256")

    def verify_token(self, token):
        try:
            return jwt.decode(
                token,
                self.secret,
                algorithms=["HS256"]
            )
        except:
            return "Invalid Token"

class SessionStore:
    def __init__(self):
        self.sessions = {}

    def add_session(self, user, token):
        self.sessions[user] = token

    def remove_session(self, user):
        if user in self.sessions:
            del self.sessions[user]

class PrivilegeLevelValidator:
    def __init__(self):
        self.roles = {
            "guest": 0,
            "user": 1,
            "admin": 2,
            "root": 3
        }

    def can_access(self, user_role, required_role):
        return self.roles.get(user_role, 0) >= self.roles.get(required_role, 0)