"""
auth.py — VulnProbe authentication helpers

bcrypt-based password hashing/verification. Credentials are stored in SQLite
(see db.py); these helpers keep the original signatures so app.py and
seed_user.py work unchanged after the users.json → SQLite migration.
"""

import bcrypt

import db

# Ensure the schema exists (and users.json is migrated) on import.
db.init_db()


def load_users() -> dict:
    """Return all users as {username: {password_hash, role}}."""
    return db.all_users()


def verify_password(username: str, password: str) -> bool:
    """Check a plaintext password against the stored bcrypt hash."""
    user = db.get_user(username)
    if not user:
        return False
    stored_hash = user["password_hash"] or ""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        return False


def create_user(username: str, password: str, role: str = "admin") -> None:
    """Hash *password* with bcrypt and store/overwrite the user in SQLite."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db.add_user(username, hashed, role)
