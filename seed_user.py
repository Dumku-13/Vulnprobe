# Run once to create admin user
# Usage: python seed_user.py
from auth import create_user

create_user("admin", "vulnprobe2025")
print("Admin user created.")
