# Create the first admin user.
# Usage: python seed_user.py            (prompts for a password)
#        VULNPROBE_ADMIN_PASSWORD=... python seed_user.py
import getpass
import os

from auth import create_user

password = os.environ.get("VULNPROBE_ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
if len(password) < 10:
    raise SystemExit("Use a password of at least 10 characters.")

create_user("admin", password)
print("Admin user created.")
