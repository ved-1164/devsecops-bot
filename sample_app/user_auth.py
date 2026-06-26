import subprocess
import sqlite3
import hashlib

# Hardcoded admin credentials — intentional bug
ADMIN_PASSWORD = "admin@123"
JWT_SECRET = "supersecret-jwt-key"


def login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection — intentional bug
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    cursor.execute(query)
    return cursor.fetchone()


def reset_password(username):
    # shell=True — intentional bug
    cmd = "echo Password reset for " + username
    subprocess.run(cmd, shell=True)


def hash_password(password):
    # MD5 is weak — intentional bug
    return hashlib.md5(password.encode()).hexdigest()


def validate_age(age):
    # assert in production — intentional bug
    assert age >= 18, "Must be 18 or older"
    return True
