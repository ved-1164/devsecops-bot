# sample_app/app.py
# This file intentionally contains issues for the DevSecOps bot to detect.
# DO NOT use this in production.

import sys  # noqa: F401  (unused import — bandit/autoflake will catch this)
import subprocess
import sqlite3


PASSWORD = "super_secret_123"  # B105 — hardcoded password


def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # B608 — SQL injection via string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def run_command(user_input):
    # B602 — shell injection via subprocess with shell=True
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout


def assert_positive(value):
    # B101 — assert used (can be disabled with -O flag)
    assert value > 0, "Value must be positive"
    return value


def long_function_that_violates_line_length_limit(
    parameter_one, parameter_two, parameter_three
):
    # E501 — line too long
    combined_result = (
        str(parameter_one)
        + " "
        + str(parameter_two)
        + " "
        + str(parameter_three)
        + " extra stuff here"
    )
    return combined_result


def duplicate_block_one(data):
    results = []
    for item in data:
        if item > 0:
            results.append(item * 2)
        else:
            results.append(0)
    return results


def duplicate_block_two(data):
    results = []
    for item in data:
        if item > 0:
            results.append(item * 2)
        else:
            results.append(0)
    return results


def read_file(path):
    # B603 — subprocess without shell, but still an issue if path is user-controlled
    with open(path) as f:
        return f.read()


class UserManager:
    def __init__(self):
        self.users = {}

    def add_user(self, name, email):  # E231 missing whitespace after ','
        self.users[name] = email  # E225 missing whitespace around operator

    def get_user(self, name):
        return self.users.get(name)
