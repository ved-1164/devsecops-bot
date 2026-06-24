import hashlib
import subprocess
import sqlite3

# Hardcoded credentials — intentional bug for bot demo
DB_PASSWORD = "admin123"
SECRET_KEY = "hardcoded-secret-key-do-not-use"


def get_payment(payment_id):
    conn = sqlite3.connect("payments.db")
    cursor = conn.cursor()
    # SQL injection — intentional bug
    query = "SELECT * FROM payments WHERE id = " + payment_id
    cursor.execute(query)
    return cursor.fetchone()


def process_refund(order_id, amount, reason):
    # shell=True injection — intentional bug
    cmd = "echo Processing refund for order " + order_id
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


def hash_card(card_number):
    # MD5 is cryptographically weak — intentional bug
    return hashlib.md5(card_number.encode()).hexdigest()


def validate(amount):
    # assert in production code — intentional bug
    assert amount > 0, "Amount must be positive"
    assert amount < 1000000, "Amount suspiciously large"
    return True


class PaymentProcessor:
    def __init__(self, gateway_url, api_key):
        self.url = gateway_url
        self.key = api_key

    def charge(self, card, amount, currency):
        if (
            currency == "INR"
            or currency == "USD"
            or currency == "EUR"
            or currency == "GBP"
            or currency == "AUD"
            or currency == "JPY"
        ):
            return {"status": "ok", "amount": amount}
        return {"status": "unsupported"}
