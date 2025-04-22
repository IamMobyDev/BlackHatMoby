import os
import hmac
import hashlib
import uuid
import logging

# Setup payment logger
payment_logger = logging.getLogger("payment")

# Get Paystack secret key from environment
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")


def generate_verification_token():
    """Generate a unique verification token"""
    return str(uuid.uuid4())


def get_readable_amount(amount_cents):
    """Convert cents to a readable dollar amount string"""
    return f"${amount_cents/100:.2f}"


def verify_paystack_signature(payload, signature):
    """Verify Paystack webhook signature"""
    if not PAYSTACK_SECRET_KEY:
        payment_logger.error("Cannot verify Paystack signature: Secret key not configured")
        return False

    try:
        secret = PAYSTACK_SECRET_KEY.encode('utf-8')
        generated = hmac.new(secret, msg=payload, digestmod=hashlib.sha512).hexdigest()
        return hmac.compare_digest(generated, signature)
    except Exception as e:
        payment_logger.error(f"Signature verification error: {str(e)}")
        return False