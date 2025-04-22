from flask import (
    Blueprint,
    redirect,
    url_for,
    request,
    session,
    flash,
    jsonify,
    render_template,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
import json
import time
import hmac
import hashlib
import requests
import re
import logging
import os
from datetime import datetime, timedelta

from models import User, Payment, PaymentPlan, UserLog
from utils.decorators import login_required
from utils.email import send_email
from extensions import db, limiter

# Setup payment logger
payment_logger = logging.getLogger("payment")

# Paystack configuration
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")

# Initialize blueprint
payment_bp = Blueprint("payment", __name__)


def get_readable_amount(amount_cents):
    """Convert cents to a readable dollar amount string"""
    return f"${amount_cents/100:.2f}"


def verify_paystack_signature(payload, signature):
    """Verify Paystack webhook signature"""
    if not PAYSTACK_SECRET_KEY:
        payment_logger.error(
            "Cannot verify Paystack signature: Secret key not configured"
        )
        return False

    try:
        secret = PAYSTACK_SECRET_KEY.encode("utf-8")
        generated = hmac.new(secret, msg=payload, digestmod=hashlib.sha512).hexdigest()
        return hmac.compare_digest(generated, signature)
    except Exception as e:
        payment_logger.error(f"Signature verification error: {str(e)}")
        return False


@payment_bp.route("/pricing")
@login_required
def pricing():
    """Pricing page - user must be logged in to see this"""
    user = User.query.get(session["user_id"])
    plans = (
        PaymentPlan.query.filter_by(is_active=True)
        .order_by(PaymentPlan.price_usd)
        .all()
    )

    msg = request.args.get("msg")
    error = request.args.get("error")

    return render_template("pricing.html", user=user, plans=plans, msg=msg, error=error)


@payment_bp.route("/activate-trial")
@login_required
def activate_trial():
    """Activate a free trial subscription"""
    user = User.query.get(session["user_id"])

    # Check if user already has an active subscription
    if user.has_active_subscription():
        return redirect(url_for("modules.index"))

    # Check if user already used their trial
    if UserLog.query.filter_by(user_id=user.id, action="activated trial").first():
        flash("You have already used your free trial", "error")
        return redirect(url_for("payment.pricing"))

    # Get trial plan
    trial_plan = PaymentPlan.query.filter_by(slug="trial").first()
    if not trial_plan:
        flash("Trial plan not available", "error")
        return redirect(url_for("payment.pricing"))

    # Activate trial
    now = datetime.utcnow()
    user.subscription_status = "trial"
    user.subscription_type = "trial"
    user.subscription_start = now
    user.subscription_end = now + timedelta(days=trial_plan.duration_days)

    # Log the action
    db.session.add(UserLog(user_id=user.id, action="activated trial"))
    db.session.commit()

    # Send confirmation email
    send_email(
        subject="Your Free Trial Has Started",
        recipient=user.email,
        template="emails/trial_activated.html",
        user_id=user.id,
        email_type="trial_activation",
        username=user.username,
        trial_end=user.subscription_end,
    )

    flash("Your free trial has been activated!", "success")
    return redirect(url_for("modules.index"))


@payment_bp.route("/initiate-payment/<plan_slug>")
@login_required
@limiter.limit("5 per minute")
def initiate_payment(plan_slug):
    """Initiate a payment for a subscription plan"""
    user = User.query.get(session["user_id"])

    # Find the plan
    plan = PaymentPlan.query.filter_by(slug=plan_slug, is_active=True).first()
    if not plan:
        flash("Invalid plan selected", "error")
        return redirect(url_for("payment.pricing"))

    # Don't allow initiating payment for free trial
    if plan.slug == "trial":
        return redirect(url_for("payment.activate_trial"))

    # Create a unique reference
    reference = f"pay_{user.id}_{int(time.time())}"

    # Store the payment attempt
    payment = Payment(
        user_id=user.id,
        plan_id=plan.id,
        reference=reference,
        amount=plan.price_usd,
        status="pending",
        ip_address=request.remote_addr,
    )

    db.session.add(payment)
    db.session.add(
        UserLog(user_id=user.id, action=f"initiated {plan.slug} payment ({reference})")
    )
    db.session.commit()

    payment_logger.info(
        f"Payment initiated: {reference} for user {user.id}, plan: {plan.slug}"
    )

    # Render payment page with Paystack integration
    return render_template(
        "payment.html",
        user=user,
        plan=plan,
        reference=reference,
        paystack_public_key=PAYSTACK_PUBLIC_KEY,
        amount_usd=get_readable_amount(plan.price_usd),
    )


@payment_bp.route("/verify-payment/<reference>", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def verify_payment(reference):
    """Verify a payment with Paystack"""
    user = User.query.get(session["user_id"])

    # Validate the reference format
    if not re.match(r"^pay_\d+_\d+$", reference):
        payment_logger.warning(f"Invalid reference format: {reference}")
        return redirect(url_for("payment.pricing", error="Invalid payment reference"))

    # Get payment record
    payment = Payment.query.filter_by(reference=reference).first()
    if not payment:
        payment_logger.warning(f"Payment not found: {reference}")
        return redirect(url_for("payment.pricing", error="Payment not found"))

    # Verify payment belongs to current user
    if payment.user_id != user.id:
        payment_logger.warning(
            f"User {user.id} attempted to verify payment of user {payment.user_id}"
        )
        return redirect(
            url_for("payment.pricing", error="Unauthorized payment verification")
        )

    # Check if payment already verified
    if payment.status == "completed":
        return redirect(url_for("payment.payment_success", reference=reference))

    # Track verification attempt
    payment.retries += 1
    verification_log = f"{datetime.utcnow()}: Verification attempt #{payment.retries}\n"

    # Verify with Paystack API
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers,
            timeout=10,
        )

        verification_log += f"API Response code: {response.status_code}\n"

        if response.status_code == 200:
            response_data = response.json()
            verification_log += f"Response data: {json.dumps(response_data)[:500]}...\n"

            if response_data["data"]["status"] == "success":
                # Get the plan
                plan = PaymentPlan.query.get(payment.plan_id)
                if not plan:
                    payment_logger.error(f"Plan not found for payment: {reference}")
                    return redirect(url_for("payment.pricing", error="Plan not found"))

                try:
                    # Begin transaction
                    db.session.begin()

                    # Update payment status
                    payment.status = "completed"
                    payment.transaction_id = response_data["data"]["id"]
                    payment.verification_logs = (
                        payment.verification_logs or ""
                    ) + verification_log

                    # Update user subscription
                    now = datetime.utcnow()
                    user.subscription_status = "active"
                    user.subscription_type = plan.slug
                    user.subscription_start = now

                    # Set subscription end date based on plan duration
                    if plan.duration_days:
                        user.subscription_end = now + timedelta(days=plan.duration_days)
                    else:
                        # For lifetime plans
                        user.subscription_end = None

                    # Log the action
                    db.session.add(
                        UserLog(
                            user_id=user.id,
                            action=f"completed {plan.slug} payment ({reference})",
                        )
                    )
                    db.session.commit()

                    # Send confirmation email
                    send_email(
                        subject="Payment Successful - Subscription Activated",
                        recipient=user.email,
                        template="emails/payment_success.html",
                        user_id=user.id,
                        email_type="payment_success",
                        username=user.username,
                        plan_name=plan.name,
                        subscription_end=user.subscription_end,
                    )

                    payment_logger.info(
                        f"Payment verified successfully: {reference} for user {user.id}"
                    )
                    return redirect(
                        url_for("payment.payment_success", reference=reference)
                    )
                except Exception as e:
                    # Roll back the transaction
                    db.session.rollback()
                    verification_log += (
                        f"Exception during payment processing: {str(e)}\n"
                    )
                    payment.verification_logs = (
                        payment.verification_logs or ""
                    ) + verification_log
                    db.session.commit()
                    payment_logger.error(
                        f"Exception during payment processing for {reference}: {str(e)}"
                    )
                    return redirect(
                        url_for(
                            "payment.pricing",
                            error="Payment processing error. Please try again or contact support",
                        )
                    )

            else:
                verification_log += "Payment was not successful at Paystack\n"
                payment.verification_logs = (
                    payment.verification_logs or ""
                ) + verification_log
                db.session.commit()
                payment_logger.warning(
                    f"Payment not successful for {reference}, Paystack status: {response_data['data']['status']}"
                )
                return redirect(
                    url_for(
                        "payment.pricing",
                        error="Payment not successful. Please try again or contact support",
                    )
                )

        elif response.status_code == 404:
            verification_log += "Transaction was not found at Paystack\n"
            payment.verification_logs = (
                payment.verification_logs or ""
            ) + verification_log
            db.session.commit()
            payment_logger.warning(f"Payment not found at Paystack: {reference}")
            return redirect(
                url_for(
                    "payment.pricing",
                    error="Payment not found. Please try again or contact support",
                )
            )

        else:
            verification_log += (
                f"Unexpected response from Paystack: {response.text[:300]}...\n"
            )
            payment.verification_logs = (
                payment.verification_logs or ""
            ) + verification_log
            db.session.commit()
            payment_logger.error(
                f"Unexpected response from Paystack for {reference}: {response.status_code} - {response.text[:300]}"
            )
            return redirect(
                url_for(
                    "payment.pricing",
                    error="Payment verification error. Please try again or contact support",
                )
            )

    except Exception as e:
        verification_log += f"Exception during verification: {str(e)}\n"
        payment.verification_logs = (payment.verification_logs or "") + verification_log
        db.session.commit()
        payment_logger.error(
            f"Exception during payment verification for {reference}: {str(e)}"
        )
        return redirect(
            url_for(
                "payment.pricing",
                error="Payment verification error. Please try again or contact support",
            )
        )


@payment_bp.route("/payment-success/<reference>")
@login_required
def payment_success(reference):
    """Payment success page"""
    user = User.query.get(session["user_id"])
    payment = Payment.query.filter_by(reference=reference, user_id=user.id).first()

    if not payment or payment.status != "completed":
        return redirect(url_for("payment.pricing"))

    plan = PaymentPlan.query.get(payment.plan_id)

    return render_template(
        "payment_success.html", user=user, payment=payment, plan=plan
    )


@payment_bp.route("/payment-webhook", methods=["POST"])
def payment_webhook():
    """Webhook for payment notifications from Paystack"""
    # Verify the signature
    signature = request.headers.get("X-Paystack-Signature")
    if not signature:
        payment_logger.warning("Webhook called without signature")
        return jsonify(status="error"), 400

    payload = request.data
    if not verify_paystack_signature(payload, signature):
        payment_logger.warning("Invalid webhook signature")
        return jsonify(status="error"), 400

    # Parse the webhook data
    try:
        event_data = json.loads(payload)
        event = event_data.get("event")
        data = event_data.get("data", {})
        reference = data.get("reference")

        payment_logger.info(f"Webhook received: {event} for reference {reference}")

        # Handle different webhook events
        if event == "charge.success":
            # Find payment in database
            payment = Payment.query.filter_by(reference=reference).first()
            if not payment:
                payment_logger.warning(f"Payment not found for webhook: {reference}")
                return jsonify(status="error"), 404

            # Update payment status
            payment.status = "completed"
            payment.transaction_id = data.get("id")

            # Get user and plan
            user = User.query.get(payment.user_id)
            plan = PaymentPlan.query.get(payment.plan_id)

            if user and plan:
                # Update user subscription
                now = datetime.utcnow()
                user.subscription_status = "active"
                user.subscription_type = plan.slug
                user.subscription_start = now

                # Set subscription end date based on plan duration
                if plan.duration_days:
                    user.subscription_end = now + timedelta(days=plan.duration_days)
                else:
                    # For lifetime plans
                    user.subscription_end = None

                # Log the action
                db.session.add(
                    UserLog(
                        user_id=user.id,
                        action=f"webhook activated {plan.slug} subscription",
                    )
                )
                db.session.commit()

                # Send email notification
                send_email(
                    subject="Payment Confirmed - Subscription Activated",
                    recipient=user.email,
                    template="emails/payment_webhook_confirmed.html",
                    user_id=user.id,
                    email_type="payment_webhook",
                    username=user.username,
                    plan_name=plan.name,
                    subscription_end=user.subscription_end,
                )

                payment_logger.info(f"Webhook processed successfully: {reference}")
                return jsonify(status="success"), 200
            else:
                payment_logger.error(f"User or plan not found for webhook: {reference}")
                return jsonify(status="error"), 404

        # Add other webhook events as needed

        # Default response for unhandled events
        return jsonify(status="success"), 200

    except Exception as e:
        payment_logger.error(f"Error processing webhook: {str(e)}")
        return jsonify(status="error"), 500


@payment_bp.route("/get-csrf-token")
def get_csrf_token():
    """Get CSRF token for AJAX requests"""
    if "user_id" not in session:
        return jsonify(error="Not authenticated"), 401

    return jsonify(csrf_token=generate_csrf())