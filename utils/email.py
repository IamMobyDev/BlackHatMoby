import threading
import logging
from flask import render_template
from flask_mail import Message
from models import EmailLog, db

# Configure logging
logger = logging.getLogger("blackmoby")


def send_email_async(app, msg):
    """Send email asynchronously"""
    with app.app_context():
        try:
            # Import here to avoid circular import
            from extensions import mail

            mail.send(msg)
            logger.info(f"Email sent to {msg.recipients}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")


def send_email(subject, recipient, template, **kwargs):
    """Send an email using a template and log it"""
    try:
        # Import here to avoid circular imports
        from flask import current_app
        from extensions import mail

        msg = Message(subject, recipients=[recipient])
        msg.html = render_template(template, **kwargs)

        # Send email in background thread to avoid blocking
        threading.Thread(
            target=send_email_async, args=(current_app._get_current_object(), msg)
        ).start()

        # Log email in database if user_id is provided
        if "user_id" in kwargs:
            email_log = EmailLog(
                user_id=kwargs["user_id"],
                email_type=kwargs.get("email_type", "general"),
                subject=subject,
                recipient=recipient,
                status="sent",
            )
            db.session.add(email_log)
            db.session.commit()

        return True
    except Exception as e:
        logger.error(f"Email sending error: {str(e)}")

        # Log failed email if user_id is provided
        if "user_id" in kwargs:
            email_log = EmailLog(
                user_id=kwargs["user_id"],
                email_type=kwargs.get("email_type", "general"),
                subject=subject,
                recipient=recipient,
                status="failed",
            )
            db.session.add(email_log)
            db.session.commit()

        return False
