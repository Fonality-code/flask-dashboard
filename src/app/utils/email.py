from flask import current_app

def send_email(to_email, subject, body):
    """Log email information instead of sending it"""
    current_app.logger.info(f"Sending email to: {to_email}")
    current_app.logger.info(f"Subject: {subject}")
    current_app.logger.info(f"Body: {body}")
    return True
