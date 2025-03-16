from flask import current_app
def send_sms(phone_number, message):
    current_app.logger.info(f"Sending SMS to {phone_number}: {message}")
