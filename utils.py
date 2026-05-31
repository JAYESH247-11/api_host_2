import os
import random
import smtplib
from email.message import EmailMessage
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

# Centralized password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "your-fallback-secret-key")
ALGORITHM = 'HS256'

def create_otp(length=4):
    """Generates an OTP of specified length."""
    start = 10**(length - 1)
    end = (10**length) - 1
    return str(random.randint(start, end))

def send_otp_email(receive_mail: str, otp: str) -> bool:
    sender_email = os.getenv("EMAIL_ADDRESS")
    sender_password = os.getenv("EMAIL_PASSWORD")

    if not sender_email or not sender_password:
        print("Email credentials are not set in the environment.")
        return False

    message = EmailMessage()
    message['Subject'] = "Account Verification OTP"
    message['From'] = sender_email
    message['To'] = receive_mail
    message.set_content(f"Your verification OTP is: {otp}. Do not share it with anyone.")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(message)
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False
    