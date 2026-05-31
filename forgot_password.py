from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta, timezone
from db_connection import user_collection
from utils import pwd_context, create_otp, send_otp_email
from pydantic_model import (
    ForgetPasswordRequest,
    VerifyForgotOTP,
    ResetPasswordRequest
)

router = APIRouter()

@router.post("/forget-password")
def request_forget_password(data: ForgetPasswordRequest):
    user = user_collection.find_one({"email": data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = create_otp(length=6) # 6-digit OTP for password reset

    user_collection.update_one(
        {"email": data.email},
        {
            "$set": {
                "forgot_otp": otp,
                "forgot_otp_time": datetime.now(timezone.utc),
                "reset_verified": False
            }
        }
    )

    send_otp_email(data.email, otp)

    return {
        "status": "success",
        "message": "OTP sent successfully"
    }

@router.post("/verify-forgot-otp")
def verify_forgot_otp(data: VerifyForgotOTP):
    user = user_collection.find_one({"email": data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db_otp = user.get("forgot_otp")
    otp_time = user.get("forgot_otp_time")

    if not db_otp or not otp_time:
        raise HTTPException(status_code=400, detail="No OTP found. Please request a new OTP.")

    if db_otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Make sure otp_time is timezone aware before comparing
    if otp_time.tzinfo is None:
        otp_time = otp_time.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) - otp_time > timedelta(minutes=5):
        raise HTTPException(status_code=400, detail="OTP Expired")

    user_collection.update_one(
        {"email": data.email},
        {"$set": {"reset_verified": True}}
    )

    return {
        "status": "success",
        "message": "OTP verified successfully"
    }

@router.post("/reset-password") # Renamed to avoid duplicate route
def reset_password(data: ResetPasswordRequest):
    try:
        user_data = user_collection.find_one({"email": data.email})
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")
            
        if not user_data.get("reset_verified"):
            raise HTTPException(status_code=403, detail="OTP not verified. Cannot reset password.")
        
        new_hashed_pass = pwd_context.hash(data.new_password[:72])

        user_collection.update_one(
            {"email": data.email},
            {"$set": {
                "password": new_hashed_pass,
                "reset_verified": False, # Reset the flag for security
                "forgot_otp": None
            }}
        )

        return {
            "status": "success",
            "message": "Password reset successfully"
        }

    except Exception as e:
        print(f"ERROR: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")