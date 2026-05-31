from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta, timezone
import jwt

from db_connection import user_collection
from pydantic_model import RegisterValidate, LoginValidate, OtpValidate
from utils import create_otp, send_otp_email, pwd_context, SECRET_KEY, ALGORITHM

# Define the router
router = APIRouter(tags=["Authentication"])

# Setup templates for this router
templates = Jinja2Templates(directory="templates")

@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register_user(data: RegisterValidate):
    if user_collection.find_one({"email": data.email}):
          raise HTTPException(status_code=400, detail="Email Already Registered")
    
    hashed_pass = pwd_context.hash(data.password[:72])
    register_otp = create_otp(length=4)
    otp_generated_at = datetime.now(timezone.utc)
    
    new_user = {
        "user_name" : data.user_name,
        "email" : data.email,
        "password" : hashed_pass,
        "mobile_no" : data.mobile_no,
        "otp" : register_otp,
        "otp_generate": otp_generated_at,
        "is_verified" : False
    }

    inserted = user_collection.insert_one(new_user)
    if inserted:
        send_otp_email(data.email, register_otp)
    else:
        raise HTTPException(status_code=500, detail="Problem saving data")
    
    return {"message": "Registration successful. OTP sent to email"}

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
def login_user(data: LoginValidate):
    user_data = user_collection.find_one({"email": data.email})
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")
    
    if pwd_context.verify(data.password, user_data.get("password")):
        login_otp = create_otp(length=4)
        otp_generated_at = datetime.now(timezone.utc)

        send_otp_email(data.email, login_otp)

        user_collection.update_one(
            {"email": data.email},
            {"$set": {"otp": login_otp, "otp_generate": otp_generated_at}}
        )

        return {
            "status": "OTP sent",
            "message": "OTP sent to your email",
            "user_name": user_data["user_name"]
        }
    else:
        raise HTTPException(status_code=401, detail="Incorrect password, please try again")

@router.get("/otp", response_class=HTMLResponse)
def otp_page(request: Request):
    return templates.TemplateResponse("otp_verify.html", {"request": request})

@router.post('/otp')
def verify_otp(data: OtpValidate):
    user_data = user_collection.find_one({"email": data.email})
    
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    current_time = datetime.now(timezone.utc)
    generate_time = user_data.get("otp_generate")
    
    if generate_time and generate_time.tzinfo is None:
        generate_time = generate_time.replace(tzinfo=timezone.utc)

    if not generate_time or current_time - generate_time > timedelta(minutes=5):
        raise HTTPException(status_code=400, detail="OTP Expired. Please Resend It.")

    if user_data.get("otp") == data.otp:
        user_collection.update_one(
            {"email": data.email},
            {"$set": {"is_verified": True, "otp": None}}
        )

        payload = {
            "user_id": str(user_data["_id"]),
            "user_name": user_data["email"],
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "status": "success",
            "message": "OTP verified successfully",
            "token": token
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP")

@router.post("/resend-otp")
def resend_otp(data: dict):
    email = data.get("email")
    user = user_collection.find_one({"email": email})
    if not user:
          raise HTTPException(status_code=404, detail="User not found")    

    new_otp = create_otp(length=4)
    if send_otp_email(email, new_otp):
        user_collection.update_one(
            {"email": email}, 
            {"$set": {"otp": new_otp, "otp_generate": datetime.now(timezone.utc)}}
        )
        return {"status": "success", "message": "New OTP Sent To Your Mail"}    
    else:
        raise HTTPException(status_code=500, detail="Resend Failed")