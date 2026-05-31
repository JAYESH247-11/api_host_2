from pydantic import BaseModel, Field, EmailStr

class RegisterValidate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    user_name: str = Field(..., min_length=3, max_length=50)
    mobile_no: str = Field(..., min_length=10, max_length=10) 

class LoginValidate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)

class ForgetPasswordRequest(BaseModel):
    email: EmailStr

class VerifyForgotOTP(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6)

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str = Field(..., min_length=6)

class OtpValidate(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=4)