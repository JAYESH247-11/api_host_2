from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import jwt

from db_connection import user_collection
from utils import SECRET_KEY, ALGORITHM

# Import your routers
from auth import router as auth_router
from forgot_password import router as forgot_router

app = FastAPI()

# Include the routers here
app.include_router(auth_router)
app.include_router(forgot_router)

security = HTTPBearer()
templates = Jinja2Templates(directory="templates")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired!")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token!")


# ----------------- REMAINING ROUTES -----------------

@app.get("/success", response_class=HTMLResponse)
def success_page(request: Request):
    return templates.TemplateResponse("success.html", {"request": request})

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.get("/dashbord", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashbord.html", {"request": request})
    
@app.get("/profile")
def get_profile(token_data: dict = Depends(verify_token)):
    email = token_data.get("user_name")
    user = user_collection.find_one(
        {"email": email},
        {"_id": 0, "user_name": 1, "email": 1, "mobile_no": 1}
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"status": "success", "data": user}

@app.get("/users")
def get_users(token_data: dict = Depends(verify_token)):    
    projection = {"user_name": 1, "email": 1, "mobile_no": 1, "_id": 0}
    users = list(user_collection.find({}, projection))
    
    if not users:
        return {"status": "error", "message": "No users found"}
        
    return {
        "status": "success", 
        "requested_by": token_data.get("user_name"),
        "data": users
    }