from fastapi import FastAPI, Form, Depends, HTTPException, Request, Path                        # type: ignore
from fastapi.templating import Jinja2Templates                                                  # type: ignore
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse                      # type: ignore
from sqlalchemy.orm import Session                                                              # type: ignore
from passlib.context import CryptContext                                                        # type: ignore
from dotenv import load_dotenv
from openai import OpenAI
import os
from db import get_db, SessionLocal, engine
from models import User, Itinerary
from typing import List
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm                    # type: ignore
import jwt                                                                                      # type: ignore

# Load environment variables
load_dotenv()

# OpenAI API Key Configuration
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OpenAI API Key")

client = OpenAI(api_key=api_key)

# Initialize FastAPI application
app = FastAPI()

# Set up Jinja2 templates for HTML rendering
templates = Jinja2Templates(directory="templates")

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Ensure database tables are created at startup
User.metadata.create_all(bind=engine)
Itinerary.metadata.create_all(bind=engine)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expires in 1 hour

# OAuth2 scheme for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Simulated token blacklist (for handling logout)
blacklisted_tokens = set()
    
# Pydantic models for request validation
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
 
class UserUpdate(BaseModel):
    username: str | None = None
    email: EmailStr | None = None
    password: str | None = None
    
# ======================== Utility Functions ======================== #

def get_password_hash(password: str) -> str:
    """Hash the user's password."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify the password against its hashed version."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)) -> str:
    """Generate a JWT access token with an expiration time."""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_access_token(token: str):
    """Decode JWT token and validate its authenticity."""
    try:
        if token in blacklisted_tokens:
            raise HTTPException(status_code=401, detail="Token is invalid (logged out)")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ======================== Routes ======================== #

@app.get("/TravelPlanner", response_class=HTMLResponse)
async def home(request: Request):
    """Render the homepage."""
    return templates.TemplateResponse("index.html", {"request": request})


# ========== 🚀 User Registration ========== #
@app.post("/register")
def register_user(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Register a new user with a username, email, and hashed password."""
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User registered successfully"}


# ========== 🔑 User Login (JWT Token) ========== #
@app.post("/login")
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and generate a JWT token."""
    user = db.query(User).filter(User.email == form_data.username).first()
         
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


# ========== 🔍 Get Current User from JWT ========== #
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Extract user information from JWT token."""
    payload = verify_access_token(token)
    user_email = payload.get("sub")
    
    if user_email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.email == user_email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


# ========== ✈️ Generate Itinerary ========== #
@app.post("/generate-itinerary")
async def generate_itinerary(
    destination: str = Form(...),
    interests: str = Form(...),
    start_date: str = Form(...),
    end_date: str = Form(...),
    budget: float = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)  # 🔒 Require authentication
):
    """Generate a travel itinerary based on user preferences."""
    
    prompt = f"""
    Create a travel itinerary for {destination} from {start_date} to {end_date} based on these interests: {interests}.
    The budget is {budget}. Suggest attractions, activities, and dining options for each day.
    """
    
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful travel assistant."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=250,
        temperature=0.5
    )

    generated_itinerary = response.choices[0].message.content

    itinerary = Itinerary(
        destination=destination, 
        interests=interests, 
        start_date=start_date, 
        end_date=end_date, 
        budget=budget, 
        generated_itinerary=generated_itinerary, 
        user_id=current_user.id  # 🔐 Link itinerary to user
    )
    
    db.add(itinerary)
    db.commit()
    db.refresh(itinerary)
    
    return {"itinerary": generated_itinerary, "user": current_user.email}


# ========== 🚪 User Logout (Token Blacklist) ========== #
@app.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme)):
    """Invalidate JWT token by adding it to the blacklist."""
    blacklisted_tokens.add(token)
    return {"message": "Successfully logged out"}


# ======================== User Management Routes ======================== #

@app.get("/users", response_model=List[UserCreate])
async def get_all_users(db: Session = Depends(get_db)):
    """Retrieve all registered users."""
    return db.query(User).all()

@app.get("/users/{user_id}", response_model=UserCreate)
async def get_user(user_id: int = Path(..., gt=0), db: Session = Depends(get_db)):
    """Retrieve a specific user by ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}")
async def update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)):
    """Update user details."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.username:
        db_user.username = user.username
    if user.email:
        db_user.email = user.email
    if user.password:
        db_user.password = get_password_hash(user.password)

    db.commit()
    db.refresh(db_user)
    
    return {"message": "User updated successfully", "user": db_user}

@app.delete("/users/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Delete a user account."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    
    return {"message": "User deleted successfully"}