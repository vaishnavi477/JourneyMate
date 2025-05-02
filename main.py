from fastapi import FastAPI, Form, Depends, HTTPException, Request, Path                        # type: ignore
from fastapi.templating import Jinja2Templates                                                  # type: ignore
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse                      # type: ignore
from sqlalchemy.orm import Session                                                              # type: ignore
from passlib.context import CryptContext                                                        # type: ignore
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles                                                     # type: ignore
from openai import OpenAI
from datetime import datetime, timedelta
import os, time, pytz
from db import get_db, SessionLocal, engine
from models import User, Itinerary
from typing import List
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm                    # type: ignore
import jwt , requests                                                                           # type: ignore

# Load environment variables
load_dotenv()

# OpenAI API Key Configuration
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("Missing OpenAI API Key")

client = OpenAI(api_key=api_key)

openweather_api_key = os.getenv("OPENWEATHER_API_KEY")
if not openweather_api_key:
    raise ValueError("Missing OpenWeather API Key")

timezone_api_key = os.getenv("GOOGLE_TIMEZONE_API")
if not timezone_api_key:
    raise ValueError("Missing Google TimeZone API Key")

# Initialize FastAPI application
app = FastAPI()

# Mount the static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

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
    
def get_weather_forecast_for_range(city: str, start_date: datetime, end_date: datetime):
    """Fetch weather forecast for a given city between the start and end date."""
    url = f"http://api.openweathermap.org/data/2.5/forecast?q={city}&units=metric&appid={openweather_api_key}"

    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Could not fetch weather data")
    
    data = response.json()
    
    # Filter the forecast data based on the provided date range
    forecast_data = data["list"]
    
    weather_forecast = []
    for forecast in forecast_data:
        forecast_date = datetime.strptime(forecast["dt_txt"], "%Y-%m-%d %H:%M:%S")
        
        if start_date <= forecast_date <= end_date:
            temp = forecast["main"]["temp"]
            weather_desc = forecast["weather"][0]["description"]
            weather_forecast.append(f"{forecast_date.strftime('%Y-%m-%d')}: {temp}°C, {weather_desc}")
    
    # Handle the case where no forecast is found for the date range
    if not weather_forecast:
        raise HTTPException(status_code=404, detail="No weather forecast found for the specified date range")
    
    # Return the weather forecast for the date range
    return weather_forecast

def get_lat_long(city_name):
    """Get latitude and longitude of a city using Google Geocoding API."""
    geo_url = f"https://maps.googleapis.com/maps/api/geocode/json?address={city_name}&key={timezone_api_key}"
    response = requests.get(geo_url).json()
    
    if response["status"] == "OK":
        location = response["results"][0]["geometry"]["location"]
        return location["lat"], location["lng"]
    else:
        print(f"Error: {response['status']}")
        return None, None
    
def get_iata_code(city_name: str, access_token: str) -> str:
    response = requests.get(
        "https://test.api.amadeus.com/v1/reference-data/locations",
        headers={"Authorization": f"Bearer {access_token}"},
        params={
            "subType": "AIRPORT,CITY",
            "keyword": city_name,
            "page[limit]": 1
        }
    )
    if response.status_code != 200 or not response.json().get("data"):
        raise HTTPException(status_code=400, detail=f"Could not resolve city '{city_name}' to IATA code.")
    return response.json()["data"][0]["iataCode"]

# ======================== Routes ======================== #

@app.get("/", response_class=HTMLResponse)
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

# ========== Get Weather ========== #
@app.get("/weather/{destination}")
def get_weather(destination: str):
    """Fetch current weather information for a given destination."""
    url = f"http://api.openweathermap.org/data/2.5/weather?q={destination}&units=metric&appid={openweather_api_key}"

    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Could not fetch weather data")

    data = response.json()
    
    weather_info = {
        "city": data["name"],
        "temperature": f"{data['main']['temp']}°C",
        "feels_like": f"{data['main']['feels_like']}°C",
        "weather": data["weather"][0]["description"],
        "humidity": f"{data['main']['humidity']}%",
        "wind_speed": f"{data['wind']['speed']} m/s"
    }

    return {"weather": weather_info}

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
    """Generate a travel itinerary and include a weather forecast based on user preferences."""
    
    # Convert start_date and end_date to datetime objects for better manipulation
    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d")
    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d")

    # Fetch weather data for each day in the date range
    # weather_forecast = get_weather_forecast_for_range(destination, start_date_obj, end_date_obj)
    # Also, consider the following weather forecast while planning activities: 
    # {weather_forecast}.
    prompt = f"""
    Create a well-structured travel itinerary for a trip to {destination} from {start_date} to {end_date}. 
    The users interests are: {interests}. The budget for the trip is {budget}. 
    There should be no asterisks and have the itinerary based on the token count.
    Keep it well structured and do not use asterisks, bullet points, Markdown, or any special characters. Just plain readable text with line breaks.
    
    The itinerary should be broken down by day, with the following details for each day:
    - Day 1: (Activity suggestion based on weather and interests)
    - Day 2: (Activity suggestion based on weather and interests)
    - Day 3: (Activity suggestion based on weather and interests)
    ...
    For each day, include:
    - A brief description of the weather
    - Recommended activities (e.g., outdoor, indoor based on the weather)
    - Suggested restaurants or dining options (if relevant)
    - Budget estimates for each day
    """
        
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful travel assistant. Respond in plain text. Use clear line-separated day labels like 'Day 1:', 'Day 2:' and avoid using asterisks, bullet points, or any Markdown formatting."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1000,
        temperature=0.5
    )
    
    generated_itinerary = response.choices[0].message.content

    itinerary = Itinerary(
        user_id=current_user.id,  # 🔐 Link itinerary to user
        destination=destination, 
        interests=interests, 
        start_date=start_date, 
        end_date=end_date, 
        budget=budget, 
        generated_itinerary=generated_itinerary
        # weather_forecast="\n".join(weather_forecast),
    )
    db.add(itinerary)
    db.commit()
    db.refresh(itinerary)
    
    return {"itinerary": generated_itinerary,  "user": current_user.email} # "weather_forecast": weather_forecast}

# ========== Get Local Time ========== #
@app.get("/local-time/{city_name}")
async def get_local_time(city_name):
    """Get local time of a city using Google Time Zone API."""
    lat, lon = get_lat_long(city_name)
    if lat is None or lon is None:
        return "Invalid city name"

    timestamp = int(time.time())  # Current Unix timestamp
    tz_url = f"https://maps.googleapis.com/maps/api/timezone/json?location={lat},{lon}&timestamp={timestamp}&key={timezone_api_key}"
    response = requests.get(tz_url).json()
    
    if response["status"] == "OK":
        raw_offset = response["rawOffset"]
        dst_offset = response["dstOffset"]
        total_offset = raw_offset + dst_offset  # Total offset in seconds

        utc_time = datetime.fromtimestamp(timestamp, tz=pytz.utc)
        local_time = utc_time + timedelta(seconds=total_offset)
        
        return local_time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        print(f"Error: {response['status']}")
        return None

# ========== Search Flights  ========== #
@app.get("/search-flights")
def search_flights(origin: str, destination: str, date_from: str, date_to: str):
    AMADEUS_API_KEY = os.getenv("AMADEUS_API_KEY")
    AMADEUS_API_SECRET = os.getenv("AMADEUS_API_SECRET")

    if not AMADEUS_API_KEY or not AMADEUS_API_SECRET:
        raise HTTPException(status_code=500, detail="Amadeus credentials missing.")

    # Step 1: Authenticate
    auth_response = requests.post(
        "https://test.api.amadeus.com/v1/security/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": AMADEUS_API_KEY,
            "client_secret": AMADEUS_API_SECRET
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    if auth_response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to authenticate with Amadeus.")

    access_token = auth_response.json()["access_token"]

    # Step 2: Get IATA codes for origin and destination
    origin_iata = get_iata_code(origin, access_token)
    destination_iata = get_iata_code(destination, access_token)

    # Step 3: Search flights
    url = "https://test.api.amadeus.com/v2/shopping/flight-offers"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    params = {
        "originLocationCode": origin_iata,
        "destinationLocationCode": destination_iata,
        "departureDate": date_from,
        "returnDate": date_to,
        "adults": 1,
        "currencyCode": "USD",
        "max": 5
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print("Flight search error:", response.text)
        raise HTTPException(status_code=500, detail="Error fetching flight data.")

    flight_data = response.json()
    results = []

    for offer in flight_data.get("data", []):
        results.append({
            "price": offer.get("price", {}).get("total", "N/A"),
            "airline": offer.get("validatingAirlineCodes", ["N/A"])[0],
            "departure": offer.get("itineraries", [{}])[0].get("segments", [{}])[0].get("departure", {}).get("at", "N/A"),
            "arrival": offer.get("itineraries", [{}])[0].get("segments", [{}])[0].get("arrival", {}).get("at", "N/A"),
        })

    return {"flights": results or [], "message": "No flights found." if not results else ""}

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

@app.patch("/users/{user_id}")
async def partial_update_user(user_id: int, user: UserUpdate, db: Session = Depends(get_db)
):
    """Partially update user details (only provided fields)."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = user.dict(exclude_unset=True)  # Exclude fields that were not provided

    if "password" in update_data:
        update_data["password"] = get_password_hash(update_data["password"])  # Hash password if updating

    for key, value in update_data.items():
        setattr(db_user, key, value)  # Dynamically update fields

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

@app.get("/my-itineraries")
def get_user_itineraries(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    trips = db.query(Itinerary).filter(Itinerary.user_id == current_user.id).all()
    return trips
