# Import necessary modules from SQLAlchemy
from sqlalchemy import create_engine  # For creating a database connection engine           # type: ignore
from sqlalchemy.orm import sessionmaker, Session  # For managing database sessions          # type: ignore
import os  # For environment variable access
from dotenv import load_dotenv  # To load environment variables from a .env file

# Load environment variables from .env file
load_dotenv()

# Retrieve the database URL from environment variables
DATABASE_URL = os.environ["DATABASE_URL"]

# Create a SQLAlchemy engine to connect to the database
# 'pool_pre_ping=True' ensures the connection is alive before using it
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Configure session factory with autocommit and autoflush disabled
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency function to get a database session
def get_db():
    """
    Provides a database session for request handling.
    Ensures the session is properly closed after use.
    """
    db = SessionLocal()  # Create a new session instance
    try:
        yield db  # Provide the session to the request handler
    finally:
        db.close()  # Close the session to free up resources
