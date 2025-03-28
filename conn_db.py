import psycopg2                                                         # type: ignore
from psycopg2 import sql                                                # type: ignore
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve database configuration from environment variables
db_config = {
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
}

# Initialize connection and cursor variables
conn = None  
cursor = None 

try:
    # Establish the database connection using environment variables
    conn = psycopg2.connect(
        host=db_config["host"],
        database=db_config["database"],
        user=db_config["user"],
        password=db_config["password"]
    )
    
    cursor = conn.cursor()

    # Execute a test query
    cursor.execute("SELECT version();")
    db_version = cursor.fetchone()
    print(f"Connected to PostgreSQL, version: {db_version}")

    cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    tables = cursor.fetchall()
    print("Tables in the database:")
    for table in tables:
        print(table[0])

except Exception as e:
    print(f"Error: {e}")

finally:
    # Close the cursor and connection to clean up
    if cursor:
        cursor.close()
    if conn:
        conn.close()
        print("Connection closed.")