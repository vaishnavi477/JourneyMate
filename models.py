from sqlalchemy import Column, Integer, String, Date, Numeric, Text, ForeignKey             # type: ignore
from sqlalchemy.ext.declarative import declarative_base                                     # type: ignore
from sqlalchemy.orm import relationship                                                     # type: ignore

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    email = Column(String, index=True, nullable=False)
    itineraries = relationship("Itinerary", back_populates="user")

class Itinerary(Base):
    __tablename__ = "itineraries"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    destination = Column(String)
    interests = Column(Text)
    start_date = Column(Date)
    end_date = Column(Date)
    budget = Column(Numeric)
    generated_itinerary = Column(Text)
    weather_forecast = Column(String, nullable=True)
    user = relationship("User", back_populates="itineraries")
