import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# 1. Cargar las variables del archivo .env
load_dotenv()

# 2. Obtener la URL de forma segura
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# 3. Motor de conexión
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"ssl": {"ssl_mode": "REQUIRED"}}
)

# 4. Sesión
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()