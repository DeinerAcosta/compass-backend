import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# 1. Usamos os.getenv para que Render lea la URL desde las Variables de Entorno.
# Si no existe (en tu PC local), usará la cadena que pongas como segundo parámetro.
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "mysql+pymysql://avnadmin:TU_CLAVE_AIVEN@kafka-cb1dfbb-pruebas-39c8.j.aivencloud.com:16767/defaultdb?ssl_ca=ca.pem"
)

# 2. El parámetro 'pool_pre_ping' es vital para conexiones en la nube, 
# ya que evita errores si Aiven cierra la conexión por inactividad.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()