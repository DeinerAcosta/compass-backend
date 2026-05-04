from sqlalchemy import Boolean, Column, Integer, String, Text, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
import enum
from database import Base # Importamos la base que creaste en el paso anterior

# Definimos los estados posibles
class StatusEnum(str, enum.Enum):
    borrador = "borrador"
    enviado = "enviado"

class SemaforoEnum(str, enum.Enum):
    verde = "verde"
    amarillo = "amarillo"
    rojo = "rojo"
    vacio = ""

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nombre = Column(String(100), nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    proceso = Column(String(100))
    rol = Column(String(20), default="user") # 'admin' o 'user'

    # Relación con formularios
    formularios = relationship("Formulario", back_populates="usuario")

class Formulario(Base):
    __tablename__ = "formularios"

    id = Column(String(50), primary_key=True, index=True) # El 'f123456789' del frontend
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    anio_principal = Column(Integer, nullable=False)
    anios_array = Column(JSON) # Para guardar la lista de años [2026, 2027]
    proceso = Column(String(100))
    lider = Column(String(100))
    mercado = Column(String(100))
    contexto = Column(Text)
    objetivo_texto = Column(Text)
    
    # Campos legacy para mantener compatibilidad si solo hay 1 compromiso
    meta_anio_1 = Column(Text)
    accion_anio_1 = Column(Text)
    meta_anio_2 = Column(Text)
    accion_anio_2 = Column(Text)
    
    supuesto_critico = Column(Text)
    apoyo_gerencia = Column(Text)
    status = Column(Enum(StatusEnum), default=StatusEnum.borrador)
    
    bsc_codigos = Column(JSON) # Guardamos la lista de códigos BSC ["4.1", "3.2"]
    
    # NUEVO: Aquí guardaremos todos los compromisos múltiples (M, P, A)
    mpa_items_json = Column(JSON) 

    # Relaciones
    usuario = relationship("Usuario", back_populates="formularios")
    kpis = relationship("FormularioKPI", back_populates="formulario", cascade="all, delete-orphan")

class FormularioKPI(Base):
    __tablename__ = "formularios_kpis"

    id = Column(Integer, primary_key=True, index=True)
    formulario_id = Column(String(50), ForeignKey("formularios.id"))
    indicador = Column(String(255))
    linea_base = Column(String(100))
    meta_1 = Column(String(100))
    meta_2 = Column(String(100))
    semaforo = Column(Enum(SemaforoEnum), default=SemaforoEnum.vacio)

    formulario = relationship("Formulario", back_populates="kpis")

class AnioActivo(Base):
    __tablename__ = "anios_activos"
    
    id = Column(Integer, primary_key=True, index=True)
    anio = Column(Integer, unique=True, index=True)