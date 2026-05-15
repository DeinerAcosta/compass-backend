from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class KPISchema(BaseModel):
    ind: str
    base: str
    meta26: str
    meta27: str
    sem: str

class MPASchema(BaseModel):
    meta26: str
    accion26: str
    meta27: str
    accion27: str

class FormularioCreate(BaseModel):
    id: str
    email: str
    year: int
    years: List[int]
    proceso: str
    lider: str
    mercado: str
    bsc: List[str]
    contexto: str
    objetivo: str
    meta26: str
    accion26: str
    meta27: str
    accion27: str
    kpis: List[KPISchema]
    mpaItems: Optional[List[MPASchema]] = []
    supuesto: str
    recurso: str
    status: str

# Esta es la clase que le falta a Python:
class UserLogin(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    nombre: str
    email: str
    password: str
    proceso: str

class AnioCreate(BaseModel):
    anio: int


# --- Recuperación / Cambio de contraseña ---
class ForgotPasswordRequest(BaseModel):
    email: str

class ChangePasswordRequest(BaseModel):
    email: str
    current_password: str
    new_password: str


# --- Notificaciones ---
class NotificacionResponse(BaseModel):
    id: int
    tipo: str
    titulo: str
    mensaje: Optional[str] = None
    formulario_id: Optional[str] = None
    leida: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True