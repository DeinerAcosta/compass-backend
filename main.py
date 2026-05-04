from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List

# Importamos la librería de seguridad para encriptación
from passlib.context import CryptContext

import models
import schemas
from database import engine, get_db

# Crea las tablas en MySQL automáticamente si no existen
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="COMPASS API", version="1.0")

# Configuración de CORS para permitir conexión desde el Frontend (Live Server)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURACIÓN DE SEGURIDAD (Bcrypt) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


@app.get("/")
def read_root():
    return {"mensaje": "API de COMPASS funcionando y base de datos sincronizada"}


# --- ENDPOINT: Autenticación Real con Seguridad ---
@app.post("/api/auth/login")
def login(user_credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    # Buscamos al usuario por correo
    user = db.query(models.Usuario).filter(models.Usuario.email == user_credentials.email).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Correo o contraseña incorrectos"
        )

    # MIGRACIÓN AUTOMÁTICA: Si la contraseña en BD no está encriptada (no empieza con $2b$)
    if not user.password_hash.startswith("$2b$"):
        if user.password_hash == user_credentials.password:
            # Si coincide, la encriptamos y la guardamos
            user.password_hash = get_password_hash(user_credentials.password)
            db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Correo o contraseña incorrectos"
            )
            
    # VERIFICACIÓN NORMAL: Compara la contraseña escrita con el hash seguro
    elif not verify_password(user_credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Correo o contraseña incorrectos"
        )
    
    return {
        "status": "success",
        "usuario": {
            "id": user.id,
            "name": user.nombre,
            "email": user.email,
            "role": user.rol,
            "proceso": user.proceso
        }
    }


# --- ENDPOINT: Registro de Usuarios ---
@app.post("/api/auth/register")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. Verificamos si el correo ya existe
    db_user = db.query(models.Usuario).filter(models.Usuario.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Este correo ya está registrado")
    
    # 2. Encriptamos la contraseña
    hashed_pw = get_password_hash(user.password)
    
    # 3. Creamos el usuario (Por defecto entra con rol 'user')
    new_user = models.Usuario(
        nombre=user.nombre,
        email=user.email,
        password_hash=hashed_pw,
        proceso=user.proceso,
        rol="user" 
    )
    db.add(new_user)
    db.commit()
    
    return {"status": "success", "message": "Usuario registrado exitosamente"}


# --- ENDPOINT: Guardar Formulario ---
@app.post("/api/forms/save")
def save_formulario(formulario: schemas.FormularioCreate, db: Session = Depends(get_db)):
    
    # 1. Buscamos si el formulario ya existe
    db_form = db.query(models.Formulario).filter(models.Formulario.id == formulario.id).first()
    
    # Buscamos el ID del usuario basado en el email para que el registro quede amarrado al usuario real
    user = db.query(models.Usuario).filter(models.Usuario.email == formulario.email).first()
    user_id = user.id if user else 1 # Fallback a 1 si no se encuentra

    # Convertimos los compromisos múltiples a lista de diccionarios para JSON
    mpa_list = [item.model_dump() for item in formulario.mpaItems] if formulario.mpaItems else []

    if db_form:
        # Actualizar existente
        db_form.anio_principal = formulario.year
        db_form.anios_array = formulario.years
        db_form.proceso = formulario.proceso
        db_form.lider = formulario.lider
        db_form.mercado = formulario.mercado
        db_form.contexto = formulario.contexto
        db_form.objetivo_texto = formulario.objetivo
        db_form.meta_anio_1 = formulario.meta26
        db_form.accion_anio_1 = formulario.accion26
        db_form.meta_anio_2 = formulario.meta27
        db_form.accion_anio_2 = formulario.accion27
        db_form.supuesto_critico = formulario.supuesto
        db_form.apoyo_gerencia = formulario.recurso
        db_form.status = formulario.status
        db_form.bsc_codigos = formulario.bsc
        db_form.mpa_items_json = mpa_list
        
        # Actualización de KPIs: borrar y recrear
        db.query(models.FormularioKPI).filter(models.FormularioKPI.formulario_id == db_form.id).delete()
        
    else:
        # Crear nuevo
        db_form = models.Formulario(
            id=formulario.id,
            usuario_id=user_id, 
            anio_principal=formulario.year,
            anios_array=formulario.years,
            proceso=formulario.proceso,
            lider=formulario.lider,
            mercado=formulario.mercado,
            contexto=formulario.contexto,
            objetivo_texto=formulario.objetivo,
            meta_anio_1=formulario.meta26,
            accion_anio_1=formulario.accion26,
            meta_anio_2=formulario.meta27,
            accion_anio_2=formulario.accion27,
            supuesto_critico=formulario.supuesto,
            apoyo_gerencia=formulario.recurso,
            status=formulario.status,
            bsc_codigos=formulario.bsc,
            mpa_items_json=mpa_list
        )
        db.add(db_form)
    
    db.commit() 
    
    # 2. Guardamos los KPIs
    for kpi in formulario.kpis:
        db_kpi = models.FormularioKPI(
            formulario_id=db_form.id,
            indicador=kpi.ind,
            linea_base=kpi.base,
            meta_1=kpi.meta26,
            meta_2=kpi.meta27,
            semaforo=kpi.sem
        )
        db.add(db_kpi)
        
    db.commit()
    return {"status": "success", "message": "Formulario guardado correctamente", "id": db_form.id}


# --- ENDPOINT: Obtener todos los Formularios ---
@app.get("/api/forms")
def get_formularios(db: Session = Depends(get_db)):
    formularios = db.query(models.Formulario).all()
    result = {}
    
    for f in formularios:
        user = db.query(models.Usuario).filter(models.Usuario.id == f.usuario_id).first()
        email = user.email if user else ""

        kpis_db = db.query(models.FormularioKPI).filter(models.FormularioKPI.formulario_id == f.id).all()
        kpis = [{"ind": k.indicador, "base": k.linea_base, "meta26": k.meta_1, "meta27": k.meta_2, "sem": k.semaforo} for k in kpis_db]
        
        while len(kpis) < 3:
            kpis.append({"ind":"", "base":"", "meta26":"", "meta27":"", "sem":""})

        result[f.id] = {
            "id": f.id,
            "email": email,
            "year": f.anio_principal,
            "years": f.anios_array or [f.anio_principal],
            "proceso": f.proceso,
            "lider": f.lider,
            "mercado": f.mercado,
            "contexto": f.contexto,
            "objetivo": f.objetivo_texto,
            "mpaItems": f.mpa_items_json or [],
            "kpis": kpis,
            "supuesto": f.supuesto_critico,
            "recurso": f.apoyo_gerencia,
            "status": f.status,
            "bsc": f.bsc_codigos or [],
            "createdAt": "2026-01-01", 
            "updatedAt": "2026-01-01"
        }
        
    return result


# --- ENDPOINT: Obtener todos los Usuarios ---
@app.get("/api/users")
def get_usuarios(db: Session = Depends(get_db)):
    usuarios = db.query(models.Usuario).all()
    result = {}
    
    for u in usuarios:
        result[u.email] = {
            "id": u.id,
            "name": u.nombre,
            "email": u.email,
            "proceso": u.proceso,
            "role": u.rol,
            "createdAt": "2026-01-01T12:00:00Z" 
        }
        
    return result

# --- ENDPOINTS: Gestión de Años ---
# --- GESTIÓN DE AÑOS ---
@app.get("/api/years")
def get_years(db: Session = Depends(get_db)):
    anios = db.query(models.AnioActivo).all()
    return [a.anio for a in anios]

@app.post("/api/years")
def add_year(anio_data: schemas.AnioCreate, db: Session = Depends(get_db)):
    exist = db.query(models.AnioActivo).filter(models.AnioActivo.anio == anio_data.anio).first()
    if not exist:
        new_anio = models.AnioActivo(anio=anio_data.anio)
        db.add(new_anio)
        db.commit()
    return {"status": "success"}

@app.delete("/api/years/{year}")
def delete_year(year: int, db: Session = Depends(get_db)):
    db.query(models.AnioActivo).filter(models.AnioActivo.anio == year).delete()
    db.commit()
    return {"status": "success"}