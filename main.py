from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel # Importación nueva para el actualizador de estado

# Importamos la librería de seguridad para encriptación
from passlib.context import CryptContext

# Envío de correos
import os
import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import models
import schemas
from database import engine, get_db

# --- Configuración SMTP (Gmail con contraseña de aplicación) ---
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "COMPASS - COI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://compass-frontend-qp7n.vercel.app")

# Crea las tablas en MySQL automáticamente si no existen
models.Base.metadata.create_all(bind=engine)

# Migración suave: añade columna 'must_change_password' a usuarios si no existe
def _ensure_must_change_password_column():
    try:
        from sqlalchemy import text
        with engine.connect() as conn:
            res = conn.execute(text(
                "SELECT COUNT(*) FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() "
                "AND TABLE_NAME = 'usuarios' "
                "AND COLUMN_NAME = 'must_change_password'"
            ))
            existe = res.scalar() or 0
            if not existe:
                conn.execute(text(
                    "ALTER TABLE usuarios ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0"
                ))
                conn.commit()
                print("[MIGRACIÓN] Columna 'must_change_password' añadida a tabla 'usuarios'.")
    except Exception as e:
        print(f"[MIGRACIÓN] No se pudo verificar/añadir columna must_change_password: {e}")

_ensure_must_change_password_column()

app = FastAPI(title="COMPASS API", version="1.0")

# Configuración de CORS para permitir conexión desde el Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://compass-frontend-qp7n.vercel.app",  # Tu página real en Vercel
        "http://localhost:5500",                     # Por si pruebas en tu PC
        "http://127.0.0.1:5500"
    ],
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


# --- Helpers de Email ---
def generar_password_temporal(longitud: int = 10) -> str:
    alfabeto = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alfabeto) for _ in range(longitud))


def send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Envía un correo vía Gmail SMTP. Devuelve True si fue enviado, False si falló."""
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[SMTP] Variables SMTP_USER/SMTP_PASSWORD no configuradas. Email a {to_email} NO enviado.")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [to_email], msg.as_string())
        return True
    except Exception as e:
        print(f"[SMTP] Error enviando email a {to_email}: {e}")
        return False


def crear_notificacion(db: Session, usuario_id: int, tipo: str, titulo: str,
                       mensaje: str = "", formulario_id: str = None) -> models.Notificacion:
    notif = models.Notificacion(
        usuario_id=usuario_id,
        tipo=tipo,
        titulo=titulo,
        mensaje=mensaje,
        formulario_id=formulario_id,
        leida=False,
    )
    db.add(notif)
    return notif


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
            "proceso": user.proceso,
            "must_change_password": bool(user.must_change_password)
        }
    }


# --- ENDPOINT: Olvidé mi contraseña (envía contraseña provisional al correo) ---
@app.post("/api/auth/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(models.Usuario).filter(models.Usuario.email == email).first()

    # Por seguridad: respondemos lo mismo aunque el correo no exista (para no filtrar usuarios)
    if not user:
        return {"status": "success", "message": "Si el correo está registrado, recibirás instrucciones para restablecer tu contraseña."}

    # 1. Generamos una contraseña provisional de 10 caracteres
    temp_password = generar_password_temporal(10)

    # 2. La guardamos hasheada y marcamos que el usuario DEBE cambiarla al ingresar
    user.password_hash = get_password_hash(temp_password)
    user.must_change_password = True
    db.commit()

    # 3. Construimos el email
    login_link = FRONTEND_URL
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;background:#FAFAF9;color:#1A1A17">
      <div style="background:#0F7A62;color:#fff;padding:20px 24px;border-radius:12px 12px 0 0">
        <h1 style="margin:0;font-size:22px;letter-spacing:.5px">COMPASS · COI</h1>
        <p style="margin:6px 0 0;opacity:.85;font-size:13px">Restablecimiento de contraseña</p>
      </div>
      <div style="background:#fff;padding:24px;border:1px solid #E5E3DC;border-top:none;border-radius:0 0 12px 12px">
        <p>Hola <strong>{user.nombre}</strong>,</p>
        <p>Hemos generado una <strong>contraseña provisional</strong> para tu cuenta en COMPASS:</p>
        <div style="background:#E3F9F5;border:1px dashed #0F7A62;border-radius:8px;padding:16px;text-align:center;margin:18px 0">
          <div style="font-size:11px;color:#0F7A62;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Contraseña provisional</div>
          <div style="font-family:'Courier New',monospace;font-size:22px;font-weight:bold;color:#0F7A62;letter-spacing:2px">{temp_password}</div>
        </div>
        <p>Al iniciar sesión, la plataforma te pedirá <strong>cambiarla inmediatamente</strong> por una nueva.</p>
        <p style="text-align:center;margin:28px 0">
          <a href="{login_link}" style="background:#0F7A62;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;display:inline-block;font-weight:600">Ir al login →</a>
        </p>
        <p style="font-size:12px;color:#8A8780;border-top:1px solid #E5E3DC;padding-top:14px;margin-top:24px">
          Si tú no solicitaste este cambio, contacta a soporte inmediatamente.<br>
          Este es un correo automático — no respondas a este mensaje.
        </p>
      </div>
    </div>
    """
    sent = send_email(user.email, "COMPASS · Tu contraseña provisional", html)

    return {
        "status": "success",
        "message": "Si el correo está registrado, recibirás instrucciones para restablecer tu contraseña.",
        "email_sent": sent
    }


# --- ENDPOINT: Cambiar contraseña (usado tras login con clave provisional o cambio normal) ---
@app.post("/api/auth/change-password")
def change_password(payload: schemas.ChangePasswordRequest, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(models.Usuario).filter(models.Usuario.email == email).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="La contraseña actual es incorrecta")

    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="La nueva contraseña debe tener al menos 6 caracteres")

    user.password_hash = get_password_hash(payload.new_password)
    user.must_change_password = False
    db.commit()

    return {"status": "success", "message": "Contraseña actualizada correctamente"}


# --- ENDPOINT: Registro de Usuarios ---
@app.post("/api/auth/register")
def register_user(user: schemas.UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # 1. Verificar si el correo ya existe
    db_user = db.query(models.Usuario).filter(models.Usuario.email == user.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Este correo ya está registrado"
        )
    
    # 2. Lista de correos autorizados para ser ADMIN
    ADMINS_AUTORIZADOS = ["gerencia@cofca.com", "desarrollo@cofca.com"]
    
    # Comparamos en minúsculas para evitar errores de dedo
    rol_asignado = "admin" if user.email.lower() in ADMINS_AUTORIZADOS else "user"
    
    # 3. Crear el nuevo usuario
    new_user = models.Usuario(
        nombre=user.nombre,
        email=user.email.lower(), # Guardamos siempre en minúsculas
        password_hash=get_password_hash(user.password),
        proceso=user.proceso,
        rol=rol_asignado
    )
    
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        return {
            "status": "success", 
            "message": f"Usuario registrado exitosamente como {rol_asignado}"
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


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


# --- NUEVO: Eliminar Formulario Completo (Cascada) ---
@app.delete("/api/forms/{form_id}")
def delete_formulario_completo(form_id: str, db: Session = Depends(get_db)):
    # 1. Borrar KPIs primero para evitar error de Llave Foránea
    db.query(models.FormularioKPI).filter(models.FormularioKPI.formulario_id == form_id).delete()
    
    # 2. Borrar Formulario principal
    resultado = db.query(models.Formulario).filter(models.Formulario.id == form_id).delete()
    db.commit()
    
    if resultado == 0:
        raise HTTPException(status_code=404, detail="Formulario no encontrado")
        
    return {"status": "success", "message": "Formulario y KPIs eliminados completamente"}


# --- NUEVO: Cambiar Estado del Formulario (Flujo de Autorización) ---
class FormStatusUpdate(BaseModel):
    status: str

@app.put("/api/forms/{form_id}/status")
def update_form_status(form_id: str, status_data: FormStatusUpdate, db: Session = Depends(get_db)):
    form = db.query(models.Formulario).filter(models.Formulario.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Formulario no encontrado")

    estado_anterior = str(form.status)
    nuevo_estado = status_data.status

    # Datos del líder dueño del formato (para mensajes y notif)
    lider = db.query(models.Usuario).filter(models.Usuario.id == form.usuario_id).first()
    lider_nombre = lider.nombre if lider else (form.lider or "Líder")
    proceso = form.proceso or "Sin proceso"

    form.status = nuevo_estado
    db.commit()

    # === Triggers de notificaciones ===
    try:
        # 1. Líder solicita edición → notificar a TODOS los admins (in-app + email)
        if nuevo_estado == "Edicion Solicitada":
            admins = db.query(models.Usuario).filter(models.Usuario.rol == "admin").all()
            titulo = f"Solicitud de edición · {proceso}"
            mensaje = f"{lider_nombre} solicitó permiso para editar el formato del proceso '{proceso}' ({form.anio_principal})."

            for admin in admins:
                crear_notificacion(db, admin.id, "edicion_solicitada", titulo, mensaje, form.id)
                # Email al admin
                html = f"""
                <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;background:#FAFAF9">
                  <div style="background:#D97706;color:#fff;padding:18px 24px;border-radius:12px 12px 0 0">
                    <h1 style="margin:0;font-size:20px">⚠️ Solicitud de edición</h1>
                    <p style="margin:4px 0 0;opacity:.9;font-size:12px">COMPASS · COI</p>
                  </div>
                  <div style="background:#fff;padding:24px;border:1px solid #E5E3DC;border-top:none;border-radius:0 0 12px 12px;color:#1A1A17">
                    <p>Hola <strong>{admin.nombre}</strong>,</p>
                    <p>El líder <strong>{lider_nombre}</strong> ha solicitado permiso para editar un formato ya enviado:</p>
                    <ul style="background:#FEF3C7;border-left:4px solid #D97706;padding:14px 14px 14px 30px;list-style:none">
                      <li><strong>Proceso:</strong> {proceso}</li>
                      <li><strong>Año:</strong> {form.anio_principal}</li>
                      <li><strong>Solicitante:</strong> {lider_nombre}</li>
                    </ul>
                    <p>Ingresa al panel administrativo de COMPASS para aprobar o rechazar la solicitud.</p>
                    <p style="text-align:center;margin:24px 0">
                      <a href="{FRONTEND_URL}" style="background:#0F7A62;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;display:inline-block;font-weight:600">Abrir COMPASS →</a>
                    </p>
                    <p style="font-size:11px;color:#8A8780;border-top:1px solid #E5E3DC;padding-top:12px">Correo automático — no responder.</p>
                  </div>
                </div>
                """
                send_email(admin.email, f"COMPASS · Solicitud de edición de {lider_nombre}", html)

        # 2. Admin aprueba la edición (de "Edicion Solicitada" → "borrador") → notif al líder
        elif estado_anterior == "Edicion Solicitada" and nuevo_estado == "borrador" and lider:
            titulo = "Edición aprobada"
            mensaje = f"Tu solicitud para editar el formato de '{proceso}' ({form.anio_principal}) fue aprobada. Ya puedes modificarlo."
            crear_notificacion(db, lider.id, "edicion_aprobada", titulo, mensaje, form.id)
            html = f"""
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px">
              <div style="background:#0F7A62;color:#fff;padding:18px 24px;border-radius:12px 12px 0 0">
                <h1 style="margin:0;font-size:20px">✓ Edición aprobada</h1>
              </div>
              <div style="background:#fff;padding:24px;border:1px solid #E5E3DC;border-top:none;border-radius:0 0 12px 12px">
                <p>Hola <strong>{lider.nombre}</strong>,</p>
                <p>Gerencia aprobó tu solicitud para editar el formato del proceso <strong>{proceso}</strong> ({form.anio_principal}).</p>
                <p>Ya puedes ingresar a COMPASS y modificarlo.</p>
                <p style="text-align:center;margin:24px 0">
                  <a href="{FRONTEND_URL}" style="background:#0F7A62;color:#fff;text-decoration:none;padding:12px 24px;border-radius:8px;display:inline-block;font-weight:600">Abrir COMPASS →</a>
                </p>
              </div>
            </div>
            """
            send_email(lider.email, "COMPASS · Tu edición fue aprobada", html)

        db.commit()
    except Exception as e:
        print(f"[NOTIF] Error generando notificación: {e}")
        db.rollback()

    return {"status": "success", "message": f"Estado cambiado a {nuevo_estado}"}


# --- ENDPOINT: Listar notificaciones de un usuario (por email) ---
@app.get("/api/notifications/{email}")
def get_notifications(email: str, db: Session = Depends(get_db)):
    user = db.query(models.Usuario).filter(models.Usuario.email == email.lower()).first()
    if not user:
        return {"unread_count": 0, "items": []}

    notifs = (
        db.query(models.Notificacion)
        .filter(models.Notificacion.usuario_id == user.id)
        .order_by(models.Notificacion.created_at.desc())
        .limit(30)
        .all()
    )
    unread = sum(1 for n in notifs if not n.leida)

    items = [{
        "id": n.id,
        "tipo": n.tipo,
        "titulo": n.titulo,
        "mensaje": n.mensaje,
        "formulario_id": n.formulario_id,
        "leida": bool(n.leida),
        "created_at": n.created_at.isoformat() if n.created_at else None,
    } for n in notifs]

    return {"unread_count": unread, "items": items}


@app.put("/api/notifications/{notif_id}/read")
def mark_notification_read(notif_id: int, db: Session = Depends(get_db)):
    notif = db.query(models.Notificacion).filter(models.Notificacion.id == notif_id).first()
    if not notif:
        raise HTTPException(status_code=404, detail="Notificación no encontrada")
    notif.leida = True
    db.commit()
    return {"status": "success"}


@app.put("/api/notifications/read-all/{email}")
def mark_all_read(email: str, db: Session = Depends(get_db)):
    user = db.query(models.Usuario).filter(models.Usuario.email == email.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.query(models.Notificacion).filter(
        models.Notificacion.usuario_id == user.id,
        models.Notificacion.leida == False
    ).update({"leida": True})
    db.commit()
    return {"status": "success"}