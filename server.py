from typing import Literal, Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request, Response, Query, Path
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
import pyodbc
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import bcrypt
import jwt
import qrcode
import os
from cryptography.fernet import Fernet
import uuid
import hashlib
import secrets
import string
import json
import re

app = FastAPI()

# Configuración CORS
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:5500",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de la base de datos
DB_CONFIG = {
    'server': 'JOSE',
    'database': 'LIANZE_DB',
    'username': 'josehart',
    'password': 'porras0111',
    'driver': '{ODBC Driver 17 for SQL Server}'
}

# Configuración de encriptación
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Configuración JWT
SECRET_KEY = "tu_clave_secreta_super_segura_32bytes"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Archivos estáticos
app.mount("/static", StaticFiles(directory="public"), name="static")

# Modelos Pydantic
class User(BaseModel):
    id: int
    email: str
    firstName: str
    lastName: str
    userType: str
    mfaEnabled: bool

class UserProfile(BaseModel):
    id: int
    email: str
    firstName: str
    lastName: str
    userType: str
    phone: Optional[str]
    dateOfBirth: Optional[str]
    gender: Optional[str]
    profileImage: Optional[str]
    bio: Optional[str]
    country_id: Optional[str]
    province_id: Optional[str]
    canton_id: Optional[str]
    district_id: Optional[str]


QuestionType = Literal['petName', 'favoriteColor', 'favoritePlace']


class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    firstName: str
    lastName: str
    email: str
    password: str
    userType: str
    countryId: str
    provinceId: Optional[str] = None
    cantonId: Optional[str] = None
    districtId: Optional[str] = None

class SecurityQuestions(BaseModel):
    petName: str
    favoriteColor: str
    favoritePlace: str

class PaymentMethod(BaseModel):
    id: int
    cardNumber: str
    cardHolder: str
    expirationMonth: int
    expirationYear: int
    cvv: str
    balance: float
    isDefault: bool

class UserProfileResponse(BaseModel):
    id: int
    email: str
    firstName: str
    lastName: str
    userType: str
    phone: Optional[str] = None
    dateOfBirth: Optional[datetime] = None
    gender: Optional[str] = None
    profileImage: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime
    bio: Optional[str] = None
    country_id: Optional[str] = None
    province_id: Optional[str] = None
    canton_id: Optional[str] = None
    district_id: Optional[str] = None

class UpdateMFARequest(BaseModel):
    userId: int
    enable: bool

class Country(BaseModel):
    id: int
    description: str
    code: str

class Province(BaseModel):
    id: str
    description: str
    code: str

class Canton(BaseModel):
    id: str
    description: str
    code: str

class District(BaseModel):
    id: str
    description: str
    code: str

class UpdateLocationRequest(BaseModel):
    userId: int
    countryId: str
    provinceId: Optional[str] = None
    cantonId: Optional[str] = None
    districtId: Optional[str] = None

class AddPaymentMethodRequest(BaseModel):
    userId: int
    cardNumber: str
    cardHolder: str
    expirationMonth: int
    expirationYear: int
    cvv: str
    balance: Optional[float] = 0.0

class AddPaymentMethodResponse(BaseModel):
    success: bool
    message: str
    cardId: int

class UpdatePaymentMethodRequest(BaseModel):
    cardHolder: str
    expirationMonth: int
    expirationYear: int
    isDefault: bool

class DeletePaymentMethodResponse(BaseModel):
    success: bool
    message: str
    new_default_card: Optional[int] = None

class PsychologistProfile(BaseModel):
    id: int
    user_id: int
    first_name: str
    last_name: str
    license_number: str
    specialties: Optional[str] = None
    experience: Optional[int] = None
    education: Optional[str] = None
    languages: Optional[List[str]] = None
    hourly_rate: Optional[float] = None
    bio: Optional[str] = None
    availability: Optional[str] = None
    rating: Optional[float] = None
    total_reviews: Optional[int] = None
    is_verified: bool
    profile_image: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class FilteredPsychologist(BaseModel):
    id: int
    user_id: int
    first_name: str
    last_name: str
    specialties: Optional[str] = None
    languages: Optional[List[str]] = None
    hourly_rate: Optional[float] = None
    rating: Optional[float] = None
    total_reviews: Optional[int] = None
    profile_image: Optional[str] = None

class PsychologistFilterParams(BaseModel):
    specialty: Optional[str] = None
    language: Optional[str] = None
    max_price: Optional[float] = None

class PsychologistDetail(BaseModel):
    id: int
    user_id: int
    first_name: str
    last_name: str
    license_number: str
    specialties: Optional[List[str]] = None
    experience: Optional[int] = None
    education: Optional[str] = None
    languages: Optional[List[str]] = None
    hourly_rate: Optional[float] = None
    bio: Optional[str] = None
    availability: Optional[str] = None
    rating: Optional[float] = None
    total_reviews: Optional[int] = None
    is_verified: bool
    profile_image: Optional[str] = None
    country_id: Optional[str] = None
    province_id: Optional[str] = None
    canton_id: Optional[str] = None
    district_id: Optional[str] = None

class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str
    user_type: str  # 'patient' or 'psychologist'
    country_id: str
    province_id: Optional[str] = None
    canton_id: Optional[str] = None
    district_id: Optional[str] = None

# Modelo para la respuesta exitosa
class RegisterResponse(BaseModel):
    success: bool
    user_id: int
    user_type: str
    next_step: str
    backup_codes: List[str]
    message: Optional[str] = None

# Modelo para la respuesta de error
class ErrorResponse(BaseModel):
    success: bool
    message: str

class SecurityQuestionsRequest(BaseModel):
    user_id: int
    pet_name: str
    favorite_color: str
    favorite_place: str

# Modelo para la respuesta
class SecurityQuestionsResponse(BaseModel):
    success: bool
    message: str

class SecurityQuestionsResponse(BaseModel):
    success: bool
    questions: SecurityQuestions
    message: Optional[str] = "Preguntas de seguridad obtenidas correctamente"


class SecurityQuestionsError(BaseModel):
    success: bool
    message: str

class DeleteAccountRequest(BaseModel):
    user_id: int
    password: str

# Modelo para la respuesta exitosa
class DeleteAccountResponse(BaseModel):
    success: bool
    message: str

# Modelo para respuestas de error
class DeleteAccountError(BaseModel):
    success: bool
    message: str

class UpdateEmailRequest(BaseModel):
    user_id: int
    new_email: EmailStr  # Validación automática de formato email

# Modelo para la respuesta exitosa
class UpdateEmailResponse(BaseModel):
    success: bool
    message: str

# Modelo para respuestas de error
class UpdateEmailError(BaseModel):
    success: bool
    message: str

class ChangePasswordRequest(BaseModel):
    user_id: int
    current_password: str
    new_password: str

# Modelo para la respuesta exitosa
class ChangePasswordResponse(BaseModel):
    success: bool
    message: str

# Modelo para respuestas de error
class ChangePasswordError(BaseModel):
    success: bool
    message: str

class MigrationResponse(BaseModel):
    success: bool
    message: str
    users_migrated: Optional[int] = None
    questions_migrated: Optional[int] = None
    payments_migrated: Optional[int] = None

class BackupCodesRequest(BaseModel):
    user_id: int
    password: str

# Modelo para la respuesta exitosa
class BackupCodesResponse(BaseModel):
    success: bool
    codes: List[str]
    message: Optional[str] = "Códigos de respaldo obtenidos correctamente"

# Modelo para respuestas de error
class BackupCodesError(BaseModel):
    success: bool
    message: str

class RegenerateCodesRequest(BaseModel):
    user_id: int
    password: str

# Modelo para la respuesta exitosa
class RegenerateCodesResponse(BaseModel):
    success: bool
    codes: List[str]
    message: str = "Códigos MFA regenerados correctamente"

# Modelo para respuestas de error
class RegenerateCodesError(BaseModel):
    success: bool
    message: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ForgotPasswordError(BaseModel):
    success: bool
    message: str

class ForgotPasswordResponse(BaseModel):
    success: bool
    email: str
    mfa_enabled: bool
    questions: SecurityQuestions
    message: Optional[str] = "Proceso de recuperación iniciado"

class VerifyAnswerRequest(BaseModel):
    email: str
    question: QuestionType
    answer: str

# Modelo para la respuesta exitosa
class VerifyAnswerResponse(BaseModel):
    success: bool
    requires_mfa: bool
    message: Optional[str] = "Respuesta verificada correctamente"

# Modelo para respuestas de error
class VerifyAnswerError(BaseModel):
    success: bool
    message: str

class VerifyMFARequest(BaseModel):
    email: str
    code: str

# Modelo para la respuesta exitosa
class VerifyMFAResponse(BaseModel):
    success: bool
    message: Optional[str] = "Código MFA verificado correctamente"

# Modelo para respuestas de error
class VerifyMFAError(BaseModel):
    success: bool
    message: str

class ResetPasswordRequest(BaseModel):
    email: str
    new_password: str

# Modelo para la respuesta exitosa
class ResetPasswordResponse(BaseModel):
    success: bool
    message: str = "Contraseña actualizada correctamente"

# Modelo para respuestas de error
class ResetPasswordError(BaseModel):
    success: bool
    message: str
    error: Optional[str] = None

class SupportRequest(BaseModel):
    email: EmailStr  # Validación automática de formato email
    message: str

# Modelo para la respuesta exitosa
class SupportResponse(BaseModel):
    success: bool
    message: str = "Ticket de soporte creado correctamente"
    ticket_id: Optional[int] = None

# Modelo para respuestas de error
class SupportError(BaseModel):
    success: bool
    message: str

class AuditLog(BaseModel):
    id: int
    user_id: Optional[int] = None
    email: Optional[str] = None
    action_type: str
    table_affected: str
    record_id: Optional[int] = None
    status: str
    ip_address: str
    created_at: datetime

# Modelo para la respuesta paginada
class AuditLogsResponse(BaseModel):
    success: bool
    logs: List[AuditLog]
    message: Optional[str] = "Logs de auditoría obtenidos correctamente"

# Modelo para respuestas de error
class AuditLogsError(BaseModel):
    success: bool
    message: str

class LoginLog(BaseModel):
    id: int
    user_id: Optional[int] = None
    email: str
    ip_address: str
    status: str
    mfa_used: bool
    created_at: datetime

# Modelo para la respuesta paginada
class LoginLogsResponse(BaseModel):
    success: bool
    logins: List[LoginLog]
    message: Optional[str] = "Logs de inicio de sesión obtenidos correctamente"

# Modelo para respuestas de error
class LoginLogsError(BaseModel):
    success: bool
    message: str

class RecentActivity(BaseModel):
    action_type: str
    created_at: datetime
    email: Optional[str] = None
    status: str

# Modelo para estadísticas
class AuditStats(BaseModel):
    total_users: int
    successful_logins: int
    failed_logins: int
    errors: int
    total_appointments: int

# Modelo para la respuesta
class AuditStatsResponse(BaseModel):
    success: bool
    stats: AuditStats
    recent_activity: List[RecentActivity]
    message: Optional[str] = "Estadísticas obtenidas correctamente"

# Modelo para respuestas de error
class AuditStatsError(BaseModel):
    success: bool
    message: str





    









# Funciones auxiliares
def get_db_connection():
    conn = pyodbc.connect(
        f"DRIVER={DB_CONFIG['driver']};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']}"
    )
    return conn

def encrypt(text: str) -> str:
    if not text:
        return text
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt(encrypted_text: str) -> str:
    if not encrypted_text:
        return encrypted_text
    try:
        return cipher_suite.decrypt(encrypted_text.encode()).decode()
    except:
        return encrypted_text

def validate_password(password: str, first_name: str, last_name: str) -> dict:
    if len(password) < 12:
        return {"valid": False, "message": "La contraseña debe tener al menos 12 caracteres"}
    
    if not any(c.isupper() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra mayúscula"}
    
    if not any(c.islower() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra minúscula"}
    
    if not any(c.isdigit() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un número"}
    
    if not any(c in "!@#$%^&*" for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un símbolo (!@#$%^&*)"}
    
    name_parts = [part.lower() for part in first_name.split() + last_name.split() if len(part) > 2]
    for part in name_parts:
        if part in password.lower():
            return {"valid": False, "message": "La contraseña no puede ser similar a tu nombre"}
    
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'contraseña', 'password123']
    if any(common in password.lower() for common in common_passwords):
        return {"valid": False, "message": "La contraseña es demasiado común"}
    
    return {"valid": True}

def generate_backup_codes(count: int = 10) -> List[str]:
    return [secrets.token_hex(4).upper()[:8] for _ in range(count)]

def generate_temp_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=10)
    payload = {
        "sub": str(user_id),
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_temp_token(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload.get("sub"))
    except jwt.PyJWTError:
        return None

async def verify_backup_code(user_id: int, code: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT code FROM MFABackupCodes WHERE userId = ? AND isUsed = 0",
            user_id
        )
        codes = cursor.fetchall()
        
        for stored_code in codes:
            if bcrypt.checkpw(code.encode(), decrypt(stored_code[0]).encode()):
                cursor.execute(
                    "UPDATE MFABackupCodes SET isUsed = 1 WHERE userId = ? AND code = ?",
                    user_id, stored_code[0]
                )
                conn.commit()
                return True
        return False
    except Exception as e:
        print(f"Error verifying backup code: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

async def log_login_attempt(email: str, user_id: Optional[int], ip: str, user_agent: str, status: str, mfa_used: bool = False, error: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO LoginAudits (userId, email, ipAddress, userAgent, status, mfaUsed, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
            user_id, email, ip, user_agent, status, mfa_used, error
        )
        conn.commit()
    except Exception as e:
        print(f"Error registrando intento de login: {e}")
    finally:
        cursor.close()
        conn.close()


def validate_password(password: str, first_name: str, last_name: str) -> Dict[str, Any]:
    """Valida que la contraseña cumpla con los requisitos de seguridad"""
    if len(password) < 12:
        return {"valid": False, "message": "La contraseña debe tener al menos 12 caracteres"}
    
    if not any(c.isupper() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra mayúscula"}
    
    if not any(c.islower() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra minúscula"}
    
    if not any(c.isdigit() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un número"}
    
    if not any(c in "!@#$%^&*" for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un símbolo (!@#$%^&*)"}
    
    name_parts = [part.lower() for part in [first_name, last_name] if len(part) > 2]
    for part in name_parts:
        if part in password.lower():
            return {"valid": False, "message": "La contraseña no puede ser similar a tu nombre"}
    
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'contraseña']
    if any(common in password.lower() for common in common_passwords):
        return {"valid": False, "message": "La contraseña es demasiado común"}
    
    return {"valid": True}

# Función para generar códigos de respaldo
def generate_backup_codes(count: int = 10) -> List[str]:
    """Genera códigos de respaldo para MFA"""
    import secrets
    import string
    return [''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(count))]

async def verify_backup_code(user_id: int, code: str) -> bool:
    """
    Verifica si un código de respaldo MFA es válido para el usuario.
    
    Args:
        user_id: ID del usuario
        code: Código a verificar
    
    Returns:
        bool: True si el código es válido y no ha sido usado
    """
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Buscar código no usado
        cursor.execute(
            """
            SELECT id, code FROM MFABackupCodes 
            WHERE userId = ? AND isUsed = 0
            """,
            user_id
        )
        codes = cursor.fetchall()

        for db_code in codes:
            try:
                decrypted_code = decrypt(db_code.code)
                if decrypted_code == code:
                    # Marcar código como usado
                    cursor.execute(
                        "UPDATE MFABackupCodes SET isUsed = 1 WHERE id = ?",
                        db_code.id
                    )
                    conn.commit()
                    return True
            except Exception as e:
                print(f"Error desencriptando código: {e}")
                continue

        return False

    except Exception as e:
        print(f"Error verificando código MFA: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def validate_password(password: str, first_name: str, last_name: str) -> dict:
    """Valida que la contraseña cumpla con los requisitos de seguridad"""
    if len(password) < 12:
        return {"valid": False, "message": "La contraseña debe tener al menos 12 caracteres"}
    
    if not any(c.isupper() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra mayúscula"}
    
    if not any(c.islower() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos una letra minúscula"}
    
    if not any(c.isdigit() for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un número"}
    
    if not any(c in "!@#$%^&*" for c in password):
        return {"valid": False, "message": "La contraseña debe contener al menos un símbolo (!@#$%^&*)"}
    
    name_parts = [part.lower() for part in [first_name, last_name] if len(part) > 2]
    for part in name_parts:
        if part in password.lower():
            return {"valid": False, "message": "La contraseña no puede ser similar a tu nombre"}
    
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'contraseña']
    if any(common in password.lower() for common in common_passwords):
        return {"valid": False, "message": "La contraseña es demasiado común"}
    
    return {"valid": True}













# Endpoints
@app.get("/")
async def root():
    return FileResponse("public/index.html")



@app.get("/login")
async def login_page():
    file_path = "public/login.html"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Login page not found")
    return FileResponse(file_path)
@app.post("/api/login")
async def login(login_data: LoginRequest, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Buscar usuario por email
        cursor.execute("SELECT * FROM Users WHERE isActive = 1")
        users = cursor.fetchall()
        
        user = None
        for u in users:
            try:
                if decrypt(u.email) == login_data.email:
                    user = u
                    break
            except:
                continue
        
        if not user:
            await log_login_attempt(login_data.email, None, ip, user_agent, "failed")
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        # Verificar contraseña
        password_match = bcrypt.checkpw(login_data.password.encode(), user.password.encode())
        if not password_match:
            await log_login_attempt(login_data.email, user.id, ip, user_agent, "failed")
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        # Desencriptar datos del usuario
        decrypted_user = {
            "id": user.id,
            "email": decrypt(user.email),
            "firstName": user.firstName,
            "lastName": user.lastName,
            "userType": user.userType,
            "mfaEnabled": user.mfaEnabled
        }
        
        # Si tiene MFA habilitado
        if user.mfaEnabled:
            temp_token = generate_temp_token(user.id)
            await log_login_attempt(login_data.email, user.id, ip, user_agent, "mfa_required")
            return {
                "success": True,
                "requiresMFA": True,
                "tempToken": temp_token,
                "message": "Por favor ingresa tu código MFA"
            }
        
        # Registrar login exitoso
        await log_login_attempt(login_data.email, user.id, ip, user_agent, "success")
        
        return {
            "success": True,
            "user": decrypted_user,
            "requiresMFA": False
        }
        
    except Exception as e:
        print(f"Error en el login: {e}")
        await log_login_attempt(login_data.email, None, ip, user_agent, "error", False, str(e))
        raise HTTPException(status_code=500, detail="Error en el servidor")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/verify-mfa")
async def verify_mfa(data: dict):
    temp_token = data.get("tempToken")
    code = data.get("code")
    
    if not temp_token or not code:
        raise HTTPException(status_code=400, detail="Token temporal y código son requeridos")
    
    user_id = verify_temp_token(temp_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
    
    code_valid = await verify_backup_code(user_id, code)
    if not code_valid:
        raise HTTPException(status_code=401, detail="Código MFA inválido")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "SELECT id, email, firstName, lastName, userType FROM Users WHERE id = ? AND isActive = 1",
            user_id
        )
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        decrypted_user = {
            "id": user.id,
            "email": decrypt(user.email),
            "firstName": user.firstName,
            "lastName": user.lastName,
            "userType": user.userType
        }
        
        return {
            "success": True,
            "user": decrypted_user,
            "message": "Autenticación MFA exitosa"
        }
    except Exception as e:
        print(f"Error verificando MFA: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    finally:
        cursor.close()
        conn.close()

@app.get("/api/user-profile/{user_id}", response_model=UserProfile)
async def get_user_profile(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT id, email, firstName, lastName, userType, phone, dateOfBirth, 
                   gender, profileImage, createdAt, updatedAt, bio, 
                   country_id, province_id, canton_id, district_id
            FROM Users 
            WHERE id = ? AND isActive = 1
            """,
            user_id
        )
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        user_dict = dict(zip([column[0] for column in cursor.description], user))
        user_dict["bio"] = user_dict["bio"] or ""
        user_dict["email"] = decrypt(user_dict["email"])
        
        return user_dict
    except Exception as e:
        print(f"Error obteniendo perfil: {e}")
        raise HTTPException(status_code=500, detail="Error al obtener perfil")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/update-profile")
async def update_profile(
    user_id: int = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    date_of_birth: str = Form(...),
    gender: str = Form(...),
    bio: str = Form(...),
    country_id: str = Form(...),
    province_id: str = Form(None),
    canton_id: str = Form(None),
    district_id: str = Form(None),
    profile_image: UploadFile = File(None)
):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar si el email ya existe
        cursor.execute(
            "SELECT id FROM Users WHERE email = ? AND id != ?",
            encrypt(email), user_id
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El correo electrónico ya está en uso por otro usuario")
        
        profile_image_path = None
        if profile_image:
            # Guardar la imagen
            file_ext = os.path.splitext(profile_image.filename)[1]
            filename = f"{uuid.uuid4()}{file_ext}"
            file_path = os.path.join("public/uploads/profile-images", filename)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as buffer:
                buffer.write(profile_image.file.read())
            
            profile_image_path = f"/uploads/profile-images/{filename}"
        
        # Construir la consulta de actualización
        update_fields = [
            "firstName = ?", "lastName = ?", "email = ?", "phone = ?",
            "dateOfBirth = ?", "gender = ?", "bio = ?", "country_id = ?",
            "province_id = ?", "canton_id = ?", "district_id = ?",
            "updatedAt = GETDATE()"
        ]
        params = [
            first_name, last_name, encrypt(email), phone,
            date_of_birth, gender, bio, country_id,
            province_id, canton_id, district_id
        ]
        
        if profile_image_path:
            update_fields.append("profileImage = ?")
            params.append(profile_image_path)
        
        params.append(user_id)
        
        query = f"UPDATE Users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, params)
        conn.commit()
        
        return {
            "success": True,
            "message": "Perfil actualizado correctamente",
            "profileImage": profile_image_path
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error actualizando perfil: {e}")
        raise HTTPException(status_code=500, detail="Error al actualizar el perfil")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/register")
async def register(register_data: RegisterRequest):
    # Validaciones
    if not all([register_data.firstName, register_data.lastName, register_data.email, 
                register_data.password, register_data.userType, register_data.countryId]):
        raise HTTPException(status_code=400, detail="Todos los campos son requeridos")
    
    if register_data.userType not in ["patient", "psychologist"]:
        raise HTTPException(status_code=400, detail="Tipo de usuario no válido")
    
    name_regex = r"^[a-zA-Z0-9_.]{5,}$"
    if not (re.match(name_regex, register_data.firstName) and re.match(name_regex, register_data.lastName)):
        raise HTTPException(
            status_code=400,
            detail="El nombre y apellido deben tener al menos 5 caracteres y solo pueden contener letras, números, _ y ."
        )
    
    password_validation = validate_password(
        register_data.password, 
        register_data.firstName, 
        register_data.lastName
    )
    if not password_validation["valid"]:
        raise HTTPException(status_code=400, detail=password_validation["message"])
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar si el email ya existe
        cursor.execute(
            "SELECT id FROM Users WHERE email = ?",
            encrypt(register_data.email)
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="El correo electrónico ya está registrado")
        
        # Hashear la contraseña
        hashed_password = bcrypt.hashpw(register_data.password.encode(), bcrypt.gensalt(12)).decode()
        
        # Insertar nuevo usuario
        cursor.execute(
            """
            INSERT INTO Users 
                (firstName, lastName, email, password, userType, 
                 country_id, province_id, canton_id, district_id, isActive, is_encrypted)
            OUTPUT INSERTED.id
            VALUES 
                (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
            """,
            (
                register_data.firstName, register_data.lastName, encrypt(register_data.email),
                hashed_password, register_data.userType, register_data.countryId,
                register_data.provinceId, register_data.cantonId, register_data.districtId
            )
        )
        new_user_id = cursor.fetchone()[0]
        
        # Generar y guardar códigos de respaldo MFA
        backup_codes = generate_backup_codes()
        for code in backup_codes:
            cursor.execute(
                "INSERT INTO MFABackupCodes (userId, code, isUsed, is_encrypted) VALUES (?, ?, 0, 1)",
                new_user_id, encrypt(code)
            )
        
        conn.commit()
        
        return {
            "success": True,
            "userId": new_user_id,
            "userType": register_data.userType,
            "nextStep": "security-questions",
            "backupCodes": backup_codes
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error en el registro: {e}")
        raise HTTPException(status_code=500, detail="Error en el servidor al registrar usuario")
    finally:
        cursor.close()
        conn.close()

@app.post("/api/security-questions")
async def save_security_questions(user_id: int, questions: SecurityQuestions):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            INSERT INTO SecurityQuestions 
                (userId, petName, favoriteColor, favoritePlace)
            VALUES 
                (?, ?, ?, ?)
            """,
            (
                user_id, 
                encrypt(questions.petName), 
                encrypt(questions.favoriteColor), 
                encrypt(questions.favoritePlace)
            )
        )
        conn.commit()
        
        return {"success": True, "message": "Preguntas de seguridad guardadas correctamente"}
    except Exception as e:
        print(f"Error al guardar preguntas de seguridad: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Error en el servidor al guardar preguntas de seguridad"
        )
    finally:
        cursor.close()
        conn.close()

@app.get("/api/security-questions/{user_id}", response_model=SecurityQuestions)
async def get_security_questions(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """
            SELECT petName, favoriteColor, favoritePlace 
            FROM SecurityQuestions 
            WHERE userId = ?
            """,
            user_id
        )
        questions = cursor.fetchone()
        
        if not questions:
            raise HTTPException(status_code=404, detail="No se encontraron preguntas")
        
        return {
            "petName": decrypt(questions.petName),
            "favoriteColor": decrypt(questions.favoriteColor),
            "favoritePlace": decrypt(questions.favoritePlace)
        }
    except Exception as e:
        print(f"Error obteniendo preguntas de seguridad: {e}")
        raise HTTPException(
            status_code=500, 
            detail="Error al obtener preguntas de seguridad"
        )
    finally:
        cursor.close()
        conn.close()

@app.get("/api/user-profile/{user_id}", response_model=UserProfileResponse)
async def get_user_profile(
    user_id: int = Path(..., title="El ID del usuario", gt=0)
):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                id, email, firstName, lastName, userType,
                phone, dateOfBirth, gender, profileImage,
                createdAt, updatedAt, bio,
                country_id, province_id, canton_id, district_id
            FROM Users 
            WHERE id = ? AND isActive = 1
        """, user_id)
        
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(
                status_code=404,
                detail="Usuario no encontrado"
            )
        
        columns = [column[0] for column in cursor.description]
        user_data = dict(zip(columns, row))
        
        user_data['bio'] = user_data.get('bio') or ''
        
        if 'email' in user_data:
            user_data['email'] = decrypt(user_data['email'])
        
        return user_data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error obteniendo perfil: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error al obtener perfil"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/update-mfa")
async def update_mfa(request: UpdateMFARequest):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            UPDATE Users 
            SET mfaEnabled = ?, updatedAt = GETDATE()
            WHERE id = ?
            """,
            request.enable, request.userId
        )
        conn.commit()
        
        action = "activado" if request.enable else "desactivado"
        
        return {
            "success": True,
            "message": f"MFA {action} correctamente"
        }
        
    except Exception as e:
        print(f"Error actualizando MFA: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al actualizar MFA"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/locations/countries", response_model=List[Country])
async def get_countries():
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, description, code 
            FROM GeographicLocations 
            WHERE type = 'Pais' 
            ORDER BY description
            """
        )
        
        countries = cursor.fetchall()
        
        columns = [column[0] for column in cursor.description]
        result = [dict(zip(columns, row)) for row in countries]
        
        return result
        
    except Exception as e:
        print(f"Error obteniendo países: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error obteniendo países"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/locations/provinces/{country_id}", response_model=List[Province])
async def get_provinces(country_id: str = Path(..., description="ID del país para filtrar provincias")):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, description, code 
            FROM GeographicLocations 
            WHERE type = 'Provincia' AND parent_id = ?
            ORDER BY description
            """,
            country_id
        )
        
        provinces = []
        columns = [column[0] for column in cursor.description]
        for row in cursor.fetchall():
            province = dict(zip(columns, row))
            provinces.append(province)
        
        return provinces
        
    except Exception as e:
        print(f"Error obteniendo provincias: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error obteniendo provincias"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/locations/cantons/{province_id}", response_model=List[Canton])
async def get_cantons(province_id: str = Path(..., description="ID de la provincia para filtrar cantones")):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, description, code 
            FROM GeographicLocations 
            WHERE type = 'Canton' AND parent_id = ?
            ORDER BY description
            """,
            province_id
        )
        
        columns = [column[0] for column in cursor.description]
        cantons = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return cantons
        
    except Exception as e:
        print(f"Error obteniendo cantones: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error obteniendo cantones"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/locations/districts/{canton_id}", 
         response_model=List[District],
         summary="Obtener distritos por cantón",
         description="Recupera todos los distritos pertenecientes a un cantón específico",
         tags=["Ubicaciones Geográficas"])
async def get_districts(canton_id: str = Path(..., 
                        description="ID del cantón para filtrar distritos",
                        example="101")):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, description, code 
            FROM GeographicLocations 
            WHERE type = 'Distrito' AND parent_id = ?
            ORDER BY description
            """,
            canton_id
        )
        
        columns = [column[0] for column in cursor.description]
        districts = [
            District(**dict(zip(columns, row)))
            for row in cursor.fetchall()
        ]
        
        return districts
        
    except pyodbc.Error as db_error:
        print(f"Error de base de datos al obtener distritos: {db_error}")
        raise HTTPException(
            status_code=500,
            detail="Error en la base de datos al recuperar distritos"
        )
    except Exception as e:
        print(f"Error inesperado al obtener distritos: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor al procesar la solicitud"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/update-location",
          summary="Actualizar ubicación del usuario",
          description="Actualiza la información geográfica (país, provincia, cantón y distrito) de un usuario",
          tags=["Usuarios"])
async def update_location(location_data: UpdateLocationRequest):
    if not location_data.userId or not location_data.countryId:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Se requieren ID de usuario y país"
            }
        )

    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        query = """
            UPDATE Users 
            SET 
                country_id = ?,
                province_id = ?,
                canton_id = ?,
                district_id = ?,
                updatedAt = GETDATE()
            WHERE id = ?
        """
        
        params = (
            location_data.countryId,
            location_data.provinceId,
            location_data.cantonId,
            location_data.districtId,
            location_data.userId
        )
        
        cursor.execute(query, params)
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )
        
        return {
            "success": True,
            "message": "Ubicación actualizada correctamente"
        }
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al actualizar ubicación: {db_error}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en la base de datos al actualizar ubicación"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error inesperado al actualizar ubicación: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error interno del servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/payment-methods/{user_id}", 
         response_model=List[PaymentMethod],
         summary="Obtener métodos de pago",
         description="Recupera todos los métodos de pago de un usuario, con datos sensibles enmascarados",
         tags=["Métodos de Pago"])
async def get_payment_methods(
    user_id: int = Path(..., title="ID del usuario", gt=0)
):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT id, cardNumber, cardHolder, expirationMonth, 
                   expirationYear, cvv, balance, isDefault
            FROM UserPaymentMethods 
            WHERE userId = ?
            """,
            user_id
        )
        
        payment_methods = []
        columns = [column[0] for column in cursor.description]
        
        for row in cursor.fetchall():
            card_data = dict(zip(columns, row))
            
            try:
                decrypted_card = {
                    'id': card_data['id'],
                    'cardNumber': decrypt(card_data['cardNumber']),
                    'cardHolder': decrypt(card_data['cardHolder']),
                    'expirationMonth': card_data['expirationMonth'],
                    'expirationYear': card_data['expirationYear'],
                    'balance': card_data['balance'],
                    'isDefault': card_data['isDefault']
                }
                
                sanitized_card = {
                    **decrypted_card,
                    'cardNumber': f"**** **** **** {decrypted_card['cardNumber'][-4:]}",
                    'cvv': '***'
                }
                
                payment_methods.append(sanitized_card)
                
            except Exception as decrypt_error:
                print(f"Error desencriptando datos de tarjeta: {decrypt_error}")
                continue
        
        return payment_methods
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos: {db_error}")
        raise HTTPException(
            status_code=500,
            detail="Error al obtener métodos de pago desde la base de datos"
        )
    except Exception as e:
        print(f"Error inesperado: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/payment-methods",
          response_model=AddPaymentMethodResponse,
          summary="Agregar método de pago",
          description="Agrega un nuevo método de pago para un usuario, encriptando datos sensibles",
          tags=["Métodos de Pago"])
async def add_payment_method(payment_data: AddPaymentMethodRequest):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        encrypted_card = {
            'number': encrypt(payment_data.cardNumber.replace(" ", "")),
            'holder': encrypt(payment_data.cardHolder),
            'cvv': encrypt(payment_data.cvv)
        }
        
        cursor.execute(
            """
            INSERT INTO UserPaymentMethods 
                (userId, cardNumber, cardHolder, expirationMonth, 
                 expirationYear, cvv, balance, is_encrypted)
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                payment_data.userId,
                encrypted_card['number'],
                encrypted_card['holder'],
                payment_data.expirationMonth,
                payment_data.expirationYear,
                encrypted_card['cvv'],
                payment_data.balance
            )
        )
        
        new_id = cursor.fetchone()[0]
        conn.commit()
        
        return {
            "success": True,
            "message": "Método de pago agregado",
            "cardId": new_id
        }
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al agregar método de pago: {db_error}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al agregar método de pago en la base de datos"
            }
        )
    except Exception as e:
        print(f"Error inesperado al agregar método de pago: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error interno del servidor al procesar la solicitud"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.put("/api/payment-methods/{card_id}", 
         summary="Actualizar método de pago",
         description="Actualiza la información de un método de pago existente",
         tags=["Métodos de Pago"])
async def update_payment_method(
    card_id: int = Path(..., title="ID de la tarjeta", gt=0),
    update_data: UpdatePaymentMethodRequest = None
):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            """
            UPDATE UserPaymentMethods 
            SET 
                cardHolder = ?,
                expirationMonth = ?,
                expirationYear = ?,
                updatedAt = GETDATE()
            WHERE id = ?
            """,
            (
                encrypt(update_data.cardHolder),
                update_data.expirationMonth,
                update_data.expirationYear,
                card_id
            )
        )
        
        if update_data.isDefault:
            cursor.execute(
                "SELECT userId FROM UserPaymentMethods WHERE id = ?",
                card_id
            )
            user_row = cursor.fetchone()
            
            if not user_row:
                raise HTTPException(
                    status_code=404,
                    detail={
                        "success": False,
                        "message": "Método de pago no encontrado"
                    }
                )
            
            user_id = user_row[0]
            
            cursor.execute(
                """
                UPDATE UserPaymentMethods 
                SET isDefault = 0 
                WHERE userId = ? AND id != ?
                """,
                (user_id, card_id)
            )
            
            cursor.execute(
                """
                UPDATE UserPaymentMethods 
                SET isDefault = 1 
                WHERE id = ?
                """,
                card_id
            )
        
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Método de pago no encontrado"
                }
            )
        
        return {
            "success": True,
            "message": "Método de pago actualizado correctamente"
        }
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al actualizar método de pago: {db_error}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en la base de datos al actualizar método de pago"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error inesperado al actualizar método de pago: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error interno del servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.delete("/api/payment-methods/{card_id}", 
           response_model=DeletePaymentMethodResponse,
           summary="Eliminar método de pago",
           description="Elimina un método de pago y maneja la reasignación de tarjeta predeterminada si es necesario",
           tags=["Métodos de Pago"])
async def delete_payment_method(
    card_id: int = Path(..., title="ID de la tarjeta", gt=0)
):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT isDefault, userId FROM UserPaymentMethods WHERE id = ?",
            card_id
        )
        card_data = cursor.fetchone()
        
        if not card_data:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Método de pago no encontrado"
                }
            )
        
        is_default = card_data.isDefault
        user_id = card_data.userId
        
        cursor.execute(
            "DELETE FROM UserPaymentMethods WHERE id = ?",
            card_id
        )
        
        new_default_card = None
        
        if is_default:
            cursor.execute(
                """
                SELECT TOP 1 id 
                FROM UserPaymentMethods 
                WHERE userId = ? 
                ORDER BY createdAt DESC
                """,
                user_id
            )
            other_card = cursor.fetchone()
            
            if other_card:
                cursor.execute(
                    """
                    UPDATE UserPaymentMethods 
                    SET isDefault = 1 
                    WHERE id = ?
                    """,
                    other_card.id
                )
                new_default_card = other_card.id
        
        conn.commit()
        
        response_data = {
            "success": True,
            "message": "Método de pago eliminado correctamente"
        }
        
        if new_default_card is not None:
            response_data["new_default_card"] = new_default_card
        
        return response_data
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al eliminar método de pago: {db_error}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en la base de datos al eliminar método de pago"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error inesperado al eliminar método de pago: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error interno del servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/psychologists", 
         response_model=List[PsychologistProfile],
         summary="Obtener lista de psicólogos",
         description="Recupera una lista de todos los psicólogos activos en la plataforma",
         tags=["Psicólogos"])
async def get_psychologists():
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                p.id, 
                p.userId as user_id,
                u.firstName as first_name,
                u.lastName as last_name,
                p.licenseNumber as license_number,
                p.specialties,
                p.experience,
                p.education,
                p.languages,
                p.hourlyRate as hourly_rate,
                p.bio,
                p.availability,
                p.rating,
                p.totalReviews as total_reviews,
                p.isVerified as is_verified,
                u.profileImage as profile_image,
                p.createdAt as created_at,
                p.updatedAt as updated_at
            FROM PsychologistProfiles p
            JOIN Users u ON p.userId = u.id
            WHERE u.isActive = 1
        """)
        
        psychologists = []
        columns = [column[0] for column in cursor.description]
        
        for row in cursor.fetchall():
            psychologist_data = dict(zip(columns, row))
            
            if psychologist_data.get('languages'):
                psychologist_data['languages'] = psychologist_data['languages'].split(',')
            else:
                psychologist_data['languages'] = []
                
            psychologists.append(psychologist_data)
        
        return psychologists
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al obtener psicólogos: {db_error}")
        raise HTTPException(
            status_code=500,
            detail="Error al obtener psicólogos desde la base de datos"
        )
    except Exception as e:
        print(f"Error inesperado al obtener psicólogos: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/psychologists/filter", 
         response_model=List[FilteredPsychologist],
         summary="Filtrar psicólogos",
         description="Filtra psicólogos por especialidad, idioma y precio máximo",
         tags=["Psicólogos"])
async def filter_psychologists(
    specialty: Optional[str] = Query(None, description="Especialidad a filtrar"),
    language: Optional[str] = Query(None, description="Idioma a filtrar"),
    max_price: Optional[float] = Query(None, description="Precio máximo por hora")
):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        query = """
            SELECT 
                p.id, 
                p.userId as user_id,
                u.firstName as first_name,
                u.lastName as last_name,
                p.specialties,
                p.languages,
                p.hourlyRate as hourly_rate,
                p.rating,
                p.totalReviews as total_reviews,
                u.profileImage as profile_image
            FROM PsychologistProfiles p
            JOIN Users u ON p.userId = u.id
            WHERE u.isActive = 1
        """
        
        params = []
        
        if specialty:
            query += " AND p.specialties LIKE ?"
            params.append(f"%{specialty}%")
        
        if language:
            query += " AND p.languages LIKE ?"
            params.append(f"%{language}%")
        
        if max_price is not None:
            query += " AND p.hourlyRate <= ?"
            params.append(max_price)
        
        cursor.execute(query, params)
        
        psychologists = []
        columns = [column[0] for column in cursor.description]
        
        for row in cursor.fetchall():
            psychologist_data = dict(zip(columns, row))
            
            if psychologist_data.get('languages'):
                psychologist_data['languages'] = psychologist_data['languages'].split(',')
            else:
                psychologist_data['languages'] = []
                
            psychologists.append(psychologist_data)
        
        return psychologists
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al filtrar psicólogos: {db_error}")
        raise HTTPException(
            status_code=500,
            detail="Error al filtrar psicólogos desde la base de datos"
        )
    except Exception as e:
        print(f"Error inesperado al filtrar psicólogos: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/psychologists/{psychologist_id}",
         response_model=PsychologistDetail,
         summary="Obtener detalles de un psicólogo",
         description="Obtiene la información detallada de un psicólogo específico",
         tags=["Psicólogos"])
async def get_psychologist(
    psychologist_id: int = Path(..., title="ID del psicólogo", gt=0)
):
    conn = None
    cursor = None
    try:
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                p.id, 
                p.userId as user_id,
                u.firstName as first_name,
                u.lastName as last_name,
                p.licenseNumber as license_number,
                p.specialties,
                p.experience,
                p.education,
                p.languages,
                p.hourlyRate as hourly_rate,
                p.bio,
                p.availability,
                p.rating,
                p.totalReviews as total_reviews,
                p.isVerified as is_verified,
                u.profileImage as profile_image,
                u.country_id,
                u.province_id,
                u.canton_id,
                u.district_id
            FROM PsychologistProfiles p
            JOIN Users u ON p.userId = u.id
            WHERE p.id = ? AND u.isActive = 1
        """, psychologist_id)
        
        psychologist = cursor.fetchone()
        
        if not psychologist:
            raise HTTPException(
                status_code=404,
                detail="Psicólogo no encontrado"
            )
        
        columns = [column[0] for column in cursor.description]
        psychologist_data = dict(zip(columns, psychologist))
        
        if psychologist_data.get('specialties'):
            psychologist_data['specialties'] = psychologist_data['specialties'].split(',')
        else:
            psychologist_data['specialties'] = []
            
        if psychologist_data.get('languages'):
            psychologist_data['languages'] = psychologist_data['languages'].split(',')
        else:
            psychologist_data['languages'] = []
        
        return psychologist_data
        
    except pyodbc.DatabaseError as db_error:
        print(f"Error de base de datos al obtener psicólogo: {db_error}")
        raise HTTPException(
            status_code=500,
            detail="Error al obtener psicólogo desde la base de datos"
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error inesperado al obtener psicólogo: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor"
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/register",
         response_model=RegisterResponse,
         responses={
             400: {"model": ErrorResponse, "description": "Validación fallida"},
             500: {"model": ErrorResponse, "description": "Error del servidor"}
         },
         summary="Registrar nuevo usuario",
         description="Endpoint para el registro de nuevos usuarios (pacientes o psicólogos)",
         tags=["Autenticación"])
async def register_user(user_data: RegisterRequest):
    """
    Registra un nuevo usuario en el sistema.
    
    Realiza validaciones de:
    - Campos requeridos
    - Formato de nombre
    - Fortaleza de contraseña
    - Email único
    
    Para usuarios válidos:
    - Encripta datos sensibles
    - Genera códigos MFA de respaldo
    - Retorna información para el siguiente paso
    """
    
    # Validaciones básicas
    if not all([user_data.first_name, user_data.last_name, user_data.email,
                user_data.password, user_data.user_type, user_data.country_id]):
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Todos los campos son requeridos"
            }
        )

    # Validar tipo de usuario
    if user_data.user_type not in ["patient", "psychologist"]:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Tipo de usuario no válido"
            }
        )

    # Validar nombre (backend)
    name_regex = r"^[a-zA-Z0-9_.]{5,}$"
    if not (re.match(name_regex, user_data.first_name) and re.match(name_regex, user_data.last_name)):
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "El nombre y apellido deben tener al menos 5 caracteres y solo pueden contener letras, números, _ y ."
            }
        )

    # Validar contraseña
    password_validation = validate_password(
        user_data.password,
        user_data.first_name,
        user_data.last_name
    )
    if not password_validation["valid"]:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": password_validation["message"]
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Verificar email único
        cursor.execute(
            "SELECT id FROM Users WHERE email = ?",
            encrypt(user_data.email)
        )
        if cursor.fetchone():
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": "El correo electrónico ya está registrado"
                }
            )

        # Hashear contraseña
        hashed_pw = bcrypt.hashpw(
            user_data.password.encode(),
            bcrypt.gensalt(12)
        ).decode()

        # Insertar usuario
        cursor.execute(
            """
            INSERT INTO Users 
                (firstName, lastName, email, password, userType, 
                 country_id, province_id, canton_id, district_id, isActive, is_encrypted)
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
            """,
            (
                user_data.first_name,
                user_data.last_name,
                encrypt(user_data.email),
                hashed_pw,
                user_data.user_type,
                user_data.country_id,
                user_data.province_id,
                user_data.canton_id,
                user_data.district_id
            )
        )
        new_user_id = cursor.fetchone()[0]

        # Generar y guardar códigos MFA
        backup_codes = generate_backup_codes()
        for code in backup_codes:
            cursor.execute(
                "INSERT INTO MFABackupCodes (userId, code, isUsed, is_encrypted) VALUES (?, ?, 0, 1)",
                (new_user_id, encrypt(code))
            )

        conn.commit()

        return {
            "success": True,
            "user_id": new_user_id,
            "user_type": user_data.user_type,
            "next_step": "security-questions",
            "backup_codes": backup_codes,
            "message": "Registro exitoso"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error en el registro: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor al registrar usuario"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/security-questions",
         response_model=SecurityQuestionsResponse,
         responses={
             500: {"model": SecurityQuestionsResponse, "description": "Error del servidor"}
         },
         summary="Guardar preguntas de seguridad",
         description="Endpoint para almacenar las preguntas de seguridad de un usuario",
         tags=["Autenticación"])
async def save_security_questions(questions: SecurityQuestionsRequest):
    """
    Guarda las preguntas de seguridad de un usuario en la base de datos.
    
    Los datos se almacenan encriptados para mayor seguridad.
    
    Parámetros:
    - user_id: ID del usuario
    - pet_name: Nombre de mascota (respuesta)
    - favorite_color: Color favorito (respuesta)
    - favorite_place: Lugar favorito (respuesta)
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo del resultado
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        # Insertar preguntas de seguridad (encriptadas)
        cursor.execute(
            """
            INSERT INTO SecurityQuestions 
                (userId, petName, favoriteColor, favoritePlace)
            VALUES 
                (?, ?, ?, ?)
            """,
            (
                questions.user_id,
                encrypt(questions.pet_name),
                encrypt(questions.favorite_color),
                encrypt(questions.favorite_place)
            )
        )
        conn.commit()
        
        return {
            "success": True,
            "message": "Preguntas de seguridad guardadas correctamente"
        }
        
    except Exception as e:
        print(f"Error al guardar preguntas de seguridad: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor al guardar preguntas de seguridad"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/security-questions/{user_id}",
         response_model=SecurityQuestionsResponse,
         responses={
             404: {"model": SecurityQuestionsError, "description": "Preguntas no encontradas"},
             500: {"model": SecurityQuestionsError, "description": "Error del servidor"}
         },
         summary="Obtener preguntas de seguridad",
         description="Endpoint para recuperar las preguntas de seguridad de un usuario",
         tags=["Autenticación"])
async def get_security_questions(
    user_id: int = Path(..., title="ID del usuario", gt=0)
):
   
    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()
        
        # Obtener preguntas de seguridad
        cursor.execute(
            """
            SELECT petName, favoriteColor, favoritePlace 
            FROM SecurityQuestions 
            WHERE userId = ?
            """,
            user_id
        )
        questions = cursor.fetchone()
        
        if not questions:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "No se encontraron preguntas"
                }
            )
        
        # Desencriptar las respuestas
        decrypted_questions = {
            "pet_name": decrypt(questions.petName),
            "favorite_color": decrypt(questions.favoriteColor),
            "favorite_place": decrypt(questions.favoritePlace)
        }
        
        return {
            "success": True,
            "questions": decrypted_questions,
            "message": "Preguntas de seguridad obtenidas correctamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error obteniendo preguntas de seguridad: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al obtener preguntas de seguridad"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.post("/api/delete-account",
         response_model=DeleteAccountResponse,
         responses={
             400: {"model": DeleteAccountError, "description": "Datos faltantes"},
             401: {"model": DeleteAccountError, "description": "Credenciales inválidas"},
             500: {"model": DeleteAccountError, "description": "Error del servidor"}
         },
         summary="Eliminar cuenta de usuario",
         description="Endpoint para desactivar y eliminar una cuenta de usuario",
         tags=["Cuenta"])
async def delete_account(request: DeleteAccountRequest):
    """
    Elimina/desactiva una cuenta de usuario después de verificar las credenciales.
    
    Realiza las siguientes acciones:
    1. Verifica que el usuario existe y la contraseña es correcta
    2. Desactiva la cuenta (marca isActive = 0)
    3. Elimina datos relacionados (preguntas de seguridad, etc.)
    
    Parámetros:
    - user_id: ID del usuario a eliminar
    - password: Contraseña para verificación
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo del resultado
    """
    # Validación básica
    if not request.user_id or not request.password:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Se requieren ID de usuario y contraseña"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Verificar credenciales
        cursor.execute(
            """
            SELECT password FROM Users 
            WHERE id = ? AND isActive = 1
            """,
            request.user_id
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Credenciales incorrectas o cuenta no encontrada"
                }
            )

        # Verificar contraseña
        if not bcrypt.checkpw(request.password.encode(), user.password.encode()):
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Credenciales incorrectas o cuenta no encontrada"
                }
            )

        # 2. Desactivar la cuenta
        cursor.execute(
            """
            UPDATE Users 
            SET isActive = 0, updatedAt = GETDATE()
            WHERE id = ?
            """,
            request.user_id
        )

        # 3. Eliminar datos relacionados (con manejo de errores individual)
        related_tables = [
            "SecurityQuestions",
            "MFABackupCodes",
            "UserSessions"
            # Agregar más tablas según sea necesario
        ]

        for table in related_tables:
            try:
                cursor.execute(
                    f"DELETE FROM {table} WHERE userId = ?",
                    request.user_id
                )
            except Exception as e:
                print(f"Error eliminando datos de {table}: {e}")
                conn.rollback()
                continue

        conn.commit()

        return {
            "success": True,
            "message": "Cuenta desactivada correctamente. Todos tus datos han sido eliminados."
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error desactivando cuenta: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor al desactivar la cuenta"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/update-email",
         response_model=UpdateEmailResponse,
         responses={
             400: {"model": UpdateEmailError, "description": "Email ya en uso o inválido"},
             500: {"model": UpdateEmailError, "description": "Error del servidor"}
         },
         summary="Actualizar dirección de correo electrónico",
         description="Endpoint para cambiar la dirección de email de un usuario",
         tags=["Cuenta"])
async def update_email(request: UpdateEmailRequest):
    """
    Actualiza la dirección de correo electrónico de un usuario.
    
    Realiza las siguientes acciones:
    1. Verifica que el nuevo email no esté en uso por otro usuario
    2. Actualiza el email en la base de datos
    3. Envía un correo de verificación (lógica simulada)
    
    Parámetros:
    - user_id: ID del usuario
    - new_email: Nueva dirección de correo electrónico
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo del resultado
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Verificar si el nuevo email ya existe
        cursor.execute(
            """
            SELECT id FROM Users 
            WHERE email = ? AND id != ?
            """,
            encrypt(request.new_email),  # Asumiendo que los emails están encriptados
            request.user_id
        )
        
        if cursor.fetchone():
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": "El correo electrónico ya está en uso"
                }
            )

        # 2. Actualizar email
        cursor.execute(
            """
            UPDATE Users 
            SET email = ?, updatedAt = GETDATE()
            WHERE id = ?
            """,
            encrypt(request.new_email),  # Encriptar el nuevo email
            request.user_id
        )

        conn.commit()

        # 3. Lógica para enviar correo de verificación (simulada)
        # En una implementación real, aquí se llamaría a un servicio de email
        print(f"Email de verificación enviado a: {request.new_email}")

        return {
            "success": True,
            "message": "Correo electrónico actualizado. Se ha enviado un correo de verificación."
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error actualizando email: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error actualizando email"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/change-password",
         response_model=ChangePasswordResponse,
         responses={
             400: {"model": ChangePasswordError, "description": "Validación fallida"},
             401: {"model": ChangePasswordError, "description": "Credenciales inválidas"},
             500: {"model": ChangePasswordError, "description": "Error del servidor"}
         },
         summary="Cambiar contraseña",
         description="Endpoint para cambiar la contraseña de un usuario",
         tags=["Cuenta"])
async def change_password(request: ChangePasswordRequest):
    """
    Cambia la contraseña de un usuario después de validar:
    1. La contraseña actual
    2. Los requisitos de la nueva contraseña
    
    Parámetros:
    - user_id: ID del usuario
    - current_password: Contraseña actual para verificación
    - new_password: Nueva contraseña
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo del resultado
    """
    # Validación básica
    if not request.user_id or not request.current_password or not request.new_password:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Todos los campos son requeridos"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Obtener usuario y verificar contraseña actual
        cursor.execute(
            """
            SELECT id, firstName, lastName, password 
            FROM Users 
            WHERE id = ? AND isActive = 1
            """,
            request.user_id
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado o inactivo"
                }
            )

        # Verificar contraseña actual
        if not bcrypt.checkpw(request.current_password.encode(), user.password.encode()):
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Contraseña actual incorrecta"
                }
            )

        # 2. Validar nueva contraseña
        password_validation = validate_password(
            request.new_password,
            user.firstName,
            user.lastName
        )
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": password_validation["message"]
                }
            )

        # 3. Hashear y actualizar nueva contraseña
        hashed_new_password = bcrypt.hashpw(
            request.new_password.encode(),
            bcrypt.gensalt(12)
        ).decode()

        cursor.execute(
            """
            UPDATE Users 
            SET password = ?, updatedAt = GETDATE()
            WHERE id = ?
            """,
            hashed_new_password,
            request.user_id
        )

        conn.commit()

        return {
            "success": True,
            "message": "Contraseña actualizada correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error cambiando contraseña: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al cambiar contraseña"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/migrate-encryption",
         response_model=MigrationResponse,
         summary="Migrar datos a encriptación",
         description="Endpoint para migrar datos no encriptados a formato encriptado (solo desarrollo)",
         tags=["Administración"])
async def migrate_encryption():
    """
    Migra datos sensibles a formato encriptado.
    
    Solo disponible en entorno de desarrollo.
    Realiza tres migraciones:
    1. Emails de usuarios
    2. Preguntas de seguridad
    3. Métodos de pago
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo
    - stats: Cantidad de registros migrados por categoría
    """
    # Verificar entorno
    if os.getenv("ENVIRONMENT") != "development":
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "message": "Solo disponible en desarrollo"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        stats = {
            "users_migrated": 0,
            "questions_migrated": 0,
            "payments_migrated": 0
        }

        # 1. Migrar usuarios
        cursor.execute("SELECT id, email FROM Users WHERE is_encrypted = 0")
        users = cursor.fetchall()
        
        for user in users:
            cursor.execute(
                """
                UPDATE Users SET 
                    email = ?,
                    is_encrypted = 1
                WHERE id = ?
                """,
                encrypt(user.email),
                user.id
            )
            stats["users_migrated"] += 1

        # 2. Migrar preguntas de seguridad
        cursor.execute("SELECT userId, petName, favoriteColor, favoritePlace FROM SecurityQuestions")
        questions = cursor.fetchall()
        
        for q in questions:
            cursor.execute(
                """
                UPDATE SecurityQuestions SET
                    petName = ?,
                    favoriteColor = ?,
                    favoritePlace = ?
                WHERE userId = ?
                """,
                encrypt(q.petName),
                encrypt(q.favoriteColor),
                encrypt(q.favoritePlace),
                q.userId
            )
            stats["questions_migrated"] += 1

        # 3. Migrar métodos de pago
        cursor.execute("SELECT id, cardNumber, cardHolder, cvv FROM UserPaymentMethods WHERE is_encrypted = 0")
        payments = cursor.fetchall()
        
        for p in payments:
            cursor.execute(
                """
                UPDATE UserPaymentMethods SET
                    cardNumber = ?,
                    cardHolder = ?,
                    cvv = ?,
                    is_encrypted = 1
                WHERE id = ?
                """,
                encrypt(p.cardNumber),
                encrypt(p.cardHolder),
                encrypt(p.cvv),
                p.id
            )
            stats["payments_migrated"] += 1

        conn.commit()

        return {
            "success": True,
            "message": "Migración completada",
            **stats
        }

    except Exception as e:
        print(f"Error en migración: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en migración"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/mfa/backup-codes",
         response_model=BackupCodesResponse,
         responses={
             400: {"model": BackupCodesError, "description": "Datos faltantes"},
             401: {"model": BackupCodesError, "description": "Credenciales inválidas"},
             500: {"model": BackupCodesError, "description": "Error del servidor"}
         },
         summary="Obtener códigos de respaldo MFA",
         description="Endpoint para recuperar los códigos de respaldo MFA no utilizados de un usuario",
         tags=["Autenticación MFA"])
async def get_backup_codes(request: BackupCodesRequest):
    """
    Obtiene los códigos de respaldo MFA no utilizados de un usuario.
    
    Requiere validación de credenciales (ID de usuario y contraseña).
    
    Parámetros:
    - user_id: ID del usuario
    - password: Contraseña para verificación
    
    Retorna:
    - success: Indicador de éxito
    - codes: Lista de códigos de respaldo activos
    - message: Mensaje descriptivo del resultado
    """
    # Validación básica
    if not request.user_id or not request.password:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Se requieren ID de usuario y contraseña"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión con la base de datos
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Verificar credenciales
        cursor.execute(
            """
            SELECT id, password FROM Users 
            WHERE id = ? AND isActive = 1
            """,
            request.user_id
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )

        # Verificar contraseña
        if not bcrypt.checkpw(request.password.encode(), user.password.encode()):
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Contraseña incorrecta"
                }
            )

        # 2. Obtener códigos no usados
        cursor.execute(
            """
            SELECT code FROM MFABackupCodes 
            WHERE userId = ? AND isUsed = 0
            """,
            request.user_id
        )
        encrypted_codes = cursor.fetchall()

        # Desencriptar códigos
        codes = [decrypt(code[0]) for code in encrypted_codes]

        return {
            "success": True,
            "codes": codes,
            "message": "Códigos de respaldo obtenidos correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error obteniendo códigos de respaldo: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al obtener códigos de respaldo"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/mfa/regenerate-codes",
         response_model=RegenerateCodesResponse,
         responses={
             400: {"model": RegenerateCodesError, "description": "Datos faltantes"},
             401: {"model": RegenerateCodesError, "description": "Credenciales inválidas"},
             500: {"model": RegenerateCodesError, "description": "Error del servidor"}
         },
         summary="Regenerar códigos MFA",
         description="Endpoint para regenerar los códigos de respaldo MFA de un usuario",
         tags=["Autenticación MFA"])
async def regenerate_backup_codes(request: RegenerateCodesRequest):
    """
    Regenera los códigos de respaldo MFA para un usuario.
    
    1. Valida credenciales del usuario
    2. Elimina los códigos existentes
    3. Genera nuevos códigos (encriptados en DB)
    4. Devuelve los nuevos códigos en claro
    
    Parámetros:
    - user_id: ID del usuario
    - password: Contraseña para verificación
    
    Retorna:
    - success: Indicador de éxito
    - codes: Lista de nuevos códigos de respaldo
    - message: Mensaje descriptivo
    """
    # Validación básica
    if not request.user_id or not request.password:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "Se requieren ID de usuario y contraseña"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Verificar credenciales
        cursor.execute(
            "SELECT password FROM Users WHERE id = ? AND isActive = 1",
            request.user_id
        )
        user = cursor.fetchone()
        
        if not user:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )

        if not bcrypt.checkpw(request.password.encode(), user.password.encode()):
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Contraseña incorrecta"
                }
            )

        # 2. Eliminar códigos existentes
        cursor.execute(
            "DELETE FROM MFABackupCodes WHERE userId = ?",
            request.user_id
        )

        # 3. Generar y guardar nuevos códigos
        backup_codes = generate_backup_codes()
        for code in backup_codes:
            cursor.execute(
                """
                INSERT INTO MFABackupCodes 
                    (userId, code, isUsed, is_encrypted)
                VALUES (?, ?, 0, 1)
                """,
                (request.user_id, encrypt(code))
            )

        conn.commit()

        return {
            "success": True,
            "codes": backup_codes,
            "message": "Códigos MFA regenerados correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error regenerando códigos MFA: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al regenerar códigos de respaldo"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/forgot-password/init",
         response_model=ForgotPasswordResponse,
         responses={
             400: {"model": ForgotPasswordError, "description": "Email requerido o preguntas faltantes"},
             404: {"model": ForgotPasswordError, "description": "Usuario no encontrado"},
             500: {"model": ForgotPasswordError, "description": "Error del servidor"}
         },
         summary="Iniciar recuperación de contraseña",
         description="Endpoint para iniciar el proceso de recuperación de contraseña",
         tags=["Autenticación"])
async def forgot_password_init(request: ForgotPasswordRequest):
    """
    Inicia el proceso de recuperación de contraseña.
    
    1. Verifica que el email existe en el sistema
    2. Comprueba que el usuario tiene preguntas de seguridad configuradas
    3. Devuelve las preguntas de seguridad para verificación
    
    Parámetros:
    - email: Correo electrónico del usuario
    
    Retorna:
    - success: Indicador de éxito
    - email: Email del usuario (sin encriptar)
    - mfa_enabled: Si el usuario tiene MFA habilitado
    - questions: Preguntas de seguridad del usuario
    """
    # Validación básica
    if not request.email:
        raise HTTPException(
            status_code=400,
            detail={
                "success": False,
                "message": "El correo electrónico es requerido"
            }
        )

    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Buscar usuario
        cursor.execute("SELECT id, email, firstName, lastName, mfaEnabled FROM Users WHERE isActive = 1")
        users = cursor.fetchall()

        user_found = None
        for user in users:
            try:
                decrypted_email = decrypt(user.email)
                if decrypted_email.lower() == request.email.lower():
                    user_found = user
                    break
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                continue

        if not user_found:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "No se encontró una cuenta con ese correo electrónico"
                }
            )

        # Obtener preguntas de seguridad
        cursor.execute(
            "SELECT petName, favoriteColor, favoritePlace FROM SecurityQuestions WHERE userId = ?",
            user_found.id
        )
        questions = cursor.fetchone()

        if not questions:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": "No hay preguntas de seguridad configuradas"
                }
            )

        # Verificar estructura de las preguntas
        required_fields = ['petName', 'favoriteColor', 'favoritePlace']
        for field in required_fields:
            if not getattr(questions, field, None):
                raise HTTPException(
                    status_code=500,
                    detail={
                        "success": False,
                        "message": f"Falta el campo de pregunta: {field}"
                    }
                )

        return {
            "success": True,
            "email": request.email,
            "mfa_enabled": user_found.mfaEnabled,
            "questions": {
                "pet_name": "¿Cuál es el nombre de tu primera mascota?",
                "favorite_color": "¿Cuál es tu color favorito?",
                "favorite_place": "¿Cuál es tu lugar favorito?"
            },
            "message": "Proceso de recuperación iniciado"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error en el servidor: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error interno del servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/forgot-password/verify-answer",
         response_model=VerifyAnswerResponse,
         responses={
             400: {"model": VerifyAnswerError, "description": "Preguntas no encontradas"},
             401: {"model": VerifyAnswerError, "description": "Respuesta incorrecta"},
             404: {"model": VerifyAnswerError, "description": "Usuario no encontrado"},
             500: {"model": VerifyAnswerError, "description": "Error del servidor"}
         },
         summary="Verificar respuesta de seguridad",
         description="Endpoint para verificar la respuesta a una pregunta de seguridad",
         tags=["Autenticación"])
async def verify_security_answer(request: VerifyAnswerRequest):
    """
    Verifica la respuesta a una pregunta de seguridad durante el proceso de recuperación de contraseña.
    
    Parámetros:
    - email: Correo electrónico del usuario
    - question: Tipo de pregunta (petName, favoriteColor, favoritePlace)
    - answer: Respuesta proporcionada por el usuario
    
    Retorna:
    - success: Indicador de éxito
    - requires_mfa: Si el usuario requiere MFA para el siguiente paso
    - message: Mensaje descriptivo
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Buscar usuario por email
        cursor.execute("SELECT id, email, mfaEnabled FROM Users WHERE isActive = 1")
        users = cursor.fetchall()

        user = None
        for u in users:
            try:
                if decrypt(u.email).lower() == request.email.lower():
                    user = u
                    break
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                continue

        if not user:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )

        # Obtener preguntas de seguridad
        cursor.execute(
            "SELECT petName, favoriteColor, favoritePlace FROM SecurityQuestions WHERE userId = ?",
            user.id
        )
        security_questions = cursor.fetchone()

        if not security_questions:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": "No se encontraron preguntas de seguridad"
                }
            )

        # Verificar respuesta
        try:
            encrypted_answer = getattr(security_questions, request.question)
            decrypted_answer = decrypt(encrypted_answer)
            is_valid = decrypted_answer.lower() == request.answer.lower()
        except Exception as e:
            print(f"Error desencriptando respuesta: {e}")
            is_valid = False

        if not is_valid:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Respuesta incorrecta"
                }
            )

        return {
            "success": True,
            "requires_mfa": user.mfaEnabled,
            "message": "Respuesta verificada correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error verificando respuesta: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/forgot-password/verify-mfa",
         response_model=VerifyMFAResponse,
         responses={
             401: {"model": VerifyMFAError, "description": "Código MFA inválido"},
             404: {"model": VerifyMFAError, "description": "Usuario no encontrado"},
             500: {"model": VerifyMFAError, "description": "Error del servidor"}
         },
         summary="Verificar código MFA",
         description="Endpoint para verificar códigos MFA durante la recuperación de contraseña",
         tags=["Autenticación"])
async def verify_mfa_code(request: VerifyMFARequest):
    """
    Verifica un código MFA durante el proceso de recuperación de contraseña.
    
    Parámetros:
    - email: Correo electrónico del usuario
    - code: Código MFA a verificar
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Buscar usuario por email
        cursor.execute("SELECT id, email FROM Users WHERE isActive = 1")
        users = cursor.fetchall()

        user = None
        for u in users:
            try:
                if decrypt(u.email).lower() == request.email.lower():
                    user = u
                    break
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                continue

        if not user:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )

        # Verificar código MFA
        code_valid = await verify_backup_code(user.id, request.code)
        if not code_valid:
            raise HTTPException(
                status_code=401,
                detail={
                    "success": False,
                    "message": "Código MFA inválido"
                }
            )

        return {
            "success": True,
            "message": "Código MFA verificado correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error verificando MFA: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/forgot-password/reset",
         response_model=ResetPasswordResponse,
         responses={
             400: {"model": ResetPasswordError, "description": "Validación de contraseña fallida"},
             404: {"model": ResetPasswordError, "description": "Usuario no encontrado"},
             500: {"model": ResetPasswordError, "description": "Error del servidor"}
         },
         summary="Restablecer contraseña",
         description="Endpoint para restablecer la contraseña después de verificación",
         tags=["Autenticación"])
async def reset_password(request: ResetPasswordRequest):
    """
    Restablece la contraseña de un usuario después de completar el proceso de verificación.
    
    Parámetros:
    - email: Correo electrónico del usuario
    - new_password: Nueva contraseña
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Buscar usuario por email
        cursor.execute("SELECT id, firstName, lastName FROM Users WHERE isActive = 1")
        users = cursor.fetchall()

        user = None
        for u in users:
            try:
                if decrypt(u.email).lower() == request.email.lower():
                    user = u
                    break
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                continue

        if not user:
            raise HTTPException(
                status_code=404,
                detail={
                    "success": False,
                    "message": "Usuario no encontrado"
                }
            )

        # 2. Validar nueva contraseña
        password_validation = validate_password(
            request.new_password,
            user.firstName,
            user.lastName
        )
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "success": False,
                    "message": password_validation["message"]
                }
            )

        # 3. Hashear nueva contraseña
        hashed_password = bcrypt.hashpw(
            request.new_password.encode(),
            bcrypt.gensalt(12)
        ).decode()

        # 4. Actualizar contraseña
        cursor.execute(
            """
            UPDATE Users 
            SET password = ?, updatedAt = GETDATE()
            WHERE id = ?
            """,
            (hashed_password, user.id)
        )
        conn.commit()

        return {
            "success": True,
            "message": "Contraseña actualizada correctamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error restableciendo contraseña: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error en el servidor",
                "error": str(e)
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.post("/api/support",
         response_model=SupportResponse,
         responses={
             422: {"model": SupportError, "description": "Validación fallida"},
             500: {"model": SupportError, "description": "Error del servidor"}
         },
         summary="Crear ticket de soporte",
         description="Endpoint para crear un nuevo ticket de soporte técnico",
         tags=["Soporte"])
async def create_support_ticket(request: SupportRequest):
    """
    Crea un nuevo ticket de soporte técnico.
    
    Parámetros:
    - email: Correo electrónico del solicitante (validado automáticamente)
    - message: Mensaje detallado del problema o consulta
    
    Retorna:
    - success: Indicador de éxito
    - message: Mensaje descriptivo
    - ticket_id: ID del ticket creado (opcional)
    """
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Insertar ticket
        cursor.execute(
            """
            INSERT INTO SupportTickets (email, message, createdAt, status)
            OUTPUT INSERTED.id
            VALUES (?, ?, GETDATE(), 'open')
            """,
            (request.email, request.message)
        )
        
        ticket_id = cursor.fetchone()[0]
        conn.commit()

        return {
            "success": True,
            "message": "Ticket de soporte creado correctamente",
            "ticket_id": ticket_id
        }

    except Exception as e:
        print(f"Error creando ticket de soporte: {e}")
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error al enviar reporte"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/audit/logs",
         response_model=AuditLogsResponse,
         responses={
             500: {"model": AuditLogsError, "description": "Error del servidor"}
         },
         summary="Obtener logs de auditoría",
         description="Endpoint para obtener registros de auditoría con filtros y paginación",
         tags=["Auditoría"])
async def get_audit_logs(
    page: int = Query(1, gt=0, description="Número de página"),
    limit: int = Query(50, gt=0, le=100, description="Registros por página"),
    action_type: Optional[str] = Query(None, description="Tipo de acción a filtrar"),
    user_id: Optional[int] = Query(None, description="ID de usuario a filtrar"),
    status: Optional[str] = Query(None, description="Estado a filtrar")
):
   
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Construir consulta base
        query = """
            SELECT 
                a.id, a.userId, u.email, a.actionType, a.tableAffected, 
                a.recordId, a.status, a.ipAddress, a.createdAt
            FROM AuditLogs a
            LEFT JOIN Users u ON a.userId = u.id
            WHERE 1=1
        """
        
        params = []
        
        # Añadir filtros
        if action_type:
            query += " AND a.actionType LIKE ?"
            params.append(f"%{action_type}%")
        
        if user_id:
            query += " AND a.userId = ?"
            params.append(user_id)
        
        if status:
            query += " AND a.status = ?"
            params.append(status)
        
        # Paginación
        offset = (page - 1) * limit
        query += " ORDER BY a.createdAt DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
        params.extend([offset, limit])

        # Ejecutar consulta
        cursor.execute(query, params)
        
        # Procesar resultados
        logs = []
        columns = [column[0] for column in cursor.description]
        
        for row in cursor.fetchall():
            log_data = dict(zip(columns, row))
            
            # Desencriptar email si existe
            if log_data.get('email'):
                try:
                    log_data['email'] = decrypt(log_data['email'])
                except Exception as e:
                    print(f"Error desencriptando email: {e}")
                    log_data['email'] = None
            
            # Mapear nombres de campos
            log_data = {
                "id": log_data["id"],
                "user_id": log_data.get("userId"),
                "email": log_data.get("email"),
                "action_type": log_data["actionType"],
                "table_affected": log_data["tableAffected"],
                "record_id": log_data.get("recordId"),
                "status": log_data["status"],
                "ip_address": log_data["ipAddress"],
                "created_at": log_data["createdAt"]
            }
            
            logs.append(log_data)

        return {
            "success": True,
            "logs": logs,
            "message": "Logs de auditoría obtenidos correctamente"
        }

    except Exception as e:
        print(f"Error obteniendo logs de auditoría: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error obteniendo logs"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/audit/logins",
         response_model=LoginLogsResponse,
         responses={
             500: {"model": LoginLogsError, "description": "Error del servidor"}
         },
         summary="Obtener logs de inicio de sesión",
         description="Endpoint para obtener registros de inicio de sesión con filtros y paginación",
         tags=["Auditoría"])
async def get_login_logs(
    page: int = Query(1, gt=0, description="Número de página"),
    limit: int = Query(50, gt=0, le=100, description="Registros por página (máx 100)"),
    email: Optional[str] = Query(None, description="Email del usuario a filtrar"),
    user_id: Optional[int] = Query(None, description="ID de usuario a filtrar"),
    status: Optional[str] = Query(None, description="Estado del login (success, failed, etc.)")
):
    
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # Construir consulta base
        query = """
            SELECT 
                id, userId, email, ipAddress, status, 
                mfaUsed, createdAt
            FROM LoginAudits
            WHERE 1=1
        """
        
        params = []
        
        # Añadir filtros
        if email:
            query += " AND email = ?"
            params.append(encrypt(email))
        
        if user_id:
            query += " AND userId = ?"
            params.append(user_id)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        # Paginación
        offset = (page - 1) * limit
        query += " ORDER BY createdAt DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY"
        params.extend([offset, limit])

        # Ejecutar consulta
        cursor.execute(query, params)
        
        # Procesar resultados
        login_logs = []
        columns = [column[0] for column in cursor.description]
        
        for row in cursor.fetchall():
            log_data = dict(zip(columns, row))
            
            # Desencriptar email
            try:
                log_data['email'] = decrypt(log_data['email'])
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                continue  # Omitir registros con email no desencriptable
            
            # Mapear nombres de campos
            login_log = {
                "id": log_data["id"],
                "user_id": log_data.get("userId"),
                "email": log_data["email"],
                "ip_address": log_data["ipAddress"],
                "status": log_data["status"],
                "mfa_used": bool(log_data["mfaUsed"]),
                "created_at": log_data["createdAt"]
            }
            
            login_logs.append(login_log)

        return {
            "success": True,
            "logins": login_logs,
            "message": "Logs de inicio de sesión obtenidos correctamente"
        }

    except Exception as e:
        print(f"Error obteniendo logs de login: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error obteniendo logs de login"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/audit/stats",
         response_model=AuditStatsResponse,
         responses={
             500: {"model": AuditStatsError, "description": "Error del servidor"}
         },
         summary="Obtener estadísticas de auditoría",
         description="Endpoint para obtener métricas del sistema y actividad reciente",
         tags=["Auditoría"])
async def get_audit_stats():
    
    conn = None
    cursor = None
    try:
        # Establecer conexión
        conn = pyodbc.connect(
            f"DRIVER={DB_CONFIG['driver']};"
            f"SERVER={DB_CONFIG['server']};"
            f"DATABASE={DB_CONFIG['database']};"
            f"UID={DB_CONFIG['username']};"
            f"PWD={DB_CONFIG['password']}"
        )
        cursor = conn.cursor()

        # 1. Obtener estadísticas generales
        stats_query = """
            SELECT 
                (SELECT COUNT(*) FROM Users WHERE isActive = 1) as total_users,
                (SELECT COUNT(*) FROM LoginAudits WHERE status = 'success') as successful_logins,
                (SELECT COUNT(*) FROM LoginAudits WHERE status = 'failed') as failed_logins,
                (SELECT COUNT(*) FROM AuditLogs WHERE status = 'error') as errors,
                (SELECT COUNT(*) FROM Appointments) as total_appointments
        """
        
        cursor.execute(stats_query)
        stats_row = cursor.fetchone()
        
        stats = {
            "total_users": stats_row.total_users,
            "successful_logins": stats_row.successful_logins,
            "failed_logins": stats_row.failed_logins,
            "errors": stats_row.errors,
            "total_appointments": stats_row.total_appointments
        }

        # 2. Obtener actividad reciente
        activity_query = """
            SELECT TOP 10 
                a.actionType, a.createdAt, u.email, a.status
            FROM AuditLogs a
            LEFT JOIN Users u ON a.userId = u.id
            ORDER BY a.createdAt DESC
        """
        
        cursor.execute(activity_query)
        activity_rows = cursor.fetchall()
        
        # Procesar actividad reciente
        recent_activity = []
        for row in activity_rows:
            try:
                email = decrypt(row.email) if row.email else None
            except Exception as e:
                print(f"Error desencriptando email: {e}")
                email = None
            
            activity = {
                "action_type": row.actionType,
                "created_at": row.createdAt,
                "email": email,
                "status": row.status
            }
            recent_activity.append(activity)

        return {
            "success": True,
            "stats": stats,
            "recent_activity": recent_activity,
            "message": "Estadísticas obtenidas correctamente"
        }

    except Exception as e:
        print(f"Error obteniendo estadísticas: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "success": False,
                "message": "Error obteniendo estadísticas"
            }
        )
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()




















if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3001)