from django.http import FileResponse
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import pyodbc
import bcrypt
import jwt
import qrcode
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from typing import Optional, List, Dict, Any
import uuid
import hashlib
import secrets
import string
import json

app = FastAPI()

# Configuración CORS
origins = [
    "http://localhost:8080",
    "http://127.0.0.1:5500"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


DB_CONFIG = {
    'server': 'JOSE',
    'database': 'LIANZE_DB',
    'username': 'josehart',
    'password': 'porras0111',
    'driver': '{ODBC Driver 17 for SQL Server}'
}

#  encriptación
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

#  JWT
SECRET_KEY = "tu_clave_secreta_super_segura_32bytes"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# archivos estáticos
app.mount("/static", StaticFiles(directory="public"), name="static")

# Modelos 
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

async def log_login_attempt(email: str, user_id: Optional[int], ip: str, user_agent: str, status: str, mfa_used: bool = False):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO LoginAudits (userId, email, ipAddress, userAgent, status, mfaUsed) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, email, ip, user_agent, status, mfa_used
        )
        conn.commit()
    except Exception as e:
        print(f"Error registrando intento de login: {e}")
    finally:
        cursor.close()
        conn.close()

# Endpoints
@app.get("/")
async def root():
    return FileResponse("public/index.html")

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
    
    # Verificar código MFA (implementar verify_backup_code similar a Node.js)
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
        # Establecer conexión con la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Ejecutar la consulta SQL
        cursor.execute("""
            SELECT 
                id, email, firstName, lastName, userType,
                phone, dateOfBirth, gender, profileImage,
                createdAt, updatedAt, bio,
                country_id, province_id, canton_id, district_id
            FROM Users 
            WHERE id = ? AND isActive = 1
        """, user_id)
        
        # Obtener los resultados
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(
                status_code=404,
                detail="Usuario no encontrado"
            )
        
        # Convertir el resultado a un diccionario
        columns = [column[0] for column in cursor.description]
        user_data = dict(zip(columns, row))
        
        # Asegurar que bio no sea None
        user_data['bio'] = user_data.get('bio') or ''
        
        # Desencriptar el email si es necesario
        if 'email' in user_data:
            user_data['email'] = decrypt(user_data['email'])
        
        return user_data
        
    except HTTPException:
        # Re-lanzar las excepciones HTTP que ya hemos manejado
        raise
        
    except Exception as e:
        print(f"Error obteniendo perfil: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error al obtener perfil"
        )
        
    finally:
        # Cerrar cursor y conexión
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.post("/api/update-mfa")
async def update_mfa(request: UpdateMFARequest):
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
        
        # Ejecutar la actualización
        cursor.execute(
            """
            UPDATE Users 
            SET mfaEnabled = ?, updatedAt = GETDATE()
            WHERE id = ?
            """,
            request.enable, request.userId
        )
        conn.commit()
        
        # Determinar el mensaje según si se activa o desactiva
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
        # Cerrar cursor y conexión
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.get("/api/locations/countries", response_model=List[Country])
async def get_countries():
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
        
        # Ejecutar la consulta SQL
        cursor.execute(
            """
            SELECT id, description, code 
            FROM GeographicLocations 
            WHERE type = 'Pais' 
            ORDER BY description
            """
        )
        
        # Obtener todos los resultados
        countries = cursor.fetchall()
        
        # Convertir a lista de diccionarios
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
        # Cerrar cursor y conexión
        if cursor:
            cursor.close()
        if conn:
            conn.close()







# Continúa con los demás endpoint
# s...
# (Implementar los endpoints restantes siguiendo el mismo patrón)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)