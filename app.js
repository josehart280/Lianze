const express = require('express');
const bodyParser = require('body-parser');
const sql = require('mssql');
const path = require('path'); 
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const multer = require('multer');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const secretKey = 'mi_clave';
const saltRounds = 12;

const app = express();

// Configuración de CORS 
app.use((req, res, next) => {
    const allowedOrigins = ['http://localhost:8080', 'http://127.0.0.1:5500'];
    const origin = req.headers.origin;
    
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

const dbConfig = {
  user: 'LianzeUser2',
  password: 'Porras0111!',
  server: 'tiusr24pl.cuc-carrera-ti.ac.cr', 
  database: 'tiusr24pl_Lianze',
  options: {
    encrypt: true, 
    trustServerCertificate: true 
  }
};

const sqlPool = new sql.ConnectionPool(dbConfig);
let poolConnect;


function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        console.log('No authorization header found');
        return res.status(401).json({ message: 'No se proporcionó token' });
    }
    
    const parts = authHeader.split(' ');
    
    // Verificar que el header tenga el formato correcto: "Bearer <token>"
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        console.log('Malformed authorization header:', authHeader);
        return res.status(401).json({ message: 'Formato de token incorrecto' });
    }
    
    const token = parts[1];
    
    // Verificar que el token tenga la estructura básica de un JWT
    if (!token || token.split('.').length !== 3) {
        console.log('Malformed JWT token:', token);
        return res.status(401).json({ message: 'Token JWT mal formado' });
    }
    
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            return res.status(403).json({ message: 'Token inválido o expirado' });
        }
        
        console.log('User authenticated:', user);
        req.user = user;
        next();
    });
}






sqlPool.connect()
  .then(pool => {
    poolConnect = pool;
    console.log('Conectado a la base de datos');
  })
  .catch(err => {
    console.error('Error al conectar a la base de datos:', err);
  });

// Middleware para manejar la conexión a la base de datos
app.use(async (req, res, next) => {
  try {
    if (!poolConnect) {
      poolConnect = await sqlPool.connect();
    }
    req.db = poolConnect;
    next();
  } catch (err) {
    console.error('Error en middleware de conexión:', err);
    res.status(500).json({ error: 'Error de conexión a la base de datos' });
  }
});
// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));



async function executeQuery(query, params = []) {
  try {
    const request = poolConnect.request(); 
    params.forEach(param => {
      request.input(param.name, param.type || sql.NVarChar, param.value);
    });
    return await request.query(query);
  } catch (err) {
    console.error('Error en la consulta SQL:', err);
    throw err;
  }
}



app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});




function validatePassword(password, firstName, lastName) {
    if (password.length < 12) {
        return { valid: false, message: "La contraseña debe tener al menos 12 caracteres" };
    }
    
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: "La contraseña debe contener al menos una letra mayúscula" };
    }
    
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: "La contraseña debe contener al menos una letra minúscula" };
    }
    
    if (!/[0-9]/.test(password)) {
        return { valid: false, message: "La contraseña debe contener al menos un número" };
    }
    
    if (!/[!@#$%^&*]/.test(password)) {
        return { valid: false, message: "La contraseña debe contener al menos un símbolo (!@#$%^&*)" };
    }
    
    const nameParts = [...firstName.toLowerCase().split(/[^a-z0-9]/), ...lastName.toLowerCase().split(/[^a-z0-9]/)];
    for (const part of nameParts) {
        if (part.length > 2 && password.toLowerCase().includes(part)) {
            return { valid: false, message: "La contraseña no puede ser similar a tu nombre" };
        }
    }
    
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'contraseña', 'password123'];
    if (commonPasswords.some(common => password.toLowerCase().includes(common.toLowerCase()))) {
        return { valid: false, message: "La contraseña es demasiado común" };
    }
    
    return { valid: true };
}




// Configuración de Multer para subir imágenes
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'public/uploads/profile-images/');
    },
    filename: function(req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: function(req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten imágenes'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    }
});






//optener perfil
app.get('/api/user-profile/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Usar input() para definir el parámetro
        request.input('userId', sql.Int, userId);
        
        const result = await request.query(`
            SELECT 
                id, email, firstName, lastName, userType,
                phone, dateOfBirth, gender, profileImage,
                createdAt, updatedAt, bio,
                country_id, province_id, canton_id, district_id
            FROM Users 
            WHERE id = @userId AND isActive = 1
        `);
        
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            user.bio = user.bio || '';

            if (user.email && user.email.includes(':')) {
                user.email = decrypt(user.email);
            }
            res.json(user);
        } else {
            res.status(404).json({ error: 'Usuario no encontrado' });
        }
    } catch (err) {
        console.error('Error obteniendo perfil:', err);
        res.status(500).json({ error: 'Error al obtener perfil' });
    }
});


// Ruta para actualizar perfil 
app.post('/api/update-profile', upload.single('profileImage'), async (req, res) => {
    const { userId, firstName, lastName, email, phone, dateOfBirth, gender, bio, 
            countryId, provinceId, cantonId, districtId } = req.body;
    let profileImagePath = null;

    if (req.file) {
        profileImagePath = '/uploads/profile-images/' + req.file.filename;
    }

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Verificar email
        request.input('emailCheck', sql.NVarChar, encrypt(email));
        request.input('userId', sql.Int, userId);
        
        const emailCheck = await request.query(`
            SELECT id FROM Users WHERE email = @emailCheck AND id != @userId
        `);
        
        if (emailCheck.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El correo electrónico ya está en uso por otro usuario' 
            });
        }

        // Construir query dinámica
        let query = `
            UPDATE Users 
            SET 
                firstName = @firstName,
                lastName = @lastName,
                email = @email,
                phone = @phone,
                dateOfBirth = @dateOfBirth,
                gender = @gender,
                bio = @bio,
                ${profileImagePath ? 'profileImage = @profileImage,' : ''}
                country_id = @countryId,
                province_id = @provinceId,
                canton_id = @cantonId,
                district_id = @districtId,
                updatedAt = GETDATE()
            WHERE id = @userId
        `;

        // Agregar parámetros
        request.input('firstName', sql.NVarChar, firstName);
        request.input('lastName', sql.NVarChar, lastName);
        request.input('email', sql.NVarChar, encrypt(email)); // Encriptar el email
        request.input('phone', sql.NVarChar, phone);
        request.input('dateOfBirth', sql.Date, dateOfBirth);
        request.input('gender', sql.NVarChar, gender);
        request.input('bio', sql.NVarChar, bio);
        request.input('countryId', sql.NVarChar, countryId || null);
        request.input('provinceId', sql.NVarChar, provinceId || null);
        request.input('cantonId', sql.NVarChar, cantonId || null);
        request.input('districtId', sql.NVarChar, districtId || null);
        
        
        if (profileImagePath) {
            request.input('profileImage', sql.NVarChar, profileImagePath);
        }

        await request.query(query);
        
        res.json({
            success: true,
            message: 'Perfil actualizado correctamente',
            profileImage: profileImagePath
        });
    } catch (err) {
        console.error('Error actualizando perfil:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar el perfil' 
        });
    }
});



// Ruta de login actualizada para MFA
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent');

    try {
        // Obtener todos los usuarios activos
        const result = await executeQuery('SELECT * FROM Users WHERE isActive = 1');
        
        // Buscar usuario por email (desencriptando)
        const user = result.recordset.find(u => {
            try {
                return decrypt(u.email) === email;
            } catch {
                return false;
            }
        });

        if (!user) {
            await logLoginAttempt(email, null, ip, userAgent, 'failed');
            return res.status(401).json({ success: false, message: 'Credenciales incorrectas' });
        }

        // Verificar contraseña
        const passwordMatch = await bcrypt.compare(password, user.password);
    
        if (!passwordMatch) {
            await logLoginAttempt(email, user.id, ip, userAgent, 'failed');
            return res.status(401).json({ success: false, message: 'Credenciales incorrectas' });
        }

        // Desencriptar datos del usuario
        const decryptedUser = {
            id: user.id,
            email: decrypt(user.email),
            firstName: user.firstName,
            lastName: user.lastName,
            userType: user.userType,
            mfaEnabled: user.mfaEnabled 
        };

        // Si tiene MFA habilitado, generar token temporal
        if (user.mfaEnabled) {
            const tempToken = generateTempToken(user.id);
            await logLoginAttempt(email, user.id, ip, userAgent, 'mfa_required');
            return res.json({ 
                success: true, 
                requiresMFA: true,
                tempToken: tempToken,
                message: 'Por favor ingresa tu código MFA'
            });
        }
         const token = jwt.sign(
            { 
                id: user.id,
                email: decrypt(user.email),
                userType: user.userType
            },
            secretKey,
            { expiresIn: '8h' }
        );

        // Registrar login exitoso
        await logLoginAttempt(email, user.id, ip, userAgent, 'success');
        
        // Si no requiere MFA
        res.json({ 
            success: true, 
            user: decryptedUser,
            token: token,
            requiresMFA: false,
            firstLogin: user.firstLogin
        });

        
    } catch (err) {
        console.error('Error en el login:', err);
        await logLoginAttempt(email, null, ip, userAgent, 'error', false, err.message);
        res.status(500).json({ success: false, message: 'Error en el servidor' });
    }
});

// Nuevo endpoint para verificar código MFA
app.post('/api/verify-mfa', async (req, res) => {
    const { tempToken, code } = req.body;
    
    if (!tempToken || !code) {
        return res.status(400).json({ 
            success: false, 
            message: 'Token temporal y código son requeridos' 
        });
    }
    
    try {
        // Verificar token temporal
        const userId = verifyTempToken(tempToken);
        if (!userId) {
            return res.status(401).json({ 
                success: false, 
                message: 'Token inválido o expirado' 
            });
        }
        
        // Verificar código MFA
        const codeValid = await verifyBackupCode(userId, code);
        if (!codeValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Código MFA inválido' 
            });
        }
        
        // Obtener información del usuario
        const userResult = await executeQuery(
            'SELECT id, email, firstName, lastName, userType FROM Users WHERE id = @userId AND isActive = 1',
            [{ name: 'userId', type: sql.Int, value: userId }]
        );
        
        if (userResult.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }
        
        const user = userResult.recordset[0];
        
        // Desencriptar datos del usuario
        const decryptedUser = {
            id: user.id,
            email: decrypt(user.email),
            firstName: user.firstName,
            lastName: user.lastName,
            userType: user.userType
        };

        res.json({ 
            success: true, 
            user: decryptedUser,
            message: 'Autenticación MFA exitosa'
        });
    } catch (err) {
        console.error('Error verificando MFA:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor' 
        });
    }
});


app.post('/api/update-mfa', async (req, res) => {
    const { userId, enable } = req.body;

    try {
        await sql.connect(dbConfig);
        
        await sql.query`
            UPDATE Users 
            SET mfaEnabled = ${enable}, updatedAt = GETDATE()
            WHERE id = ${userId}
        `;
        
        res.json({
            success: true,
            message: `MFA ${enable ? 'activado' : 'desactivado'} correctamente`
        });
    } catch (err) {
        console.error('Error actualizando MFA:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar MFA' 
        });
    } finally {
        sql.close();
    }
});




//paises apis


//paises
app.get('/api/locations/countries', async (req, res) => {
    try {
        const pool = await poolConnect;
        const result = await pool.request().query(
            `SELECT id, description, code FROM GeographicLocations WHERE type = 'Pais' ORDER BY description`
        );
        res.json(result.recordset);
    } catch (err) {
        console.error('Error obteniendo países:', err);
        res.status(500).json({ error: 'Error obteniendo países' });
    }
});

// provincias-pais    aopii
app.get('/api/locations/provinces/:countryId', async (req, res) => {
    try {
        const result = await executeQuery(
            `SELECT id, description, code FROM GeographicLocations 
             WHERE type = 'Provincia' AND parent_id = @countryId ORDER BY description`,
            [{ name: 'countryId', type: sql.NVarChar, value: req.params.countryId }]
        );
        res.json(result.recordset);
    } catch (err) {
        console.error('Error obteniendo provincias:', err);
        res.status(500).json({ error: 'Error obteniendo provincias' });
    }
});

//cantones-provincias
app.get('/api/locations/cantons/:provinceId', async (req, res) => {
    try {
        const result = await executeQuery(
            `SELECT id, description, code FROM GeographicLocations 
             WHERE type = 'Canton' AND parent_id = @provinceId ORDER BY description`,
            [{ name: 'provinceId', type: sql.NVarChar, value: req.params.provinceId }]
        );
        res.json(result.recordset);
    } catch (err) {
        console.error('Error obteniendo cantones:', err);
        res.status(500).json({ error: 'Error obteniendo cantones' });
    }
});

// distritos-provincias
app.get('/api/locations/districts/:cantonId', async (req, res) => {
    try {
        const result = await executeQuery(
            `SELECT id, description, code FROM GeographicLocations 
             WHERE type = 'Distrito' AND parent_id = @cantonId ORDER BY description`,
            [{ name: 'cantonId', type: sql.NVarChar, value: req.params.cantonId }]
        );
        res.json(result.recordset);
    } catch (err) {
        console.error('Error obteniendo distritos:', err);
        res.status(500).json({ error: 'Error obteniendo distritos' });
    }
});








//cambios location




app.post('/api/update-location', async (req, res) => {
    const { userId, countryId, provinceId, cantonId, districtId } = req.body;

    if (!userId || !countryId) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requieren ID de usuario y país' 
        });
    }

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Agregar todos los parámetros necesarios
        request.input('userId', sql.Int, userId);
        request.input('countryId', sql.NVarChar, countryId);
        request.input('provinceId', sql.NVarChar, provinceId || null);
        request.input('cantonId', sql.NVarChar, cantonId || null);
        request.input('districtId', sql.NVarChar, districtId || null);
        
        await request.query(`
            UPDATE Users 
            SET 
                country_id = @countryId,
                province_id = @provinceId,
                canton_id = @cantonId,
                district_id = @districtId,
                updatedAt = GETDATE()
            WHERE id = @userId
        `);
        
        res.json({
            success: true,
            message: 'Ubicación actualizada correctamente'
        });
    } catch (err) {
        console.error('Error actualizando ubicación:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar ubicación' 
        });
    }
});






















//CRUD payments

app.get('/api/payment-methods/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const request = poolConnect.request();
        request.input('userId', sql.Int, userId);
        
       const result = await request.query(`
            SELECT 
                c.id, 
                c.cardNumber, 
                c.cardHolder, 
                c.expirationMonth, 
                c.expirationYear, 
                b.balance,  -- Obtenemos el balance de BankAccounts
                c.isDefault,
                c.isActive,
                c.createdAt,
                c.updatedAt
            FROM Cards c
            LEFT JOIN BankAccounts b ON c.userId = b.userId
            WHERE c.userId = @userId AND c.isActive = 1
            ORDER BY c.isDefault DESC, c.createdAt DESC
        `);
        
        // Desencriptar datos sensibles
        const sanitizedCards = result.recordset.map(card => {
            try {
                const decryptedCard = {
                    id: card.id,
                    cardNumber: `•••• •••• •••• ${decrypt(card.cardNumber).slice(-4)}`,
                    cardHolder: decrypt(card.cardHolder),
                    expirationMonth: card.expirationMonth,
                    expirationYear: card.expirationYear,
                    isDefault: card.isDefault,
                    isActive: card.isActive,
                    createdAt: card.createdAt,
                    updatedAt: card.updatedAt
                };
                
                // Solo agregar balance si existe y es un número
                if (card.balance !== undefined && card.balance !== null) {
                    decryptedCard.balance = parseFloat(card.balance);
                }
                
                return decryptedCard;
            } catch (err) {
                console.error('Error desencriptando tarjeta:', err);
                return null;
            }
        }).filter(card => card !== null);
        
        res.json(sanitizedCards);
    } catch (err) {
        console.error('Error obteniendo métodos de pago:', err);
        res.status(500).json({ error: 'Error al obtener métodos de pago' });
    }
});

app.get('/api/user/payment-methods', async (req, res) => {
    const userId = req.user.id; // Asumiendo autenticación JWT
    
    try {
        // Obtener tarjetas
        const cards = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .query(`
                SELECT id, cardNumber, cardHolder, expirationMonth, expirationYear, 
                       balance, isDefault, 'card' as type
                FROM UserPaymentMethods 
                WHERE userId = @userId
            `);
        
        // Obtener asociaciones SINPE
        const sinpeAccounts = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .query(`
                SELECT s.id, s.phoneNumber, u.cardNumber, s.isVerified, 'sinpe' as type
                FROM SinpeMovilAssociations s
                JOIN UserPaymentMethods u ON s.paymentMethodId = u.id
                WHERE s.userId = @userId
            `);
        
        // Desencriptar y formatear datos
        const paymentMethods = [
            ...cards.recordset.map(card => ({
                ...card,
                cardNumber: `•••• •••• •••• ${decrypt(card.cardNumber).slice(-4)}`,
                isSinpe: false
            })),
            ...sinpeAccounts.recordset.map(sinpe => ({
                ...sinpe,
                cardNumber: `•••• •••• •••• ${decrypt(sinpe.cardNumber).slice(-4)}`,
                isSinpe: true
            }))
        ];
        
        res.json(paymentMethods);
    } catch (err) {
        console.error('Error obteniendo métodos de pago:', err);
        res.status(500).json({ error: 'Error al obtener métodos de pago' });
    }
});


app.post('/api/payment-methods', async (req, res) => {
    const { userId, cardNumber, cardHolder, expirationMonth, expirationYear, cvv } = req.body; // Eliminado balance

    try {
        // Validaciones (sin balance)
        if (!userId || !cardNumber || !cardHolder || !expirationMonth || !expirationYear || !cvv) {
            return res.status(400).json({ 
                success: false, 
                message: 'Todos los campos son requeridos' 
            });
        }

        // Encriptación (igual)
        const encryptedCardNumber = encrypt(cardNumber);
        const encryptedCardHolder = encrypt(cardHolder);
        const encryptedCvv = encrypt(cvv);

        const pool = await poolConnect;
        
        // Consulta para contar tarjetas (igual)
        const countRequest = pool.request();
        const countResult = await countRequest
            .input('userId', sql.Int, userId)
            .query('SELECT COUNT(*) as count FROM Cards WHERE userId = @userId AND isActive = 1');
        
        const isFirstCard = countResult.recordset[0].count === 0;
        
        // Insertar tarjeta (sin balance)
        const insertRequest = pool.request();
        const insertResult = await insertRequest
            .input('userId', sql.Int, userId)
            .input('cardNumber', sql.NVarChar, encryptedCardNumber)
            .input('cardHolder', sql.NVarChar, encryptedCardHolder)
            .input('expirationMonth', sql.Int, expirationMonth)
            .input('expirationYear', sql.Int, expirationYear)
            .input('cvv', sql.NVarChar, encryptedCvv)
            .input('cardType', sql.NVarChar, 'credit')
            .input('cardBrand', sql.NVarChar, getCardBrand(cardNumber))
            .input('isDefault', sql.Bit, isFirstCard)
            .input('isActive', sql.Bit, 1)
            .input('is_encrypted', sql.Bit, 1)
            .query(`
                INSERT INTO Cards 
                (userId, cardNumber, cardHolder, expirationMonth, expirationYear, cvv, 
                 cardType, cardBrand, isDefault, isActive, is_encrypted)
                OUTPUT INSERTED.id
                VALUES 
                (@userId, @cardNumber, @cardHolder, @expirationMonth, @expirationYear, @cvv, 
                 @cardType, @cardBrand, @isDefault, @isActive, @is_encrypted)
            `);
        
        res.json({
            success: true,
            message: 'Tarjeta agregada correctamente',
            cardId: insertResult.recordset[0].id,
            isDefault: isFirstCard
        });
    } catch (err) {
        console.error('Error agregando método de pago:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al agregar método de pago: ' + err.message 
        });
    }
});
// Función auxiliar para detectar la marca de la tarjeta
function getCardBrand(cardNumber) {
    const firstDigit = cardNumber[0];
    if (firstDigit === '4') return 'visa';
    if (firstDigit === '5') return 'mastercard';
    if (firstDigit === '3') return 'amex';
    return 'other';
}


app.put('/api/payment-methods/:id', async (req, res) => {
    const cardId = parseInt(req.params.id);
    const { cardHolder, expirationMonth, expirationYear, isDefault } = req.body;

    if (isNaN(cardId)) {
        return res.status(400).json({ error: 'ID de tarjeta no válido' });
    }

    try {
        const pool = await poolConnect;
        
        // 1. Verificar que la tarjeta existe (con un request nuevo)
        const checkRequest = pool.request();
        const cardCheck = await checkRequest
            .input('cardId', sql.Int, cardId)
            .query('SELECT userId FROM Cards WHERE id = @cardId AND isActive = 1');
        
        if (cardCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tarjeta no encontrada' 
            });
        }
        
        const userId = cardCheck.recordset[0].userId;
        
        // 2. Si se está marcando como predeterminada, actualizar otras tarjetas (con otro request)
        if (isDefault) {
            const updateDefaultRequest = pool.request();
            await updateDefaultRequest
                .input('userId', sql.Int, userId)
                .query('UPDATE Cards SET isDefault = 0 WHERE userId = @userId AND isActive = 1');
        }
        
        // 3. Actualizar tarjeta (con otro request nuevo)
        const updateRequest = pool.request();
        await updateRequest
            .input('cardId', sql.Int, cardId)
            .input('cardHolder', sql.NVarChar, encrypt(cardHolder))
            .input('expirationMonth', sql.Int, expirationMonth)
            .input('expirationYear', sql.Int, expirationYear)
            .input('isDefault', sql.Bit, isDefault || 0)
            .query(`
                UPDATE Cards 
                SET 
                    cardHolder = @cardHolder,
                    expirationMonth = @expirationMonth,
                    expirationYear = @expirationYear,
                    isDefault = @isDefault,
                    updatedAt = GETDATE()
                WHERE id = @cardId
            `);
        
        res.json({
            success: true,
            message: 'Tarjeta actualizada correctamente'
        });
    } catch (err) {
        console.error('Error actualizando tarjeta:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar tarjeta' 
        });
    }
});

app.delete('/api/payment-methods/:id', async (req, res) => {
    const cardId = parseInt(req.params.id);

    if (isNaN(cardId)) {
        return res.status(400).json({ error: 'ID de tarjeta no válido' });
    }

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Verificar si es la tarjeta predeterminada
        const cardCheck = await request
            .input('cardId', sql.Int, cardId)
            .query('SELECT userId, isDefault FROM Cards WHERE id = @cardId AND isActive = 1');
        
        if (cardCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tarjeta no encontrada' 
            });
        }
        
        const userId = cardCheck.recordset[0].userId;
        const isDefault = cardCheck.recordset[0].isDefault;
        
        // "Eliminar" la tarjeta (marcar como inactiva en lugar de borrar)
        await request
            .input('cardId', sql.Int, cardId)
            .query('UPDATE Cards SET isActive = 0, updatedAt = GETDATE() WHERE id = @cardId');
        
        // Si era la predeterminada, asignar una nueva predeterminada
        if (isDefault) {
            const newDefaultResult = await request
                .input('userId', sql.Int, userId)
                .query(`
                    SELECT TOP 1 id FROM Cards 
                    WHERE userId = @userId AND isActive = 1
                    ORDER BY createdAt DESC
                `);
            
            if (newDefaultResult.recordset.length > 0) {
                await request
                    .input('newDefaultId', sql.Int, newDefaultResult.recordset[0].id)
                    .query('UPDATE Cards SET isDefault = 1 WHERE id = @newDefaultId');
            }
        }
        
        res.json({
            success: true,
            message: 'Tarjeta eliminada correctamente'
        });
    } catch (err) {
        console.error('Error eliminando tarjeta:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al eliminar tarjeta' 
        });
    }
});



app.put('/api/payment-methods/:id/set-default', async (req, res) => {
    const cardId = parseInt(req.params.id);

    if (isNaN(cardId)) {
        return res.status(400).json({ error: 'ID de tarjeta no válido' });
    }

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Verificar que la tarjeta existe
        const cardCheck = await request
            .input('cardId', sql.Int, cardId)
            .query('SELECT userId FROM Cards WHERE id = @cardId AND isActive = 1');
        
        if (cardCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Tarjeta no encontrada' 
            });
        }
        
        const userId = cardCheck.recordset[0].userId;
        
        // Primero, quitar el estado predeterminado de todas las tarjetas del usuario
        await request
            .input('userId', sql.Int, userId)
            .query('UPDATE Cards SET isDefault = 0 WHERE userId = @userId AND isActive = 1');
        
        // Luego, marcar esta tarjeta como predeterminada
        await request
            .input('cardId', sql.Int, cardId)
            .query('UPDATE Cards SET isDefault = 1 WHERE id = @cardId');
        
        res.json({
            success: true,
            message: 'Tarjeta establecida como predeterminada'
        });
    } catch (err) {
        console.error('Error estableciendo tarjeta predeterminada:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al establecer tarjeta predeterminada' 
        });
    }
});


app.get('/api/bank-accounts/:userId/balance', async (req, res) => {
    try {
        const userId = req.params.userId;
        const result = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .query('SELECT balance FROM BankAccounts WHERE userId = @userId');
        
        if (result.recordset.length > 0) {
            res.json({ balance: result.recordset[0].balance });
        } else {
            res.json({ balance: 0 });
        }
    } catch (err) {
        console.error('Error obteniendo balance:', err);
        res.status(500).json({ error: 'Error al obtener balance' });
    }
});


app.post('/api/payments/process-card', async (req, res) => {
    const { userId, cardId, cardNumber, cardHolder, expirationMonth, expirationYear, cvv, amount, psychologistId, description } = req.body;

    try {
        // Validaciones básicas
        if (!userId || !psychologistId || !amount || amount <= 0) {
            return res.status(400).json({ success: false, message: 'Datos de pago inválidos' });
        }
        // Verificar si el psicólogo existe
        const psychologist = await poolConnect.request()
            .input('psychologistId', sql.Int, psychologistId)
            .query(`
                SELECT p.id, u.id as userId 
                FROM PsychologistProfiles p
                JOIN Users u ON p.userId = u.id
                WHERE p.id = @psychologistId
            `);

        if (psychologist.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Psicólogo no encontrado' });
        }

        const psychologistUserId = psychologist.recordset[0].userId;

        // Crear transacción
        const transaction = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .input('psychologistId', sql.Int, psychologistId)
            .input('amount', sql.Decimal(10, 2), amount)
            .input('description', sql.NVarChar, description)
            .input('cardId', sql.Int, cardId || null)
            .input('cardLastFour', sql.NVarChar, cardNumber ? cardNumber.slice(-4) : null)
            .query(`
                INSERT INTO Transactions (
                    userId, psychologistId, amount, description, 
                    status, transactionType, createdAt, 
                    cardId, cardLastFour
                )
                OUTPUT INSERTED.id
                VALUES (
                    @userId, @psychologistId, @amount, @description,
                    'pending', 'card', GETDATE(),
                    @cardId, @cardLastFour
                )
            `);

        const transactionId = transaction.recordset[0].id;

        // Simular procesamiento de pago (en producción integrar con pasarela de pago)
        setTimeout(async () => {
            try {
                // Marcar como completado
                await poolConnect.request()
                    .input('transactionId', sql.Int, transactionId)
                    .query('UPDATE Transactions SET status = \'completed\', completedAt = GETDATE() WHERE id = @transactionId');
                
                // Registrar pago en cuenta del psicólogo
                await poolConnect.request()
                    .input('userId', sql.Int, psychologistUserId)
                    .input('amount', sql.Decimal(10, 2), amount)
                    .query(`
                        UPDATE BankAccounts 
                        SET balance = balance + @amount 
                        WHERE userId = @userId AND isDefault = 1
                    `);
            } catch (error) {
                console.error('Error procesando pago:', error);
            }
        }, 1000);

        res.json({
            success: true,
            transactionId,
            message: 'Pago procesado exitosamente'
        });

    } catch (error) {
        console.error('Error en process-card:', error);
        res.status(500).json({ success: false, message: 'Error al procesar el pago' });
    }
});

app.post('/api/payments/process-sinpe', async (req, res) => {
    const { phoneNumber, psychologistId } = req.body;

    try {
        // Validaciones básicas
        if (!phoneNumber || !psychologistId) {
            return res.status(400).json({ success: false, message: 'Datos incompletos' });
        }

        // Obtener información del psicólogo
        const psychologist = await poolConnect.request()
            .input('psychologistId', sql.Int, psychologistId)
            .query(`
                SELECT p.id, p.hourlyRate, u.firstName, u.lastName 
                FROM PsychologistProfiles p
                JOIN Users u ON p.userId = u.id
                WHERE p.id = @psychologistId
            `);

        if (psychologist.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Psicólogo no encontrado' });
        }

        const psychologistData = psychologist.recordset[0];
        const amount = psychologistData.hourlyRate + 5; // Tarifa + comisión

        // Verificar cuenta bancaria del psicólogo
        const psychologistAccount = await poolConnect.request()
            .input('psychologistId', sql.Int, psychologistId)
            .query(`
                SELECT b.id 
                FROM BankAccounts b
                JOIN PsychologistProfiles p ON b.userId = p.userId
                WHERE p.id = @psychologistId AND b.isVerified = 1
            `);

        if (psychologistAccount.recordset.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El psicólogo no tiene una cuenta bancaria verificada' 
            });
        }

        const receiverAccountId = psychologistAccount.recordset[0].id;

        // Generar referencia SINPE
        const sinpeReference = 'SM-' + Math.random().toString(36).substring(2, 10).toUpperCase();

        // Crear transacción sin requerir userId
        const transaction = await poolConnect.request()
            .input('psychologistId', sql.Int, psychologistId)
            .input('amount', sql.Decimal(10, 2), amount)
            .input('description', sql.NVarChar, `Cita con ${psychologistData.firstName} ${psychologistData.lastName}`)
            .input('receiverPhone', sql.NVarChar, phoneNumber)
            .input('sinpeReference', sql.NVarChar, sinpeReference)
            .input('receiverAccountId', sql.Int, receiverAccountId)
            .query(`
                INSERT INTO Transactions (
                    psychologistId, amount, description, 
                    status, transactionType, createdAt, 
                    receiverPhone, sinpeReference,
                    receiverAccountId
                )
                OUTPUT INSERTED.id
                VALUES (
                    @psychologistId, @amount, @description,
                    'completed', 'sinpe', GETDATE(),
                    @receiverPhone, @sinpeReference,
                    @receiverAccountId
                )
            `);

        const transactionId = transaction.recordset[0].id;

        // Actualizar saldo del psicólogo
        await poolConnect.request()
            .input('accountId', sql.Int, receiverAccountId)
            .input('amount', sql.Decimal(10, 2), amount)
            .query(`
                UPDATE BankAccounts 
                SET balance = balance + @amount 
                WHERE id = @accountId
            `);

        res.json({
            success: true,
            transactionId,
            sinpeReference,
            amount,
            message: 'Pago con SINPE Móvil completado exitosamente'
        });

    } catch (error) {
        console.error('Error en process-sinpe:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al procesar pago SINPE',
            error: error.message 
        });
    }
});








//PAgos Sinpe




app.post('/api/payments/sinpe/initiate', async (req, res) => {
    const { senderPaymentMethodId, receiverPhone, amount } = req.body;
    const userId = req.user.id;
    
    try {
        // Verificar que el método de pago pertenece al usuario
        const paymentMethodCheck = await poolConnect.request()
            .input('id', sql.Int, senderPaymentMethodId)
            .input('userId', sql.Int, userId)
            .query('SELECT id, balance FROM UserPaymentMethods WHERE id = @id AND userId = @userId');
            
        if (paymentMethodCheck.recordset.length === 0) {
            return res.status(400).json({ error: 'Método de pago no válido' });
        }
        
        // Verificar saldo suficiente
        if (paymentMethodCheck.recordset[0].balance < amount) {
            return res.status(400).json({ error: 'Saldo insuficiente' });
        }
        
        // Verificar que el teléfono receptor está registrado y verificado
        const receiverCheck = await poolConnect.request()
            .input('phoneNumber', sql.NVarChar, receiverPhone)
            .query(`
                SELECT u.id as userId, s.paymentMethodId
                FROM SinpeMovilAssociations s
                JOIN Users u ON s.userId = u.id
                WHERE s.phoneNumber = @phoneNumber AND s.isVerified = 1
            `);
            
        if (receiverCheck.recordset.length === 0) {
            return res.status(400).json({ error: 'Teléfono receptor no válido o no verificado' });
        }
        
        const receiver = receiverCheck.recordset[0];
        
        // Crear transacción pendiente
        const transaction = await poolConnect.request()
            .input('senderUserId', sql.Int, userId)
            .input('receiverUserId', sql.Int, receiver.userId)
            .input('amount', sql.Decimal(10, 2), amount)
            .input('senderPaymentMethodId', sql.Int, senderPaymentMethodId)
            .input('receiverPaymentMethodId', sql.Int, receiver.paymentMethodId)
            .input('senderPhone', sql.NVarChar, req.body.senderPhone)
            .input('receiverPhone', sql.NVarChar, receiverPhone)
            .query(`
                INSERT INTO Transactions (
                    senderUserId, receiverUserId, amount, status, transactionType,
                    senderPhone, receiverPhone, paymentMethodId, createdAt
                )
                VALUES (
                    @senderUserId, @receiverUserId, @amount, 'pending', 'sinpe_movil',
                    @senderPhone, @receiverPhone, @senderPaymentMethodId, GETDATE()
                )
                SELECT SCOPE_IDENTITY() AS transactionId;
            `);
        
        // Generar código de confirmación
        const confirmationCode = Math.floor(1000 + Math.random() * 9000).toString();
        
        await poolConnect.request()
            .input('transactionId', sql.Int, transaction.recordset[0].transactionId)
            .input('confirmationCode', sql.NVarChar, confirmationCode)
            .query(`
                UPDATE Transactions 
                SET confirmationCode = @confirmationCode
                WHERE id = @transactionId
            `);
        
        // En producción, enviar código por SMS al usuario
        console.log(`Código de confirmación para transacción ${transaction.recordset[0].transactionId}: ${confirmationCode}`);
        
        res.json({
            success: true,
            transactionId: transaction.recordset[0].transactionId,
            nextStep: 'confirm' // Indica que el siguiente paso es confirmar con el código
        });
        
    } catch (err) {
        console.error('Error iniciando pago SINPE:', err);
        res.status(500).json({ error: 'Error iniciando pago' });
    }
});



app.post('/api/payments/sinpe/confirm', async (req, res) => {
    const { transactionId, confirmationCode } = req.body;
    const userId = req.user.id;
    
    try {
        // Verificar transacción
        const transaction = await poolConnect.request()
            .input('transactionId', sql.Int, transactionId)
            .input('senderUserId', sql.Int, userId)
            .query(`
                SELECT id, senderUserId, receiverUserId, amount, status, 
                       senderPaymentMethodId, receiverPaymentMethodId, confirmationCode
                FROM Transactions
                WHERE id = @transactionId AND senderUserId = @senderUserId
            `);
            
        if (transaction.recordset.length === 0) {
            return res.status(404).json({ error: 'Transacción no encontrada' });
        }
        
        const tx = transaction.recordset[0];
        
        // Validar estado
        if (tx.status !== 'pending') {
            return res.status(400).json({ error: 'Transacción ya procesada' });
        }
        
        // Validar código de confirmación
        if (tx.confirmationCode !== confirmationCode) {
            return res.status(400).json({ error: 'Código de confirmación incorrecto' });
        }
        
        // Iniciar transacción SQL para asegurar consistencia
        const sqlTransaction = new sql.Transaction(poolConnect);
        await sqlTransaction.begin();
        
        try {
            const request = new sql.Request(sqlTransaction);
            
            // 1. Descontar del saldo del remitente
            await request
                .input('paymentMethodId', sql.Int, tx.senderPaymentMethodId)
                .input('amount', sql.Decimal(10, 2), tx.amount)
                .query(`
                    UPDATE UserPaymentMethods
                    SET balance = balance - @amount
                    WHERE id = @paymentMethodId AND balance >= @amount
                `);
                
            // Verificar que se actualizó el saldo
            const updatedBalance = await request
                .input('paymentMethodId', sql.Int, tx.senderPaymentMethodId)
                .query('SELECT balance FROM UserPaymentMethods WHERE id = @paymentMethodId');
                
            if (updatedBalance.recordset[0].balance < 0) {
                throw new Error('Saldo insuficiente después de verificación');
            }
            
            // 2. Acreditar al destinatario
            await request
                .input('paymentMethodId', sql.Int, tx.receiverPaymentMethodId)
                .input('amount', sql.Decimal(10, 2), tx.amount)
                .query(`
                    UPDATE UserPaymentMethods
                    SET balance = balance + @amount
                    WHERE id = @paymentMethodId
                `);
                
            // 3. Marcar transacción como completada
            await request
                .input('transactionId', sql.Int, tx.id)
                .query(`
                    UPDATE Transactions
                    SET status = 'completed',
                        confirmationCode = NULL,
                        createdAt = GETDATE()
                    WHERE id = @transactionId
                `);
                
            // Generar referencia SINPE
            const sinpeReference = `SM${tx.id.toString().padStart(8, '0')}`;
            await request
                .input('transactionId', sql.Int, tx.id)
                .input('sinpeReference', sql.NVarChar, sinpeReference)
                .query(`
                    UPDATE Transactions
                    SET sinpeReference = @sinpeReference
                    WHERE id = @transactionId
                `);
                
            // Commit de la transacción
            await sqlTransaction.commit();
            
            // Registrar en el log de auditoría
            await poolConnect.request()
                .input('userId', sql.Int, userId)
                .input('actionType', sql.NVarChar, 'sinpe_payment')
                .input('tableAffected', sql.NVarChar, 'Transactions')
                .input('recordId', sql.Int, tx.id)
                .input('newValues', sql.NVarChar, JSON.stringify({
                    amount: tx.amount,
                    receiver: tx.receiverPhone,
                    reference: sinpeReference
                }))
                .query(`
                    INSERT INTO AuditLogs
                    (userId, actionType, tableAffected, recordId, newValues, status, createdAt)
                    VALUES
                    (@userId, @actionType, @tableAffected, @recordId, @newValues, 'success', GETDATE())
                `);
            
            res.json({
                success: true,
                reference: sinpeReference,
                newBalance: updatedBalance.recordset[0].balance
            });
            
        } catch (err) {
            await sqlTransaction.rollback();
            throw err;
        }
        
    } catch (err) {
        console.error('Error confirmando pago SINPE:', err);
        res.status(500).json({ error: 'Error confirmando pago', details: err.message });
    }
});

app.post('/api/sinpe/verify-phone', authenticateJWT, async (req, res) => {
    const { phoneNumber, verificationCode } = req.body;
    const userId = req.user.id;

    try {
        // Validaciones
        if (!phoneNumber || !verificationCode) {
            return res.status(400).json({ success: false, message: 'Datos incompletos' });
        }

        // Verificar código
        const verification = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .input('verificationCode', sql.NVarChar, verificationCode)
            .query(`
                SELECT verificationExpiry 
                FROM SinpeMovilAssociations 
                WHERE userId = @userId 
                  AND phoneNumber = @phoneNumber 
                  AND verificationCode = @verificationCode
                  AND isVerified = 0
            `);

        if (verification.recordset.length === 0) {
            return res.status(400).json({ success: false, message: 'Código inválido o expirado' });
        }

        const expiryDate = new Date(verification.recordset[0].verificationExpiry);
        if (expiryDate < new Date()) {
            return res.status(400).json({ success: false, message: 'Código expirado' });
        }

        // Marcar como verificado
        await poolConnect.request()
            .input('userId', sql.Int, userId)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .query(`
                UPDATE SinpeMovilAssociations 
                SET isVerified = 1,
                    verificationCode = NULL,
                    verificationExpiry = NULL,
                    updatedAt = GETDATE()
                WHERE userId = @userId AND phoneNumber = @phoneNumber
            `);

        res.json({ 
            success: true, 
            message: 'Teléfono verificado exitosamente' 
        });

    } catch (error) {
        console.error('Error en verify-phone:', error);
        res.status(500).json({ success: false, message: 'Error verificando teléfono' });
    }
});

// API para enviar código de verificación
app.post('/api/sinpe/send-code', async (req, res) => {
    const { userId, phoneNumber } = req.body;
    
    try {
        let verificationCode = '';
        const request = poolConnect.request();
        
        // Verificar si ya existe una asociación
        const checkResult = await request
            .input('userId', sql.Int, userId)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .query(`
                SELECT id FROM SinpeMovilAssociations 
                WHERE userId = @userId AND phoneNumber = @phoneNumber
            `);
        
        // Generar código de 6 dígitos
        verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        if (checkResult.recordset.length > 0) {
            // Actualizar asociación existente
            await request
                .input('verificationCode', sql.NVarChar, verificationCode)
                .input('verificationExpiry', sql.DateTime2, new Date(Date.now() + 15 * 60000)) // 15 minutos
                .query(`
                    UPDATE SinpeMovilAssociations 
                    SET verificationCode = @verificationCode,
                        verificationExpiry = @verificationExpiry,
                        isVerified = 0,
                        updatedAt = GETDATE()
                    WHERE userId = @userId AND phoneNumber = @phoneNumber
                `);
        } else {
            // Crear nueva asociación (necesitamos un paymentMethodId)
            const paymentMethodResult = await poolConnect.request()
                .input('userId', sql.Int, userId)
                .query(`
                    SELECT TOP 1 id FROM UserPaymentMethods 
                    WHERE userId = @userId 
                    ORDER BY isDefault DESC, createdAt DESC
                `);
            
            if (paymentMethodResult.recordset.length === 0) {
                return res.status(400).json({ error: 'El usuario no tiene métodos de pago registrados' });
            }
            
            const paymentMethodId = paymentMethodResult.recordset[0].id;
            
            await poolConnect.request()
                .input('userId', sql.Int, userId)
                .input('phoneNumber', sql.NVarChar, phoneNumber)
                .input('paymentMethodId', sql.Int, paymentMethodId)
                .input('verificationCode', sql.NVarChar, verificationCode)
                .input('verificationExpiry', sql.DateTime2, new Date(Date.now() + 15 * 60000))
                .query(`
                    INSERT INTO SinpeMovilAssociations 
                    (userId, phoneNumber, paymentMethodId, verificationCode, verificationExpiry, isVerified)
                    VALUES 
                    (@userId, @phoneNumber, @paymentMethodId, @verificationCode, @verificationExpiry, 0)
                `);
        }
        
        // En producción, aquí se enviaría el código por SMS al teléfono
        console.log(`Código de verificación SINPE para ${phoneNumber}: ${verificationCode}`);
        
        res.json({ success: true, message: 'Código de verificación enviado' });
    } catch (err) {
        console.error('Error enviando código:', err);
        res.status(500).json({ error: 'Error enviando código de verificación' });
    }
});

// API para verificar código
app.post('/api/sinpe/verify-code', async (req, res) => {
    const { userId, phoneNumber, verificationCode } = req.body;
    
    try {
        const result = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .input('verificationCode', sql.NVarChar, verificationCode)
            .query(`
                SELECT verificationExpiry 
                FROM SinpeMovilAssociations 
                WHERE userId = @userId 
                  AND phoneNumber = @phoneNumber 
                  AND verificationCode = @verificationCode
                  AND isVerified = 0
            `);
        
        if (result.recordset.length === 0) {
            return res.status(400).json({ error: 'Código inválido o expirado' });
        }
        
        const expiryDate = new Date(result.recordset[0].verificationExpiry);
        if (expiryDate < new Date()) {
            return res.status(400).json({ error: 'Código expirado' });
        }
        
        // Marcar como verificado
        await poolConnect.request()
            .input('userId', sql.Int, userId)
            .input('phoneNumber', sql.NVarChar, phoneNumber)
            .query(`
                UPDATE SinpeMovilAssociations 
                SET isVerified = 1,
                    verificationCode = NULL,
                    verificationExpiry = NULL,
                    updatedAt = GETDATE()
                WHERE userId = @userId AND phoneNumber = @phoneNumber
            `);
        
        res.json({ success: true, message: 'Teléfono verificado exitosamente' });
    } catch (err) {
        console.error('Error verificando código:', err);
        res.status(500).json({ error: 'Error verificando código' });
    }
});

// API para realizar pago con SINPE
app.post('/api/sinpe/make-payment', async (req, res) => {
    try {
        const { userId, phoneNumber, amount, psychologistId, description } = req.body;
        
        // Validaciones
        if (!userId || !phoneNumber || !amount || !psychologistId) {
            return res.status(400).json({ success: false, message: 'Datos incompletos' });
        }
        
        // Verificar si el usuario tiene cuenta bancaria verificada
        const accountQuery = `
            SELECT id FROM BankAccounts 
            WHERE userId = @userId AND isVerified = 1`;
        
        const accountResult = await db.query(accountQuery, { userId });
        
        if (accountResult.recordset.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No tienes una cuenta bancaria verificada' 
            });
        }
        
        const senderAccountId = accountResult.recordset[0].id;
        
        // Verificar cuenta del psicólogo
        const psychologistQuery = `
            SELECT p.id, u.id as userId 
            FROM PsychologistProfiles p
            JOIN Users u ON p.userId = u.id
            WHERE p.id = @psychologistId`;
        
        const psychologistResult = await db.query(psychologistQuery, { psychologistId });
        
        if (psychologistResult.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Psicólogo no encontrado' });
        }
        
        const psychologistUserId = psychologistResult.recordset[0].userId;
        
        // Verificar cuenta bancaria del psicólogo
        const psychologistAccountQuery = `
            SELECT id FROM BankAccounts 
            WHERE userId = @psychologistUserId AND isVerified = 1`;
        
        const psychologistAccountResult = await db.query(psychologistAccountQuery, { psychologistUserId });
        
        if (psychologistAccountResult.recordset.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El psicólogo no tiene una cuenta bancaria verificada' 
            });
        }
        
        const receiverAccountId = psychologistAccountResult.recordset[0].id;
        
        // Generar referencia SINPE
        const sinpeReference = 'SINPE-' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        // Crear transacción
        const transactionQuery = `
            INSERT INTO Transactions (
                userId, psychologistId, amount, description, 
                status, transactionType, createdAt, 
                receiverPhone, sinpeReference,
                senderAccountId, receiverAccountId
            )
            OUTPUT INSERTED.id
            VALUES (
                @userId, @psychologistId, @amount, @description,
                'pending', 'sinpe', GETDATE(),
                @phoneNumber, @sinpeReference,
                @senderAccountId, @receiverAccountId
            )`;
        
        const transactionResult = await db.query(transactionQuery, {
            userId, psychologistId, amount, description,
            phoneNumber, sinpeReference,
            senderAccountId, receiverAccountId
        });
        
        const transactionId = transactionResult.recordset[0].id;
        
        // Simular procesamiento de SINPE
        setTimeout(async () => {
            try {
                // Actualizar saldos y estado de transacción
                await db.query('BEGIN TRANSACTION');
                
                // Descontar del remitente
                await db.query(`
                    UPDATE BankAccounts 
                    SET balance = balance - @amount
                    WHERE id = @senderAccountId`,
                    { amount, senderAccountId });
                
                // Acreditar al destinatario
                await db.query(`
                    UPDATE BankAccounts 
                    SET balance = balance + @amount
                    WHERE id = @receiverAccountId`,
                    { amount, receiverAccountId });
                
                // Marcar transacción como completada
                await db.query(`
                    UPDATE Transactions 
                    SET status = 'completed', completedAt = GETDATE()
                    WHERE id = @transactionId`, 
                    { transactionId });
                
                await db.query('COMMIT TRANSACTION');
                
            } catch (updateError) {
                await db.query('ROLLBACK TRANSACTION');
                console.error('Error actualizando transacción SINPE:', updateError);
                
                // Marcar transacción como fallida
                await db.query(`
                    UPDATE Transactions 
                    SET status = 'failed'
                    WHERE id = @transactionId`, 
                    { transactionId });
            }
        }, 1000);
        
        res.json({
            success: true,
            transactionId,
            reference: sinpeReference,
            message: 'Transacción SINPE iniciada exitosamente'
        });
        
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'Error al procesar pago SINPE' });
    }
});




























//Psicologos

app.post('/api/psychologists', async (req, res) => {
    const {
        userId,
        licenseNumber,
        specialties,
        experience,
        education,
        languages,
        hourlyRate,
        bio,
        availability
    } = req.body;

    // Validaciones básicas
    if (!userId || !licenseNumber || !specialties || !experience || !education || 
        !languages || !hourlyRate || !bio || !availability) {
        return res.status(400).json({ 
            success: false, 
            message: 'Todos los campos son requeridos' 
        });
    }

    try {
        await sql.connect(dbConfig);

        // Verificar si el usuario ya tiene un perfil de psicólogo
        const existingProfile = await sql.query`
            SELECT id FROM PsychologistProfiles WHERE userId = ${userId}
        `;

        if (existingProfile.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Este usuario ya tiene un perfil de psicólogo registrado' 
            });
        }

        // Verificar si el usuario existe y es psicólogo
        const userCheck = await sql.query`
            SELECT id, userType FROM Users WHERE id = ${userId} AND isActive = 1
        `;

        if (userCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado o inactivo' 
            });
        }

        if (userCheck.recordset[0].userType !== 'psychologist') {
            return res.status(400).json({ 
                success: false, 
                message: 'El usuario no es de tipo psicólogo' 
            });
        }

        // Insertar nuevo perfil de psicólogo
        const result = await sql.query`
            INSERT INTO PsychologistProfiles (
                userId, licenseNumber, specialties, experience, 
                education, languages, hourlyRate, bio, availability
            )
            VALUES (
                ${userId}, ${licenseNumber}, ${specialties}, ${parseInt(experience)}, 
                ${education}, ${languages}, ${parseFloat(hourlyRate)}, ${bio}, ${availability}
            )
            
            SELECT SCOPE_IDENTITY() AS newId;
        `;

        const newProfileId = result.recordset[0].newId;

        res.json({ 
            success: true, 
            profileId: newProfileId,
            message: 'Perfil de psicólogo creado exitosamente'
        });
    } catch (err) {
        console.error('Error al crear perfil de psicólogo:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al crear el perfil de psicólogo' 
        });
    } finally {
        sql.close();
    }
});


app.get('/api/psychologists', async (req, res) => {
  try {
    const result = await poolConnect.request()
      .query(`
        SELECT 
          p.id, p.userId, u.firstName, u.lastName, p.licenseNumber,
          p.specialties, p.experience, p.education, p.languages,
          p.hourlyRate, p.bio, p.availability, p.rating, 
          p.totalReviews, p.isVerified
        FROM PsychologistProfiles p
        JOIN Users u ON p.userId = u.id
        WHERE u.isActive = 1
      `);
    
    // Función de normalización mejorada
    const ensureArray = (data) => {
      if (Array.isArray(data)) return data;
      if (!data) return [];
      if (typeof data === 'string' && data.startsWith('[')) {
        try {
          const parsed = JSON.parse(data);
          return Array.isArray(parsed) ? parsed : [parsed];
        } catch {
          return data.split(',').map(item => item.trim());
        }
      }
      return data.split(',').map(item => item.trim());
    };
    
    const psychologists = result.recordset.map(p => ({
      ...p,
      specialties: ensureArray(p.specialties),
      languages: ensureArray(p.languages),
      education: ensureArray(p.education),
      hourlyRate: parseFloat(p.hourlyRate) || 0
    }));
    
    res.json(psychologists);
  } catch (err) {
    console.error('Error fetching psychologists:', err);
    res.status(500).json({ error: 'Error al obtener psicólogos' });
  }
});





//Verificacion de psicologos

app.get('/api/psychologists/verify/:userId', async (req, res) => {
    const userId = parseInt(req.params.userId);

    if (isNaN(userId)) {
        return res.status(400).json({ 
            success: false, 
            message: 'El ID del psicólogo debe ser un número' 
        });
    }

    try {
        // 1. Verificar si el usuario existe en LIANZE_DB y es psicólogo
        const userCheck = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .query(`
                SELECT u.id, u.firstName, u.lastName, p.id as profileId, p.licenseNumber
                FROM [tiusr24pl_Lianze].[dbo].[Users] u
                LEFT JOIN [tiusr24pl_Lianze].[dbo].[PsychologistProfiles] p ON u.id = p.userId
                WHERE u.id = @userId AND u.isActive = 1
            `);

        if (userCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'No se encontró un usuario activo con ese ID' 
            });
        }

        const user = userCheck.recordset[0];
        const fullName = `${user.firstName} ${user.lastName}`;

        // 2. Buscar en COLEGIO_PSICOLOGOS_DB
        const colegioCheck = await poolConnect.request()
            .input('userId', sql.Int, userId)
            .query(`
                SELECT 
                    p.id,
                    p.licenciaNumber,
                    c.nombre as colegio,
                    p.fechaRegistro,
                    p.fechaExpiracion,
                    p.estatus,
                    p.isVerified,
                    p.fechaVerificacion,
                    u.firstName + ' ' + u.lastName as nombreCompleto
                FROM [tiusr24pl_COLEGIO_PSICOLOGOS_DB].[dbo].[PsicologosRegistrados] p
                JOIN [tiusr24pl_COLEGIO_PSICOLOGOS_DB].[dbo].[ColegiosPsicologos] c ON p.colegioId = c.id
                JOIN [tiusr24pl_Lianze].[dbo].[Users] u ON p.userId = u.id
                WHERE p.userId = @userId
            `);

        if (colegioCheck.recordset.length > 0) {
            const psicologo = colegioCheck.recordset[0];
            
            return res.json({
                success: true,
                isVerified: psicologo.isVerified,
                psychologist: {
                    nombreCompleto: psicologo.nombreCompleto,
                    licenciaNumber: psicologo.licenciaNumber,
                    colegio: psicologo.colegio,
                    fechaRegistro: psicologo.fechaRegistro,
                    fechaExpiracion: psicologo.fechaExpiracion,
                    estatus: psicologo.estatus,
                    isVerified: psicologo.isVerified,
                    fechaVerificacion: psicologo.fechaVerificacion
                }
            });
        } else {
            return res.json({
                success: true,
                isVerified: false,
                message: 'El psicólogo no está registrado en el Colegio de Psicólogos'
            });
        }
    } catch (err) {
        console.error('Error verificando psicólogo:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al verificar el psicólogo en el Colegio de Psicólogos' 
        });
    }
});




//entradas diario

// GET /api/diary-entries - Obtener todas las entradas del usuario
app.get('/api/diary-entries', authenticateJWT, async (req, res) => {
    // Obtén el userId del token JWT en lugar de req.userId
    const userId = req.user.id; // Cambia esta línea
    
    if (!userId) {
        return res.status(401).json({ 
            success: false, 
            message: 'Usuario no autenticado' 
        });
    }

    try {
        await sql.connect(dbConfig);

        const result = await sql.query`
            SELECT 
                id, date, mood, emotions, notes, activities, 
                sleepHours, stressLevel, createdAt, updatedAt
            FROM DiaryEntries 
            WHERE userId = ${userId}
            ORDER BY date DESC, createdAt DESC
        `;

        res.json({ 
            success: true, 
            entries: result.recordset 
        });
    } catch (err) {
        console.error('Error al obtener entradas del diario:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener las entradas del diario' 
        });
    } finally {
        sql.close();
    }
});

// POST /api/diary-entries - Crear una nueva entrada
app.post('/api/diary-entries', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    
    const {
        date,
        mood,
        emotions,
        notes,
        activities,
        sleepHours,
        stressLevel
    } = req.body;

    // Validaciones básicas
    if (!date || !mood || !notes) {
        return res.status(400).json({ 
            success: false, 
            message: 'Fecha, estado de ánimo y notas son campos requeridos' 
        });
    }

    // Validar rango de mood (1-10)
    if (mood < 1 || mood > 10) {
        return res.status(400).json({ 
            success: false, 
            message: 'El estado de ánimo debe estar entre 1 y 10' 
        });
    }

    // Validar rango de stressLevel si se proporciona
    if (stressLevel && (stressLevel < 1 || stressLevel > 10)) {
        return res.status(400).json({ 
            success: false, 
            message: 'El nivel de estrés debe estar entre 1 y 10' 
        });
    }

    try {
        await sql.connect(dbConfig);

        // Verificar si ya existe una entrada para esta fecha
        const existingEntry = await sql.query`
            SELECT id FROM DiaryEntries 
            WHERE userId = ${userId} AND date = ${date}
        `;

        if (existingEntry.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Ya existe una entrada para esta fecha' 
            });
        }

        // Insertar nueva entrada
        const result = await sql.query`
            INSERT INTO DiaryEntries (
                userId, date, mood, emotions, notes, 
                activities, sleepHours, stressLevel
            )
            VALUES (
                ${userId}, ${date}, ${parseInt(mood)}, ${emotions}, ${notes}, 
                ${activities}, ${sleepHours ? parseFloat(sleepHours) : null}, 
                ${stressLevel ? parseInt(stressLevel) : null}
            )
            
            SELECT SCOPE_IDENTITY() AS newId;
        `;

        const newEntryId = result.recordset[0].newId;

        res.status(201).json({ 
            success: true, 
            entryId: newEntryId,
            message: 'Entrada del diario creada exitosamente'
        });
    } catch (err) {
        console.error('Error al crear entrada del diario:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al crear la entrada del diario' 
        });
    } finally {
        sql.close();
    }
});

// PUT /api/diary-entries/:id - Actualizar una entrada existente
app.put('/api/diary-entries/:id', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    const entryId = req.params.id;
    
    const {
        date,
        mood,
        emotions,
        notes,
        activities,
        sleepHours,
        stressLevel
    } = req.body;

    // Validaciones básicas
    if (!date || !mood || !notes) {
        return res.status(400).json({ 
            success: false, 
            message: 'Fecha, estado de ánimo y notas son campos requeridos' 
        });
    }

    try {
        await sql.connect(dbConfig);

        // Verificar que la entrada existe y pertenece al usuario
        const existingEntry = await sql.query`
            SELECT id FROM DiaryEntries 
            WHERE id = ${entryId} AND userId = ${userId}
        `;

        if (existingEntry.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Entrada no encontrada' 
            });
        }

        // Verificar si ya existe otra entrada para la nueva fecha
        const dateConflict = await sql.query`
            SELECT id FROM DiaryEntries 
            WHERE userId = ${userId} AND date = ${date} AND id != ${entryId}
        `;

        if (dateConflict.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Ya existe otra entrada para esta fecha' 
            });
        }

        // Actualizar la entrada
        await sql.query`
            UPDATE DiaryEntries 
            SET 
                date = ${date},
                mood = ${parseInt(mood)},
                emotions = ${emotions},
                notes = ${notes},
                activities = ${activities},
                sleepHours = ${sleepHours ? parseFloat(sleepHours) : null},
                stressLevel = ${stressLevel ? parseInt(stressLevel) : null},
                updatedAt = GETDATE()
            WHERE id = ${entryId} AND userId = ${userId}
        `;

        res.json({ 
            success: true,
            message: 'Entrada actualizada exitosamente'
        });
    } catch (err) {
        console.error('Error al actualizar entrada del diario:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar la entrada del diario' 
        });
    } finally {
        sql.close();
    }
});

// DELETE /api/diary-entries/:id - Eliminar una entrada
app.delete('/api/diary-entries/:id', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    const entryId = req.params.id;

    try {
        await sql.connect(dbConfig);

        // Verificar que la entrada existe y pertenece al usuario
        const existingEntry = await sql.query`
            SELECT id FROM DiaryEntries 
            WHERE id = ${entryId} AND userId = ${userId}
        `;

        if (existingEntry.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Entrada no encontrada' 
            });
        }

        // Eliminar la entrada
        await sql.query`
            DELETE FROM DiaryEntries 
            WHERE id = ${entryId} AND userId = ${userId}
        `;

        res.json({ 
            success: true,
            message: 'Entrada eliminada exitosamente'
        });
    } catch (err) {
        console.error('Error al eliminar entrada del diario:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al eliminar la entrada del diario' 
        });
    } finally {
        sql.close();
    }
});




// GET /api/diary-entries/:id - Obtener una entrada específica
app.get('/api/diary-entries/:id', authenticateJWT, async (req, res) => {
    const userId = req.user.id;
    const entryId = req.params.id;

    try {
        await sql.connect(dbConfig);

        const result = await sql.query`
            SELECT 
                id, date, mood, emotions, notes, activities, 
                sleepHours, stressLevel, createdAt, updatedAt
            FROM DiaryEntries 
            WHERE id = ${entryId} AND userId = ${userId}
        `;

        if (result.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Entrada no encontrada' 
            });
        }

        res.json({ 
            success: true, 
            entry: result.recordset[0] 
        });
    } catch (err) {
        console.error('Error al obtener entrada del diario:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener la entrada del diario' 
        });
    } finally {
        sql.close();
    }
});



//Fin diario

// Filter psychologists

app.get('/api/psychologists/filter', async (req, res) => {
  const { specialty, language, maxPrice } = req.query;
  
  try {
    // Obtener todos los psicólogos activos
    const allPsychologists = await poolConnect.request()
      .query(`
        SELECT 
          p.id, p.userId, u.firstName, u.lastName, p.licenseNumber,
          p.specialties, p.experience, p.education, p.languages,
          p.hourlyRate, p.bio, p.availability, p.rating, 
          p.totalReviews, p.isVerified
        FROM PsychologistProfiles p
        JOIN Users u ON p.userId = u.id
        WHERE u.isActive = 1
      `);
    
    // Función mejorada para normalizar cualquier formato de datos
    const normalizeArrayData = (data) => {
      if (!data) return [];
      
      // Si ya es un array, devolverlo directamente
      if (Array.isArray(data)) return data;
      
      // Si es un string que parece JSON (contiene [ o {)
      if (typeof data === 'string' && (data.includes('[') || data.includes('"'))) {
        try {
          const parsed = JSON.parse(data);
          if (Array.isArray(parsed)) return parsed;
          if (typeof parsed === 'string') return parsed.split(',').map(item => item.trim());
          return [String(parsed)];
        } catch {
          // Si falla el parseo JSON, tratar como string normal
          return data.split(',').map(item => item.trim());
        }
      }
      
      // Si es un string normal separado por comas
      if (typeof data === 'string') {
        return data.split(',')
          .map(item => item.trim())
          .filter(item => item.length > 0)
          .map(item => item.replace(/[\[\]"]+/g, '').trim());
      }
      
      // Para cualquier otro caso (números, etc.)
      return [String(data)];
    };
    
    // Procesar y filtrar los psicólogos
    const filteredPsychologists = allPsychologists.recordset
      .map(psychologist => {
        // Normalizar los datos
        const specialties = normalizeArrayData(psychologist.specialties);
        const languages = normalizeArrayData(psychologist.languages);
        const education = normalizeArrayData(psychologist.education);
        
        return {
          ...psychologist,
          specialties,
          languages,
          education,
          // Asegurar que hourlyRate sea número
          hourlyRate: psychologist.hourlyRate ? parseFloat(psychologist.hourlyRate) : 0
        };
      })
      .filter(psychologist => {
        // Aplicar filtros
        let matches = true;
        
        // Filtro por especialidad (búsqueda insensible a mayúsculas y sin caracteres especiales)
        if (specialty) {
          matches = matches && psychologist.specialties.some(s => 
            s.toLowerCase().replace(/[^a-z0-9áéíóúüñ]/g, '')
             .includes(specialty.toLowerCase().replace(/[^a-z0-9áéíóúüñ]/g, ''))
          );
        }
        
        // Filtro por idioma (búsqueda insensible a mayúsculas y sin caracteres especiales)
        if (language) {
          matches = matches && psychologist.languages.some(l => 
            l.toLowerCase().replace(/[^a-z0-9áéíóúüñ]/g, '')
             .includes(language.toLowerCase().replace(/[^a-z0-9áéíóúüñ]/g, ''))
          );
        }
        
        // Filtro por precio máximo
        if (maxPrice) {
          matches = matches && psychologist.hourlyRate <= parseFloat(maxPrice);
        }
        
        return matches;
      });
    
    res.json(filteredPsychologists);
  } catch (err) {
    console.error('Error filtering psychologists:', err);
    res.status(500).json({ error: 'Error filtering psychologists' });
  }
});


// Nueva ruta para obtener datos de filtros
app.get('/api/psychologists/filters-data', async (req, res) => {
    try {
        const psychologists = await poolConnect.request()
            .query(`
                SELECT specialties, languages 
                FROM PsychologistProfiles
                JOIN Users ON PsychologistProfiles.userId = Users.id
                WHERE Users.isActive = 1
            `);
        
        // Procesar para obtener valores únicos
        const specialtiesSet = new Set();
        const languagesSet = new Set();
        
        psychologists.recordset.forEach(psych => {
            // Procesar especialidades
            const specialties = normalizeArrayData(psych.specialties);
            specialties.forEach(s => specialtiesSet.add(s));
            
            // Procesar idiomas
            const languages = normalizeArrayData(psych.languages);
            languages.forEach(l => languagesSet.add(l));
        });
        
        res.json({
            specialties: Array.from(specialtiesSet).sort(),
            languages: Array.from(languagesSet).sort()
        });
        
    } catch (err) {
        console.error('Error fetching filter data:', err);
        res.status(500).json({ error: 'Error al obtener datos de filtros' });
    }
});

// Función auxiliar para asegurar arrays (ya existe en tu código)
function normalizeArrayData(data) {
    if (!data) return [];
    
    // Si ya es un array, devolverlo directamente
    if (Array.isArray(data)) return data;
    
    // Si es un string que parece JSON (contiene [ o {)
    if (typeof data === 'string' && (data.includes('[') || data.includes('"'))) {
        try {
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed)) return parsed;
            if (typeof parsed === 'string') return parsed.split(',').map(item => item.trim());
            return [String(parsed)];
        } catch {
            // Si falla el parseo JSON, tratar como string normal
            return data.split(',').map(item => item.trim());
        }
    }
    
    // Si es un string normal separado por comas
    if (typeof data === 'string') {
        return data.split(',')
          .map(item => item.trim())
          .filter(item => item.length > 0)
          .map(item => item.replace(/[\[\]"]+/g, '').trim());
    }
    
    // Para cualquier otro caso (números, etc.)
    return [String(data)];
}


app.get('/api/psychologists/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  
  if (isNaN(id)) {
    return res.status(400).json({ error: 'ID must be a number' });
  }
    try {
    await sql.connect(dbConfig);
    
    const result = await sql.query`
      SELECT 
        p.id, 
        p.userId,
        u.firstName,
        u.lastName,
        p.licenseNumber,
        p.specialties,
        p.experience,
        p.education,
        p.languages,
        p.hourlyRate,
        p.bio,
        p.availability,
        p.rating,
        p.totalReviews,
        p.isVerified
      FROM PsychologistProfiles p
      JOIN Users u ON p.userId = u.id
      WHERE p.id = ${req.params.id} AND u.isActive = 1
    `;
    
    if (result.recordset.length > 0) {
      res.json(result.recordset[0]);
    } else {
      res.status(404).json({ error: 'Psychologist not found' });
    }
  } catch (err) {
    console.error('Error fetching psychologist:', err);
    res.status(500).json({ error: 'Error fetching psychologist' });
  } finally {
    sql.close();
  }
});

// Función auxiliar para parsear JSON
function tryParseJSON(jsonString) {
  try {
    return JSON.parse(jsonString);
  } catch (e) {
    return null;
  }
}












//registro
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, email, password, userType, countryId, provinceId, cantonId, districtId } = req.body;

    // Validaciones básicas
    if (!firstName || !lastName || !email || !password || !userType || !countryId) {
        return res.status(400).json({ 
            success: false, 
            message: 'Todos los campos son requeridos' 
        });
    }

    // Validar tipo de usuario
    if (userType !== 'patient' && userType !== 'psychologist') {
        return res.status(400).json({ 
            success: false, 
            message: 'Tipo de usuario no válido' 
        });
    }

    // Validar nombre (backend)
    const nameRegex = /^[a-zA-Z0-9_.]{4,}$/;
    if (!nameRegex.test(firstName) || !nameRegex.test(lastName)) {
        return res.status(400).json({ 
            success: false, 
            message: 'El nombre y apellido deben tener al menos 4 caracteres y solo pueden contener letras, números, _ y .' 
        });
    }

    // Validar contraseña (backend)
    const passwordValidation = validatePassword(password, firstName, lastName);
    if (!passwordValidation.valid) {
        return res.status(400).json({ 
            success: false, 
            message: passwordValidation.message 
        });
    }

    try {
        await sql.connect(dbConfig);
        
        // Verificar si el email ya existe
        const emailCheck = await sql.query`
            SELECT id FROM Users WHERE email = ${email}
        `;

        if (emailCheck.recordset.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El correo electrónico ya está registrado' 
            });
        }

        const encryptedEmail = encrypt(email);
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Insertar nuevo usuario
         const result = await sql.query`
            INSERT INTO Users 
                (firstName, lastName, email, password, userType, 
                 country_id, province_id, canton_id, district_id, isActive, is_encrypted)
            VALUES 
                (${firstName}, ${lastName}, ${encryptedEmail}, ${hashedPassword}, ${userType},
                 ${countryId}, ${provinceId || null}, ${cantonId || null}, ${districtId || null}, 1, 1)
            
            SELECT SCOPE_IDENTITY() AS newId;
        `;
        
        const newUserId = result.recordset[0].newId;
    
    // Generar y guardar códigos de respaldo MFA (encriptados)
    const backupCodes = generateBackupCodes();
    for (const code of backupCodes) {
    await sql.query`
        INSERT INTO MFABackupCodes (userId, code, isUsed, is_encrypted)
        VALUES (${newUserId}, ${encrypt(code)}, 0, 1)
    `;
}

    res.json({ 
        success: true, 
        userId: newUserId,
        userType: userType,
        nextStep: 'security-questions',
        backupCodes: backupCodes // Enviar códigos en claro al cliente (solo esta vez)
    });
    } catch (err) {
        console.error('Error en el registro:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor al registrar usuario' 
        });
    } finally {
        sql.close();
    }
});



//preguntas de seguridad
app.post('/api/security-questions', async (req, res) => {
    const { userId, petName, favoriteColor, favoritePlace } = req.body;

    try {
        await sql.connect(dbConfig);
        
        // Encriptar preguntas de seguridad
        await sql.query`
            INSERT INTO SecurityQuestions 
                (userId, petName, favoriteColor, favoritePlace)
            VALUES 
                (${userId}, ${encrypt(petName)}, ${encrypt(favoriteColor)}, ${encrypt(favoritePlace)})
        `;
        
        res.json({ success: true, message: 'Preguntas de seguridad guardadas correctamente' });
    } catch (err) {
        console.error('Error al guardar preguntas de seguridad:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor al guardar preguntas de seguridad' 
        });
    } finally {
        sql.close();
    }
});


app.get('/api/security-questions/:userId', async (req, res) => {
    try {
        await sql.connect(dbConfig);
        
        const result = await sql.query`
            SELECT petName, favoriteColor, favoritePlace 
            FROM SecurityQuestions 
            WHERE userId = ${req.params.userId}
        `;
        
        if (result.recordset.length > 0) {
            const questions = result.recordset[0];
            // Desencriptar las respuestas
            res.json({
                success: true,
                questions: {
                    petName: decrypt(questions.petName),
                    favoriteColor: decrypt(questions.favoriteColor),
                    favoritePlace: decrypt(questions.favoritePlace)
                }
            });
        } else {
            res.status(404).json({ success: false, message: 'No se encontraron preguntas' });
        }
    } catch (err) {
        console.error('Error obteniendo preguntas de seguridad:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener preguntas de seguridad' 
        });
    } finally {
        sql.close();
    }
});

app.post('/api/verify-password', async (req, res) => {
    const { userId, password } = req.body;

    try {
        const pool = await poolConnect;
        const request = pool.request();
        
        // Obtener contraseña hasheada
        request.input('userId', sql.Int, userId);
        const result = await request.query('SELECT password FROM Users WHERE id = @userId');
        
        if (result.recordset.length === 0) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }
        
        const user = result.recordset[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (passwordMatch) {
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false, message: 'Contraseña incorrecta' });
        }
    } catch (err) {
        console.error('Error verificando contraseña:', err);
        res.status(500).json({ success: false, message: 'Error en el servidor' });
    }
});


// Endpoint para eliminar cuenta
app.post('/api/delete-account', async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requieren ID de usuario y contraseña' 
        });
    }

    try {
        await sql.connect(dbConfig);
        
        // 1. Verificar que el usuario existe y la contraseña es correcta
        const userResult = await sql.query`
            SELECT id FROM Users 
            WHERE id = ${userId} AND password = ${password} AND isActive = 1
        `;
        
        if (userResult.recordset.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Credenciales incorrectas o cuenta no encontrada' 
            });
        }

        // 2. Desactivar la cuenta
        await sql.query`
            UPDATE Users 
            SET isActive = 0, updatedAt = GETDATE()
            WHERE id = ${userId}
        `;
        
        // 3. Eliminar datos relacionados (opcional)
        try {
            await sql.query`DELETE FROM SecurityQuestions WHERE userId = ${userId}`;
            // Aquí puedes añadir más consultas para eliminar otros datos relacionados
        } catch (error) {
            console.error('Error eliminando datos relacionados:', error);
            // Continuamos aunque falle porque lo importante es desactivar la cuenta
        }
        
        res.json({
            success: true,
            message: 'Cuenta desactivada correctamente. Todos tus datos han sido eliminados.'
        });
    } catch (err) {
        console.error('Error desactivando cuenta:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor al desactivar la cuenta' 
        });
    } finally {
        sql.close();
    }
});

// Endpoint para actualizar email
app.post('/api/update-email', async (req, res) => {
    const { userId, newEmail } = req.body;

    try {
        await sql.connect(dbConfig);
        
        // Verificar si el nuevo email ya existe
        const emailCheck = await sql.query`
            SELECT id FROM Users WHERE email = ${newEmail} AND id != ${userId}
        `;
        
        if (emailCheck.recordset.length > 0) {
            return res.status(400).json({ success: false, message: 'El correo electrónico ya está en uso' });
        }

        // Actualizar email
        await sql.query`
            UPDATE Users 
            SET email = ${newEmail}, updatedAt = GETDATE()
            WHERE id = ${userId}
        `;
        
        res.json({
            success: true,
            message: 'Correo electrónico actualizado. Se ha enviado un correo de verificación.'
        });
    } catch (err) {
        console.error('Error actualizando email:', err);
        res.status(500).json({ success: false, message: 'Error actualizando email' });
    } finally {
        sql.close();
    }
});


// Endpoint para cambiar contraseña
app.post('/api/change-password', async (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;

    if (!userId || !currentPassword || !newPassword) {
        return res.status(400).json({ 
            success: false, 
            message: 'Todos los campos son requeridos' 
        });
    }

    try {
        await sql.connect(dbConfig);
        
        // 1. Verificar la contraseña actual
        const userCheck = await sql.query`
            SELECT id, firstName, lastName FROM Users 
            WHERE id = ${userId} AND password = ${currentPassword} AND isActive = 1
        `;
        
        if (userCheck.recordset.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Contraseña actual incorrecta' 
            });
        }

        const user = userCheck.recordset[0];
        
        // 2. Validar la nueva contraseña
        const passwordValidation = validatePassword(newPassword, user.firstName, user.lastName);
        if (!passwordValidation.valid) {
            return res.status(400).json({ 
                success: false, 
                message: passwordValidation.message 
            });
        }

        // 3. Actualizar la contraseña
        await sql.query`
            UPDATE Users 
            SET password = ${newPassword}, updatedAt = GETDATE()
            WHERE id = ${userId}
        `;
        
        res.json({
            success: true,
            message: 'Contraseña actualizada correctamente'
        });
    } catch (err) {
        console.error('Error cambiando contraseña:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al cambiar contraseña' 
        });
    } finally {
        sql.close();
    }
});






app.get('/api/migrate-encryption', async (req, res) => {
    if (process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ success: false, message: 'Solo disponible en desarrollo' });
    }

    try {
        await sql.connect(dbConfig);
        
        // Migrar usuarios
         const users = await sql.query`SELECT id, email FROM Users WHERE is_encrypted = 0`;
        for (const user of users.recordset) {
            await sql.query`
                UPDATE Users SET 
                    email = ${encrypt(user.email)},
                    is_encrypted = 1
                WHERE id = ${user.id}
            `;
        }
        
        // Migrar preguntas de seguridad
        const questions = await sql.query`SELECT * FROM SecurityQuestions`;
        for (const q of questions.recordset) {
            await sql.query`
                UPDATE SecurityQuestions SET
                    petName = ${encrypt(q.petName)},
                    favoriteColor = ${encrypt(q.favoriteColor)},
                    favoritePlace = ${encrypt(q.favoritePlace)}
                WHERE userId = ${q.userId}
            `;
        }
        
        // Migrar métodos de pago
        const payments = await sql.query`SELECT * FROM UserPaymentMethods WHERE is_encrypted = 0`;
        for (const p of payments.recordset) {
            await sql.query`
                UPDATE UserPaymentMethods SET
                    cardNumber = ${encrypt(p.cardNumber)},
                    cardHolder = ${encrypt(p.cardHolder)},
                    cvv = ${encrypt(p.cvv)},
                    is_encrypted = 1
                WHERE id = ${p.id}
            `;
        }
        
        res.json({ success: true, message: 'Migración completada' });
    } catch (err) {
        console.error('Error en migración:', err);
        res.status(500).json({ success: false, message: 'Error en migración' });
    }
});

//fin encroptaciones


//apointments:


// Modelo de datos para citas (simplificado)
const appointmentStatuses = ['scheduled', 'confirmed', 'completed', 'cancelled'];
const appointmentTypes = ['video', 'phone', 'in_person'];

// Ruta para obtener citas de un usuario
app.get('/api/appointments', authenticateJWT, async (req, res) => {
    const { userId } = req.query;
    const { status } = req.query;

    try {
        let query = `
            SELECT 
                c.id, c.patientId, c.psychologistId, 
                c.dateTime, c.duration, c.type, 
                c.status, c.notes, c.summary,
                c.rating, c.ratingComment, c.videoUrl,
                c.createdAt, c.updatedAt,
                up.firstName as patientFirstName, up.lastName as patientLastName,
                u.firstName as psychologistFirstName, u.lastName as psychologistLastName,
                pp.specialties, pp.hourlyRate
            FROM Citas c
            JOIN Users up ON c.patientId = up.id
            JOIN Users u ON c.psychologistId = u.id
            LEFT JOIN PsychologistProfiles pp ON c.psychologistId = pp.userId
            WHERE c.patientId = @userId OR c.psychologistId = @userId
        `;

        const params = [{ name: 'userId', value: userId }];

        if (status && status !== 'all') {
            query += ' AND c.status = @status';
            params.push({ name: 'status', value: status });
        }

        query += ' ORDER BY c.dateTime DESC';

        const result = await executeQuery(query, params);
        
        const appointments = result.recordset.map(appointment => {
            return {
                id: appointment.id,
                patientId: appointment.patientId,
                psychologistId: appointment.psychologistId,
                dateTime: appointment.dateTime,
                duration: appointment.duration,
                type: appointment.type,
                status: appointment.status,
                notes: appointment.notes,
                summary: appointment.summary,
                rating: appointment.rating,
                ratingComment: appointment.ratingComment,
                videoUrl: appointment.videoUrl,
                createdAt: appointment.createdAt,
                updatedAt: appointment.updatedAt,
                psychologist: {
                    firstName: appointment.psychologistFirstName,
                    lastName: appointment.psychologistLastName,
                    specialties: appointment.specialties ? JSON.parse(appointment.specialties) : [],
                    hourlyRate: appointment.hourlyRate
                },
                patient: {
                    firstName: appointment.patientFirstName,
                    lastName: appointment.patientLastName
                }
            };
        });

        res.json(appointments);
    } catch (err) {
        console.error('Error obteniendo citas:', err);
        res.status(500).json({ error: 'Error al obtener citas' });
    }
});

// Ruta para obtener detalles de una cita específica
app.get('/api/appointments/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await executeQuery(`
            SELECT 
                c.*,
                up.firstName as patientFirstName, up.lastName as patientLastName,
                u.firstName as psychologistFirstName, u.lastName as psychologistLastName,
                pp.specialties, pp.hourlyRate, pp.bio
            FROM Citas c
            JOIN Users up ON c.patientId = up.id
            JOIN Users u ON c.psychologistId = u.id
            LEFT JOIN PsychologistProfiles pp ON c.psychologistId = pp.userId
            WHERE c.id = @id
        `, [{ name: 'id', value: id }]);

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada' });
        }

        const appointment = result.recordset[0];
        
        const response = {
            id: appointment.id,
            patientId: appointment.patientId,
            psychologistId: appointment.psychologistId,
            dateTime: appointment.dateTime,
            duration: appointment.duration,
            type: appointment.type,
            status: appointment.status,
            notes: appointment.notes,
            summary: appointment.summary,
            rating: appointment.rating,
            ratingComment: appointment.ratingComment,
            videoUrl: appointment.videoUrl,
            price: appointment.price,
            createdAt: appointment.createdAt,
            updatedAt: appointment.updatedAt,
            psychologist: {
                firstName: appointment.psychologistFirstName,
                lastName: appointment.psychologistLastName,
                specialties: appointment.specialties ? JSON.parse(appointment.specialties) : [],
                bio: appointment.bio,
                hourlyRate: appointment.hourlyRate
            },
            patient: {
                firstName: appointment.patientFirstName,
                lastName: appointment.patientLastName
            }
        };

        res.json(response);
    } catch (err) {
        console.error('Error obteniendo detalles de cita:', err);
        res.status(500).json({ error: 'Error al obtener detalles de cita' });
    }
});

// Ruta para crear una nueva cita
app.post('/api/appointments', authenticateJWT, async (req, res) => {
    const { psychologistId, dateTime, type, notes, patientId } = req.body;

    try {
        // Validaciones básicas
        if (!psychologistId || !dateTime || !type || !patientId) {
            return res.status(400).json({ error: 'Datos incompletos' });
        }

        if (!['video', 'phone', 'in_person', 'chat', 'audio'].includes(type)) {
            return res.status(400).json({ error: 'Tipo de cita no válido' });
        }

        const appointmentDate = new Date(dateTime);
        if (isNaN(appointmentDate.getTime())) {
            return res.status(400).json({ error: 'Fecha no válida' });
        }

        // Verificar disponibilidad del psicólogo
        const availabilityCheck = await executeQuery(`
            SELECT id FROM Citas 
            WHERE psychologistId = @psychologistId 
            AND dateTime BETWEEN DATEADD(MINUTE, -59, @dateTime) AND DATEADD(MINUTE, 59, @dateTime)
            AND status NOT IN ('cancelled')
        `, [
            { name: 'psychologistId', value: psychologistId },
            { name: 'dateTime', value: dateTime }
        ]);

        if (availabilityCheck.recordset.length > 0) {
            return res.status(400).json({ error: 'El psicólogo no está disponible en ese horario' });
        }

        // Obtener tarifa del psicólogo
        const psychologistRate = await executeQuery(`
            SELECT hourlyRate FROM PsychologistProfiles WHERE userId = @psychologistId
        `, [{ name: 'psychologistId', value: psychologistId }]);

        const hourlyRate = psychologistRate.recordset[0]?.hourlyRate || 0;
        const price = (hourlyRate * 1).toFixed(2); // Duración predeterminada de 60 minutos

        // Crear la cita
        const result = await executeQuery(`
            INSERT INTO Citas (
                patientId, psychologistId, dateTime, duration, 
                type, status, notes, price, createdAt, updatedAt
            )
            OUTPUT INSERTED.id
            VALUES (
                @patientId, @psychologistId, @dateTime, 60, 
                @type, 'scheduled', @notes, @price, GETDATE(), GETDATE()
            )
        `, [
            { name: 'patientId', value: patientId },
            { name: 'psychologistId', value: psychologistId },
            { name: 'dateTime', value: dateTime },
            { name: 'type', value: type },
            { name: 'notes', value: notes || null },
            { name: 'price', value: price }
        ]);

        const newAppointmentId = result.recordset[0].id;

        // Generar URL de videollamada si es una cita por video
        let videoUrl = null;
        if (type === 'video') {
            videoUrl = `https://meet.lianze.com/${crypto.randomBytes(8).toString('hex')}`;
            await executeQuery(`
                UPDATE Citas SET videoUrl = @videoUrl WHERE id = @id
            `, [
                { name: 'videoUrl', value: videoUrl },
                { name: 'id', value: newAppointmentId }
            ]);
        }

        // Obtener información del psicólogo para la respuesta
        const psychologistResult = await executeQuery(`
            SELECT u.firstName, u.lastName, pp.specialties, pp.hourlyRate
            FROM Users u
            LEFT JOIN PsychologistProfiles pp ON u.id = pp.userId
            WHERE u.id = @psychologistId
        `, [{ name: 'psychologistId', value: psychologistId }]);

        const psychologist = psychologistResult.recordset[0];

        res.json({
            success: true,
            appointmentId: newAppointmentId,
            psychologist: {
                firstName: psychologist.firstName,
                lastName: psychologist.lastName,
                specialties: psychologist.specialties ? JSON.parse(psychologist.specialties) : [],
                hourlyRate: psychologist.hourlyRate
            },
            price: price,
            videoUrl: videoUrl
        });
    } catch (err) {
        console.error('Error creando cita:', err);
        res.status(500).json({ error: 'Error al crear cita' });
    }
});

// Ruta para cancelar una cita
app.post('/api/appointments/:id/cancel', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;

    try {
        // Verificar que la cita pertenece al usuario
        const appointmentCheck = await executeQuery(`
            SELECT id, status, dateTime, psychologistId
            FROM Citas 
            WHERE id = @id AND (patientId = @userId OR psychologistId = @userId)
        `, [
            { name: 'id', value: id },
            { name: 'userId', value: userId }
        ]);

        if (appointmentCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada o no autorizada' });
        }

        const appointment = appointmentCheck.recordset[0];

        // Verificar que la cita no esté ya cancelada o completada
        if (appointment.status === 'cancelled') {
            return res.status(400).json({ error: 'La cita ya está cancelada' });
        }

        if (appointment.status === 'completed') {
            return res.status(400).json({ error: 'No se puede cancelar una cita completada' });
        }

        // Verificar que no sea demasiado tarde para cancelar (más de 24 horas antes)
        const appointmentDate = new Date(appointment.dateTime);
        const now = new Date();
        const hoursUntilAppointment = (appointmentDate - now) / (1000 * 60 * 60);

        if (hoursUntilAppointment < 24) {
            return res.status(400).json({ error: 'Solo puedes cancelar citas con más de 24 horas de anticipación' });
        }

        // Actualizar estado de la cita
        await executeQuery(`
            UPDATE Citas 
            SET status = 'cancelled', updatedAt = GETDATE() 
            WHERE id = @id
        `, [{ name: 'id', value: id }]);

        res.json({ success: true });
    } catch (err) {
        console.error('Error cancelando cita:', err);
        res.status(500).json({ error: 'Error al cancelar cita' });
    }
});

// Ruta para reagendar una cita
app.put('/api/appointments/:id/reschedule', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { dateTime, type, notes, userId } = req.body;

    try {
        // Validaciones básicas
        if (!dateTime || !type) {
            return res.status(400).json({ error: 'Datos incompletos' });
        }

        if (!['video', 'phone', 'in_person', 'chat', 'audio'].includes(type)) {
            return res.status(400).json({ error: 'Tipo de cita no válido' });
        }

        const newAppointmentDate = new Date(dateTime);
        if (isNaN(newAppointmentDate.getTime())) {
            return res.status(400).json({ error: 'Fecha no válida' });
        }

        // Verificar que la cita exista y pertenezca al usuario
        const appointmentCheck = await executeQuery(`
            SELECT psychologistId, status, dateTime 
            FROM Citas 
            WHERE id = @id AND (patientId = @userId OR psychologistId = @userId)
        `, [
            { name: 'id', value: id },
            { name: 'userId', value: userId }
        ]);

        if (appointmentCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada o no autorizada' });
        }

        const appointment = appointmentCheck.recordset[0];

        // Verificar que la cita no esté cancelada o completada
        if (appointment.status === 'cancelled') {
            return res.status(400).json({ error: 'No se puede reagendar una cita cancelada' });
        }

        if (appointment.status === 'completed') {
            return res.status(400).json({ error: 'No se puede reagendar una cita completada' });
        }

        // Verificar disponibilidad del psicólogo en la nueva fecha
        const availabilityCheck = await executeQuery(`
            SELECT id FROM Citas 
            WHERE psychologistId = @psychologistId 
            AND id != @id
            AND dateTime BETWEEN DATEADD(MINUTE, -59, @dateTime) AND DATEADD(MINUTE, 59, @dateTime)
            AND status NOT IN ('cancelled')
        `, [
            { name: 'psychologistId', value: appointment.psychologistId },
            { name: 'id', value: id },
            { name: 'dateTime', value: dateTime }
        ]);

        if (availabilityCheck.recordset.length > 0) {
            return res.status(400).json({ error: 'El psicólogo no está disponible en ese horario' });
        }

        // Actualizar la cita
        await executeQuery(`
            UPDATE Citas 
            SET 
                dateTime = @dateTime,
                type = @type,
                notes = @notes,
                updatedAt = GETDATE()
            WHERE id = @id
        `, [
            { name: 'dateTime', value: dateTime },
            { name: 'type', value: type },
            { name: 'notes', value: notes || null },
            { name: 'id', value: id }
        ]);

        // Generar nueva URL de videollamada si es necesario
        let videoUrl = null;
        if (type === 'video') {
            videoUrl = `https://meet.lianze.com/${crypto.randomBytes(8).toString('hex')}`;
            await executeQuery(`
                UPDATE Citas SET videoUrl = @videoUrl WHERE id = @id
            `, [
                { name: 'videoUrl', value: videoUrl },
                { name: 'id', value: id }
            ]);
        }

        res.json({ success: true, videoUrl: videoUrl });
    } catch (err) {
        console.error('Error reagendando cita:', err);
        res.status(500).json({ error: 'Error al reagendar cita' });
    }
});

// Ruta para calificar una cita completada
app.post('/api/appointments/:id/rate', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { rating, comment, userId } = req.body;

    try {
        // Validaciones
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Calificación no válida' });
        }

        // Verificar que la cita exista, esté completada y pertenezca al usuario
        const appointmentCheck = await executeQuery(`
            SELECT status, psychologistId 
            FROM Citas 
            WHERE id = @id AND patientId = @userId
        `, [
            { name: 'id', value: id },
            { name: 'userId', value: userId }
        ]);

        if (appointmentCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada o no autorizada' });
        }

        const appointment = appointmentCheck.recordset[0];

        if (appointment.status !== 'completed') {
            return res.status(400).json({ error: 'Solo puedes calificar citas completadas' });
        }

        // Actualizar calificación
        await executeQuery(`
            UPDATE Citas 
            SET 
                rating = @rating,
                ratingComment = @comment,
                updatedAt = GETDATE()
            WHERE id = @id
        `, [
            { name: 'rating', value: rating },
            { name: 'comment', value: comment || null },
            { name: 'id', value: id }
        ]);

        // Actualizar calificación promedio del psicólogo
        await updatePsychologistRating(appointment.psychologistId);

        res.json({ success: true });
    } catch (err) {
        console.error('Error calificando cita:', err);
        res.status(500).json({ error: 'Error al calificar cita' });
    }
});

// Función auxiliar para actualizar calificación del psicólogo
async function updatePsychologistRating(psychologistId) {
    try {
        const ratingResult = await executeQuery(`
            SELECT AVG(CAST(rating AS DECIMAL(3,2))) as avgRating, COUNT(rating) as ratingCount
            FROM Citas
            WHERE psychologistId = @psychologistId AND rating IS NOT NULL
        `, [{ name: 'psychologistId', value: psychologistId }]);

        const avgRating = ratingResult.recordset[0].avgRating;
        const ratingCount = ratingResult.recordset[0].ratingCount;

        await executeQuery(`
            UPDATE PsychologistProfiles
            SET 
                rating = @avgRating,
                totalReviews = @ratingCount,
                updatedAt = GETDATE()
            WHERE userId = @psychologistId
        `, [
            { name: 'avgRating', value: avgRating || 0 },
            { name: 'ratingCount', value: ratingCount || 0 },
            { name: 'psychologistId', value: psychologistId }
        ]);
    } catch (err) {
        console.error('Error actualizando calificación del psicólogo:', err);
    }
}

//Ruta para confirmar asistencia
app.post('/api/appointments/:id/confirm', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { psychologistId, summary } = req.body;

    try {
        // Verificar que la cita pertenece al psicólogo
        const appointmentCheck = await executeQuery(`
            SELECT id, status, dateTime 
            FROM Citas 
            WHERE id = @id AND psychologistId = @psychologistId
        `, [
            { name: 'id', value: id },
            { name: 'psychologistId', value: psychologistId }
        ]);

        if (appointmentCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada o no autorizada' });
        }

        const appointment = appointmentCheck.recordset[0];

        // Verificar que la cita esté programada
        if (appointment.status !== 'scheduled') {
            return res.status(400).json({ error: 'Solo puedes confirmar citas programadas' });
        }

        // Verificar que la cita ya haya ocurrido
        const appointmentDate = new Date(appointment.dateTime);
        const now = new Date();
        if (appointmentDate > now) {
            return res.status(400).json({ error: 'No puedes confirmar una cita antes de su horario' });
        }

        // Actualizar estado de la cita
        await executeQuery(`
            UPDATE Citas 
            SET 
                status = 'completed',
                summary = @summary,
                updatedAt = GETDATE()
            WHERE id = @id
        `, [
            { name: 'summary', value: summary || null },
            { name: 'id', value: id }
        ]);

        res.json({ success: true });
    } catch (err) {
        console.error('Error confirmando cita:', err);
        res.status(500).json({ error: 'Error al confirmar cita' });
    }
});


//actulizar session
app.put('/api/appointments/:id/summary', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { psychologistId, summary } = req.body;

    try {
        // Verificar que la cita pertenece al psicólogo y está completada
        const appointmentCheck = await executeQuery(`
            SELECT id FROM Citas 
            WHERE id = @id AND psychologistId = @psychologistId AND status = 'completed'
        `, [
            { name: 'id', value: id },
            { name: 'psychologistId', value: psychologistId }
        ]);

        if (appointmentCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Cita no encontrada, no autorizada o no completada' });
        }

        // Actualizar resumen
        await executeQuery(`
            UPDATE Citas 
            SET 
                summary = @summary,
                updatedAt = GETDATE()
            WHERE id = @id
        `, [
            { name: 'summary', value: summary },
            { name: 'id', value: id }
        ]);

        res.json({ success: true });
    } catch (err) {
        console.error('Error actualizando resumen:', err);
        res.status(500).json({ error: 'Error al actualizar resumen' });
    }
});

//disponibilidad del psicologo
app.get('/api/psychologists/:id/availability', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { start, end } = req.query;

    try {
        // Validar fechas
        if (!start || !end) {
            return res.status(400).json({ error: 'Debes proporcionar fechas de inicio y fin' });
        }

        // Obtener disponibilidad del psicólogo
        const availabilityResult = await executeQuery(`
            SELECT availability FROM PsychologistProfiles WHERE userId = @id
        `, [{ name: 'id', value: id }]);

        if (availabilityResult.recordset.length === 0) {
            return res.status(404).json({ error: 'Psicólogo no encontrado' });
        }

        const availability = availabilityResult.recordset[0].availability 
            ? JSON.parse(availabilityResult.recordset[0].availability)
            : {};

        // Obtener citas existentes en el rango de fechas
        const appointmentsResult = await executeQuery(`
            SELECT dateTime, duration 
            FROM Citas 
            WHERE psychologistId = @id 
            AND status NOT IN ('cancelled')
            AND dateTime BETWEEN @start AND @end
            ORDER BY dateTime
        `, [
            { name: 'id', value: id },
            { name: 'start', value: start },
            { name: 'end', value: end }
        ]);

        const appointments = appointmentsResult.recordset.map(a => ({
            start: a.dateTime,
            end: new Date(new Date(a.dateTime).getTime() + (a.duration * 60000))
        }));

        res.json({
            psychologistId: id,
            availability,
            appointments,
            startDate: start,
            endDate: end
        });
    } catch (err) {
        console.error('Error verificando disponibilidad:', err);
        res.status(500).json({ error: 'Error al verificar disponibilidad' });
    }
});



//fin citas

//codigos


// generar codigosfunction generateBackupCodes(count = 10) {
function generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase().slice(0, 8);
        codes.push(code);
    }
    return codes;
}
// Verificar códigos de respaldo
async function verifyBackupCode(userId, code) {
    try {
        const result = await executeQuery(
            'SELECT id, code FROM MFABackupCodes WHERE userId = @userId AND isUsed = 0',
            [{ name: 'userId', type: sql.Int, value: userId }]
        );
        
        if (result.recordset.length === 0) {
            return false;
        }

        for (const row of result.recordset) {
            try {
                const decryptedCode = decrypt(row.code);
                if (decryptedCode === code) {
                    await executeQuery(
                        'UPDATE MFABackupCodes SET isUsed = 1 WHERE id = @id',
                        [{ name: 'id', type: sql.Int, value: row.id }]
                    );
                    return true;
                }
            } catch (error) {
                console.error('Error desencriptando código:', error);
                continue;
            }
        }
        return false;
    } catch (err) {
        console.error('Error verificando código de respaldo:', err);
        return false;
    }
}

function generateTempToken(userId) {
    const payload = {
        userId: userId,
        exp: Math.floor(Date.now() / 1000) + (10 * 60) // 10 minutos
    };
    const secret = process.env.TEMP_TOKEN_SECRET || 'tu_clave_secreta_temporal';
    return jwt.sign(payload, secret);
}

function verifyTempToken(token) {
    try {
        const secret = process.env.TEMP_TOKEN_SECRET || 'tu_clave_secreta_temporal';
        const decoded = jwt.verify(token, secret);
        return decoded.userId;
    } catch (err) {
        console.error('Error verificando token:', err);
        return null;
    }
}




// Obtener códigos de respaldo no usados
async function getUnusedBackupCodes(userId) {
    try {
        await sql.connect(dbConfig);
        const result = await sql.query`
            SELECT code FROM MFABackupCodes 
            WHERE userId = ${userId} AND isUsed = 0
            ORDER BY createdAt
        `;
        // Desencriptar cada código antes de devolverlo
        return result.recordset.map(row => decrypt(row.code));
    } finally {
        sql.close();
    }
}

app.post('/api/mfa/backup-codes', async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requieren ID de usuario y contraseña' 
        });
    }

    try {
        await sql.connect(dbConfig);
        
        // Verificar credenciales
        const user = await sql.query`
            SELECT id, password FROM Users WHERE id = ${userId} AND isActive = 1
        `;
        
        if (user.recordset.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.recordset[0].password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Contraseña incorrecta' 
            });
        }

        // Obtener códigos no usados (ya se desencriptan en getUnusedBackupCodes)
        const codes = await getUnusedBackupCodes(userId);
        
        res.json({
            success: true,
            codes: codes
        });
    } catch (err) {
        console.error('Error obteniendo códigos de respaldo:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener códigos de respaldo' 
        });
    } finally {
        sql.close();
    }
});

// Generar nuevos códigos de respaldo (invalida los anteriores)
app.post('/api/mfa/regenerate-codes', async (req, res) => {
    const { userId, password } = req.body;

    if (!userId || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Se requieren ID de usuario y contraseña' 
        });
    }

    try {
        await sql.connect(dbConfig);
        
        // Verificar credenciales
        const user = await sql.query`
            SELECT id, password FROM Users WHERE id = ${userId} AND isActive = 1
        `;
        
        if (user.recordset.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.recordset[0].password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Contraseña incorrecta' 
            });
        }

        // Eliminar códigos existentes
        await sql.query`
            DELETE FROM MFABackupCodes WHERE userId = ${userId}
        `;

        // Generar nuevos códigos y guardarlos encriptados
        const backupCodes = generateBackupCodes();
        for (const code of backupCodes) {
            await sql.query`
                INSERT INTO MFABackupCodes (userId, code, isUsed, is_encrypted)
                VALUES (${userId}, ${encrypt(code)}, 0, 1)
            `;
        }

        res.json({
            success: true,
            codes: backupCodes // Devuelve los códigos en claro al cliente
        });
    } catch (err) {
        console.error('Error regenerando códigos de respaldo:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al regenerar códigos de respaldo' 
        });
    } finally {
        sql.close();
    }
});



app.post('/api/forgot-password/init', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: 'El correo electrónico es requerido'
        });
    }

    console.log('Solicitud de recuperación para:', email);

    try {
        // Verificar conexión a la base de datos
        if (!poolConnect) {
            throw new Error('No hay conexión a la base de datos');
        }

        // Buscar usuario
        const usersResult = await poolConnect.request()
            .query('SELECT id, email, firstName, lastName, mfaEnabled FROM Users WHERE isActive = 1');
        
        console.log('Total usuarios activos:', usersResult.recordset.length);

        let userFound = null;
        for (const u of usersResult.recordset) {
            try {
                const decryptedEmail = decrypt(u.email);
                console.log(`Comparando: ${decryptedEmail} con ${email}`);
                
                if (decryptedEmail.toLowerCase() === email.toLowerCase()) {
                    userFound = u;
                    break;
                }
            } catch (err) {
                console.error('Error desencriptando email:', err.message);
            }
        }

        if (!userFound) {
            console.log('Usuario no encontrado');
            return res.status(404).json({ 
                success: false, 
                message: 'No se encontró una cuenta con ese correo electrónico' 
            });
        }

        console.log('Usuario encontrado:', userFound.id);

        // Obtener preguntas de seguridad
        const questionsResult = await poolConnect.request()
            .input('userId', sql.Int, userFound.id)
            .query('SELECT petName, favoriteColor, favoritePlace FROM SecurityQuestions WHERE userId = @userId');

        if (questionsResult.recordset.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No hay preguntas de seguridad configuradas' 
            });
        }

        const questions = questionsResult.recordset[0];
        
        // Verificar estructura de las preguntas
        const requiredFields = ['petName', 'favoriteColor', 'favoritePlace'];
        for (const field of requiredFields) {
            if (!questions[field]) {
                return res.status(500).json({
                    success: false,
                    message: `Falta el campo de pregunta: ${field}`
                });
            }
        }

        // Configurar CORS explícitamente para esta respuesta
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Headers', 'Content-Type');
        
        return res.json({
            success: true,
            email: email, // Usar el email original en lugar del encriptado
            mfaEnabled: userFound.mfaEnabled,
            questions: {
                petName: '¿Cuál es el nombre de tu primera mascota?',
                favoriteColor: '¿Cuál es tu color favorito?',
                favoritePlace: '¿Cuál es tu lugar favorito?'
            }
        });

    } catch (err) {
        console.error('Error en el servidor:', err);
        return res.status(500).json({ 
            success: false, 
            message: 'Error interno del servidor',
            error: err.message 
        });
    }
});




// Endpoint para verificar respuesta de seguridad
app.post('/api/forgot-password/verify-answer', async (req, res) => {
    const { email, question, answer } = req.body;

    try {
        const pool = req.db;
        
        // Buscar usuario por email
        const users = await pool.request().query('SELECT * FROM Users WHERE isActive = 1');
        const user = users.recordset.find(u => {
            try {
                return decrypt(u.email) === email;
            } catch (err) {
                console.error('Error desencriptando email:', err);
                return false;
            }
        });

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        // Obtener preguntas de seguridad
        const questionsResult = await pool.request()
            .input('userId', sql.Int, user.id)
            .query('SELECT * FROM SecurityQuestions WHERE userId = @userId');

        if (questionsResult.recordset.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No se encontraron preguntas de seguridad' 
            });
        }

        const securityQuestions = questionsResult.recordset[0];
        
        // Verificar respuesta
        let isAnswerValid = false;
        try {
            const decryptedAnswer = decrypt(securityQuestions[question]);
            isAnswerValid = decryptedAnswer === answer;
        } catch (err) {
            console.error('Error desencriptando respuesta:', err);
            isAnswerValid = false;
        }

        if (!isAnswerValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Respuesta incorrecta' 
            });
        }

        res.json({
            success: true,
            requiresMFA: user.mfaEnabled
        });
    } catch (err) {
        console.error('Error verificando respuesta:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor' 
        });
    }
});


// Endpoint para verificar código MFA
app.post('/api/forgot-password/verify-mfa', async (req, res) => {
    const { email, code } = req.body;

    try {
        const pool = req.db;
        
        // Buscar usuario por email
        const users = await pool.request().query('SELECT * FROM Users WHERE isActive = 1');
        const user = users.recordset.find(u => decrypt(u.email) === email);

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        // Verificar código MFA
        const codeValid = await verifyBackupCode(user.id, code);
        if (!codeValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Código MFA inválido' 
            });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Error verificando MFA:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor' 
        });
    }
});

// Endpoint para restablecer contraseña
app.post('/api/forgot-password/reset', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        // Verificar conexión a la base de datos
        if (!poolConnect) {
            throw new Error('No hay conexión a la base de datos');
        }

        // 1. Buscar usuario por email
        const usersResult = await poolConnect.request()
            .query('SELECT * FROM Users WHERE isActive = 1');
        
        const user = usersResult.recordset.find(u => {
            try {
                return decrypt(u.email) === email;
            } catch (err) {
                console.error('Error desencriptando email:', err);
                return false;
            }
        });

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        // 2. Validar nueva contraseña
        const passwordValidation = validatePassword(newPassword, user.firstName, user.lastName);
        if (!passwordValidation.valid) {
            return res.status(400).json({ 
                success: false, 
                message: passwordValidation.message 
            });
        }

        // 3. Hashear nueva contraseña
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // 4. Actualizar contraseña en la base de datos
        await poolConnect.request()
            .input('hashedPassword', sql.NVarChar, hashedPassword)
            .input('userId', sql.Int, user.id)
            .query('UPDATE Users SET password = @hashedPassword, updatedAt = GETDATE() WHERE id = @userId');

        res.json({ 
            success: true,
            message: 'Contraseña actualizada correctamente' 
        });

    } catch (err) {
        console.error('Error restableciendo contraseña:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor',
            error: err.message 
        });
    }
});




// Endpoint para soporte
app.post('/api/support', async (req, res) => {
    const { email, message } = req.body;

    try {
        await sqlConnect;
        
        await sql.query`
            INSERT INTO SupportTickets (email, message)
            VALUES (${email}, ${message})
        `;

        res.json({ success: true });
    } catch (err) {
        console.error('Error creando ticket de soporte:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al enviar reporte' 
        });
    }
});


async function auditMiddleware(req, res, next) {
    const originalSend = res.send;
    const startTime = new Date();
    
    res.send = function(body) {
        const duration = new Date() - startTime;
        const status = res.statusCode >= 400 ? 'error' : 'success';
        
        // Registrar la acción (no bloqueante)
        logAudit({
            userId: req.user?.id,
            actionType: req.method + ' ' + req.path,
            tableAffected: null,
            recordId: null,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            status: status,
            responseStatus: res.statusCode,
            duration: duration
        }).catch(err => console.error('Error en auditoría:', err));
        
        originalSend.call(this, body);
    };
    
    next();
}

// Función para registrar auditorías
async function logAudit(data) {
    try {
        const request = poolConnect.request();
        request.input('userId', sql.Int, data.userId || null);
        request.input('actionType', sql.NVarChar, data.actionType);
        request.input('tableAffected', sql.NVarChar, data.tableAffected || null);
        request.input('recordId', sql.Int, data.recordId || null);
        request.input('oldValues', sql.NVarChar, data.oldValues ? JSON.stringify(data.oldValues) : null);
        request.input('newValues', sql.NVarChar, data.newValues ? JSON.stringify(data.newValues) : null);
        request.input('ipAddress', sql.NVarChar, data.ipAddress || null);
        request.input('userAgent', sql.NVarChar, data.userAgent || null);
        request.input('status', sql.NVarChar, data.status || 'success');
        request.input('errorMessage', sql.NVarChar, data.errorMessage || null);
        
        await request.query(`
            INSERT INTO AuditLogs 
            (userId, actionType, tableAffected, recordId, oldValues, newValues, ipAddress, userAgent, status, errorMessage)
            VALUES 
            (@userId, @actionType, @tableAffected, @recordId, @oldValues, @newValues, @ipAddress, @userAgent, @status, @errorMessage)
        `);
    } catch (err) {
        console.error('Error registrando auditoría:', err);
    }
}

// Función para registrar intentos de login
async function logLoginAttempt(email, userId, ip, userAgent, status, mfaUsed = false) {
    try {
        const request = poolConnect.request();
        request.input('userId', sql.Int, userId || null);
        request.input('email', sql.NVarChar, email);
        request.input('ipAddress', sql.NVarChar, ip);
        request.input('userAgent', sql.NVarChar, userAgent || null);
        request.input('status', sql.NVarChar, status);
        request.input('mfaUsed', sql.Bit, mfaUsed);
        
        await request.query(`
            INSERT INTO LoginAudits 
            (userId, email, ipAddress, userAgent, status, mfaUsed)
            VALUES 
            (@userId, @email, @ipAddress, @userAgent, @status, @mfaUsed)
        `);
    } catch (err) {
        console.error('Error registrando intento de login:', err);
    }
}

// Endpoints de auditoría
app.get('/api/audit/logs', async (req, res) => {
    try {
        const { page = 1, limit = 50, actionType, userId, status } = req.query;
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                a.id, a.userId, u.email, a.actionType, a.tableAffected, 
                a.recordId, a.status, a.ipAddress, a.createdAt
            FROM AuditLogs a
            LEFT JOIN Users u ON a.userId = u.id
            WHERE 1=1
        `;
        
        const params = [];
        
        if (actionType) {
            query += ` AND a.actionType LIKE '%' + @actionType + '%'`;
            params.push({ name: 'actionType', value: actionType });
        }
        
        if (userId) {
            query += ` AND a.userId = @userId`;
            params.push({ name: 'userId', value: parseInt(userId) });
        }
        
        if (status) {
            query += ` AND a.status = @status`;
            params.push({ name: 'status', value: status });
        }
        
        query += ` ORDER BY a.createdAt DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY`;
        params.push({ name: 'offset', value: offset });
        params.push({ name: 'limit', value: parseInt(limit) });
        
        const request = poolConnect.request();
        params.forEach(param => {
            request.input(param.name, param.value);
        });
        
        const result = await request.query(query);
        
        // Desencriptar emails
        const logs = result.recordset.map(log => {
            try {
                return {
                    ...log,
                    email: log.email ? decrypt(log.email) : null
                };
            } catch {
                return log;
            }
        });
        
        res.json({ success: true, logs });
    } catch (err) {
        console.error('Error obteniendo logs de auditoría:', err);
        res.status(500).json({ success: false, message: 'Error obteniendo logs' });
    }
});

app.get('/api/audit/logins', async (req, res) => {
    try {
        const { page = 1, limit = 50, email, userId, status } = req.query;
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                id, userId, email, ipAddress, status, 
                mfaUsed, createdAt
            FROM LoginAudits
            WHERE 1=1
        `;
        
        const params = [];
        
        if (email) {
            query += ` AND email = @email`;
            params.push({ name: 'email', value: encrypt(email) });
        }
        
        if (userId) {
            query += ` AND userId = @userId`;
            params.push({ name: 'userId', value: parseInt(userId) });
        }
        
        if (status) {
            query += ` AND status = @status`;
            params.push({ name: 'status', value: status });
        }
        
        query += ` ORDER BY createdAt DESC OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY`;
        params.push({ name: 'offset', value: offset });
        params.push({ name: 'limit', value: parseInt(limit) });
        
        const request = poolConnect.request();
        params.forEach(param => {
            request.input(param.name, param.value);
        });
        
        const result = await request.query(query);
        
        // Desencriptar emails
        const logins = result.recordset.map(login => {
            try {
                return {
                    ...login,
                    email: decrypt(login.email)
                };
            } catch {
                return login;
            }
        });
        
        res.json({ success: true, logins });
    } catch (err) {
        console.error('Error obteniendo logs de login:', err);
        res.status(500).json({ success: false, message: 'Error obteniendo logs de login' });
    }
});

app.get('/api/audit/stats', async (req, res) => {
    try {
        // Obtener estadísticas generales
        const statsQuery = `
            SELECT 
                (SELECT COUNT(*) FROM Users WHERE isActive = 1) as totalUsers,
                (SELECT COUNT(*) FROM LoginAudits WHERE status = 'success') as successfulLogins,
                (SELECT COUNT(*) FROM LoginAudits WHERE status = 'failed') as failedLogins,
                (SELECT COUNT(*) FROM AuditLogs WHERE status = 'error') as errors,
                (SELECT COUNT(*) FROM Appointments) as totalAppointments
        `;
        
        const statsResult = await poolConnect.request().query(statsQuery);
        
        // Obtener actividad reciente
        const activityQuery = `
            SELECT TOP 10 
                a.actionType, a.createdAt, u.email, a.status
            FROM AuditLogs a
            LEFT JOIN Users u ON a.userId = u.id
            ORDER BY a.createdAt DESC
        `;
        
        const activityResult = await poolConnect.request().query(activityQuery);
        
        // Desencriptar emails
        const recentActivity = activityResult.recordset.map(activity => {
            try {
                return {
                    ...activity,
                    email: activity.email ? decrypt(activity.email) : null
                };
            } catch {
                return activity;
            }
        });
        
        res.json({
            success: true,
            stats: statsResult.recordset[0],
            recentActivity
        });
    } catch (err) {
        console.error('Error obteniendo estadísticas:', err);
        res.status(500).json({ success: false, message: 'Error obteniendo estadísticas' });
    }
});






//Encriptaciones:
const encryptionAlgorithm = 'aes-256-cbc';
const ENCRYPTION_KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'tu_clave_secreta_super_segura_32bytes', 'salt', 32);
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(encryptionAlgorithm, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return text;
    
    if (!text.includes(':') || text.split(':').length !== 2) {
        return text;
    }
    try {
        const textParts = text.split(':');
        if (textParts.length !== 2) {
            console.error('Texto encriptado no tiene el formato correcto:', text);
            return text; // O podrías lanzar un error aquí
        }
        
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedText = Buffer.from(textParts[1], 'hex');
        
        if (iv.length !== IV_LENGTH) {
            throw new Error('Tamaño de IV incorrecto');
            return text;
        }
        
        const decipher = crypto.createDecipheriv(encryptionAlgorithm, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (err) {
        console.error('Error al desencriptar:', err);
        return text; // O manejar el error de otra manera
    }
}

// Prueba rápida de desencriptación
const testEmail = 'test@example.com';
const encrypted = encrypt(testEmail);
const decrypted = decrypt(encrypted);
console.log('Prueba de encriptación:', { original: testEmail, encrypted, decrypted });

function isValidEncrypted(text) {
    if (!text) return false;
    try {
        const textParts = text.split(':');
        if (textParts.length !== 2) return false;
        
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedText = Buffer.from(textParts[1], 'hex');
        
        return iv.length === IV_LENGTH && encryptedText.length > 0;
    } catch (err) {
        return false;
    }
}



//TSE

const tseDbConfig = {
  user: 'josehart',
  password: 'porras0111',
  server: 'JOSE',
  database: 'TSE_DB',
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

const tseSqlPool = new sql.ConnectionPool(tseDbConfig);
let tsePoolConnect;

tseSqlPool.connect()
  .then(pool => {
    tsePoolConnect = pool;
    console.log('Conectado a la base de datos TSE');
  })
  .catch(err => {
    console.error('Error al conectar a la base de datos TSE:', err);
  });





app.get('/api/tse/ciudadano/:dni', async (req, res) => {
    const dni = req.params.dni;
    
    if (!dni) {
        return res.status(400).json({ 
            success: false, 
            message: 'El DNI es requerido' 
        });
    }

    try {
        const request = tsePoolConnect.request();
        request.input('dni', sql.VarChar, dni);
        
        const result = await request.query(`
            SELECT 
                DNI, Nombre, PrimerApellido, SegundoApellido, 
                FechaNacimiento, Email
            FROM Ciudadanos 
            WHERE DNI = @dni
        `);
        
        if (result.recordset.length > 0) {
            const ciudadano = result.recordset[0];
            res.json({
                success: true,
                data: {
                    dni: ciudadano.DNI,
                    firstName: ciudadano.Nombre,
                    lastName: `${ciudadano.PrimerApellido} ${ciudadano.SegundoApellido || ''}`.trim(),
                    email: ciudadano.Email,
                    dateOfBirth: ciudadano.FechaNacimiento
                }
            });
        } else {
            res.status(404).json({ 
                success: false, 
                message: 'No se encontró el ciudadano con ese DNI' 
            });
        }
    } catch (err) {
        console.error('Error consultando TSE:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al consultar la base de datos del TSE' 
        });
    }
});







//Fin TSE






//apis Publicas  

// API para verificar psicologo por licencia
app.get('/api/psychologists/verify/:licenseNumber', async (req, res) => {
    try {
        const { licenseNumber } = req.params;
        
        const result = await poolConnect.request()
            .input('licenseNumber', sql.NVarChar, licenseNumber)
            .query(`
                SELECT u.id, u.firstName, u.lastName, u.email, 
                       p.specialties, p.experience, p.isVerified,
                       p.rating, p.totalReviews
                FROM PsychologistProfiles p
                JOIN Users u ON p.userId = u.id
                WHERE p.licenseNumber = @licenseNumber
            `);

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Psicólogo no encontrado' });
        }

        const psychologist = result.recordset[0];
        res.json({
            isValid: psychologist.isVerified,
            profile: {
                id: psychologist.id,
                name: `${psychologist.firstName} ${psychologist.lastName}`,
                email: psychologist.email,
                specialties: psychologist.specialties ? JSON.parse(psychologist.specialties) : [],
                experience: psychologist.experience,
                rating: psychologist.rating,
                reviews: psychologist.totalReviews
            }
        });
    } catch (err) {
        console.error('Error en verificación de psicólogo:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// API para obtener disponibilidad de psicólogos
app.get('/api/psychologists/disponibilidad', async (req, res) => {
    try {
        const result = await poolConnect.request()
            .query('SELECT id, specialties FROM PsychologistProfiles');
        
        const psychologists = result.recordset.map(psych => ({
            id: parseInt(psych.id), // Conversión explícita a número
            specialties: psych.specialties || ''
        }));
        
        res.json({
            success: true,
            data: psychologists
        });
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({ 
            success: false,
            error: 'Error en la consulta',
            details: err.message 
        });
    }
});


app.get('/api/psychologists', async (req, res) => {
  try {
    const result = await poolConnect.request()
      .query(`
        SELECT 
          p.id, p.userId, u.firstName, u.lastName, p.licenseNumber,
          p.specialties, p.experience, p.education, p.languages,
          p.hourlyRate, p.bio, p.availability, p.rating, 
          p.totalReviews, p.isVerified
        FROM PsychologistProfiles p
        JOIN Users u ON p.userId = u.id
        WHERE u.isActive = 1
      `);
    
    // Función de normalización mejorada
    const normalizeArrayData = (data) => {
      if (!data) return [];
      if (Array.isArray(data)) return data;
      if (typeof data === 'string' && (data.includes('[') || data.includes('"'))) {
        try {
          const parsed = JSON.parse(data);
          if (Array.isArray(parsed)) return parsed;
          if (typeof parsed === 'string') return parsed.split(',').map(item => item.trim());
          return [String(parsed)];
        } catch {
          return data.split(',').map(item => item.trim());
        }
      }
      if (typeof data === 'string') {
        return data.split(',')
          .map(item => item.trim())
          .filter(item => item.length > 0)
          .map(item => item.replace(/[\[\]"]+/g, '').trim());
      }
      return [String(data)];
    };
    
    const psychologists = result.recordset.map(p => ({
      ...p,
      specialties: normalizeArrayData(p.specialties),
      languages: normalizeArrayData(p.languages),
      education: normalizeArrayData(p.education),
      hourlyRate: parseFloat(p.hourlyRate) || 0
    }));
    
    res.json(psychologists);
  } catch (err) {
    console.error('Error fetching psychologists:', err);
    res.status(500).json({ error: 'Error al obtener psicólogos' });
  }
});





// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
