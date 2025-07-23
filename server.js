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
  user: 'josehart',
  password: 'porras0111',
  server: 'JOSE', 
  database: 'LIANZE_DB',
  options: {
    encrypt: true, 
    trustServerCertificate: true 
  }
};

const sqlPool = new sql.ConnectionPool(dbConfig);
let poolConnect;


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
        const emailCheck = await request.query(`
            SELECT id FROM Users WHERE email = @email AND id != @userId
        `, [
            { name: 'email', value: email },
            { name: 'userId', value: userId }
        ]);
        
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
        request.input('email', sql.NVarChar, email);
        request.input('phone', sql.NVarChar, phone);
        request.input('dateOfBirth', sql.Date, dateOfBirth);
        request.input('gender', sql.NVarChar, gender);
        request.input('bio', sql.NVarChar, bio);
        request.input('countryId', sql.NVarChar, countryId || null);
        request.input('provinceId', sql.NVarChar, provinceId || null);
        request.input('cantonId', sql.NVarChar, cantonId || null);
        request.input('districtId', sql.NVarChar, districtId || null);
        request.input('userId', sql.Int, userId);
        
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

        // Registrar login exitoso
        await logLoginAttempt(email, user.id, ip, userAgent, 'success');
        
        // Si no requiere MFA
        res.json({ 
            success: true, 
            user: decryptedUser,
            requiresMFA: false
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
        await sql.connect(dbConfig);
        
        const result = await sql.query`
            SELECT id, cardNumber, cardHolder, expirationMonth, expirationYear, cvv, balance, isDefault
            FROM UserPaymentMethods 
            WHERE userId = ${req.params.userId}
        `;
        
        // Desencriptar datos sensibles
        const sanitizedCards = result.recordset.map(card => {
            const decryptedCard = {
                id: card.id,
                cardNumber: decrypt(card.cardNumber),
                cardHolder: decrypt(card.cardHolder),
                expirationMonth: card.expirationMonth,
                expirationYear: card.expirationYear,
                balance: card.balance,
                isDefault: card.isDefault
            };
            
            return {
                ...decryptedCard,
                // Mostrar solo los últimos 4 dígitos
                cardNumber: `**** **** **** ${decryptedCard.cardNumber.slice(-4)}`,
                // No mostrar el CVV real
                cvv: '***'
            };
        });
        
        res.json(sanitizedCards);
    } catch (err) {
        console.error('Error obteniendo métodos de pago:', err);
        res.status(500).json({ error: 'Error al obtener métodos de pago' });
    } finally {
        sql.close();
    }
});

app.post('/api/payment-methods', async (req, res) => {
    const { userId, cardNumber, cardHolder, expirationMonth, expirationYear, cvv, balance } = req.body;

    try {
        await sql.connect(dbConfig);
        
        // Encriptar datos sensibles de la tarjeta
        const encryptedCard = {
            number: encrypt(cardNumber.replace(/\s+/g, '')),
            holder: encrypt(cardHolder),
            cvv: encrypt(cvv)
        };
        
        const result = await sql.query`
            INSERT INTO UserPaymentMethods 
                (userId, cardNumber, cardHolder, expirationMonth, expirationYear, cvv, balance, is_encrypted)
            VALUES 
                (${userId}, ${encryptedCard.number}, ${encryptedCard.holder}, 
                ${expirationMonth}, ${expirationYear}, ${encryptedCard.cvv}, 
                ${balance || 0}, 1)
            
            SELECT SCOPE_IDENTITY() AS newId;
        `;
        
        res.json({ success: true, message: 'Método de pago agregado', cardId: result.recordset[0].newId });
    } catch (err) {
        console.error('Error agregando método de pago:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al agregar método de pago' 
        });
    } finally {
        sql.close();
    }
});

app.put('/api/payment-methods/:id', async (req, res) => {
    const cardId = parseInt(req.params.id);
    const { cardHolder, expirationMonth, expirationYear, isDefault } = req.body;

    if (isNaN(cardId)) {
        return res.status(400).json({ error: 'ID de tarjeta no válido' });
    }

    try {
        await sql.connect(dbConfig);
        
        // Actualizar tarjeta
        await sql.query`
            UPDATE UserPaymentMethods 
            SET 
                cardHolder = ${cardHolder},
                expirationMonth = ${expirationMonth},
                expirationYear = ${expirationYear},
                updatedAt = GETDATE()
            WHERE id = ${cardId}
        `;
        
        // Si se marca como predeterminada, actualizar las demás
        if (isDefault) {
            await sql.query`
                UPDATE UserPaymentMethods 
                SET isDefault = 0 
                WHERE userId = (SELECT userId FROM UserPaymentMethods WHERE id = ${cardId})
            `;
            
            await sql.query`
                UPDATE UserPaymentMethods 
                SET isDefault = 1 
                WHERE id = ${cardId}
            `;
        }
        
        res.json({
            success: true,
            message: 'Método de pago actualizado correctamente'
        });
    } catch (err) {
        console.error('Error actualizando método de pago:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al actualizar método de pago' 
        });
    } finally {
        sql.close();
    }
});

app.delete('/api/payment-methods/:id', async (req, res) => {
    const cardId = parseInt(req.params.id);

    if (isNaN(cardId)) {
        return res.status(400).json({ error: 'ID de tarjeta no válido' });
    }

    try {
        await sql.connect(dbConfig);
        
        // Verificar si es la tarjeta predeterminada
        const cardCheck = await sql.query`
            SELECT isDefault FROM UserPaymentMethods WHERE id = ${cardId}
        `;
        
        if (cardCheck.recordset.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Método de pago no encontrado' 
            });
        }
        
        const isDefault = cardCheck.recordset[0].isDefault;
        const userId = (await sql.query`SELECT userId FROM UserPaymentMethods WHERE id = ${cardId}`).recordset[0].userId;
        
        // Eliminar la tarjeta
        await sql.query`
            DELETE FROM UserPaymentMethods 
            WHERE id = ${cardId}
        `;
        
        // Si era la predeterminada, asignar una nueva predeterminada
        if (isDefault) {
            const otherCards = await sql.query`
                SELECT TOP 1 id FROM UserPaymentMethods 
                WHERE userId = ${userId} 
                ORDER BY createdAt DESC
            `;
            
            if (otherCards.recordset.length > 0) {
                await sql.query`
                    UPDATE UserPaymentMethods 
                    SET isDefault = 1 
                    WHERE id = ${otherCards.recordset[0].id}
                `;
            }
        }
        
        res.json({
            success: true,
            message: 'Método de pago eliminado correctamente'
        });
    } catch (err) {
        console.error('Error eliminando método de pago:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Error al eliminar método de pago' 
        });
    } finally {
        sql.close();
    }
});









app.get('/api/psychologists', async (req, res) => {
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
      WHERE u.isActive = 1
    `;
    
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching psychologists:', err);
    res.status(500).json({ error: 'Error fetching psychologists' });
  } finally {
    sql.close();
  }
});

// Filter psychologists
app.get('/api/psychologists/filter', async (req, res) => {
  const { specialty, language, maxPrice } = req.query;
  
  try {
    await sql.connect(dbConfig);
    
    let query = `
      SELECT 
        p.id, 
        p.userId,
        u.firstName,
        u.lastName,
        p.specialties,
        p.languages,
        p.hourlyRate,
        p.rating,
        p.totalReviews
      FROM PsychologistProfiles p
      JOIN Users u ON p.userId = u.id
      WHERE u.isActive = 1
    `;
    
    const params = [];
    
    if (specialty) {
      query += ` AND p.specialties LIKE '%' + @specialty + '%'`;
      params.push({ name: 'specialty', value: specialty });
    }
    
    if (language) {
      query += ` AND p.languages LIKE '%' + @language + '%'`;
      params.push({ name: 'language', value: language });
    }
    
    if (maxPrice) {
      query += ` AND p.hourlyRate <= @maxPrice`;
      params.push({ name: 'maxPrice', value: parseFloat(maxPrice) });
    }
    
    const request = new sql.Request();
    params.forEach(param => {
      request.input(param.name, param.value);
    });
    
    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error('Error filtering psychologists:', err);
    res.status(500).json({ error: 'Error filtering psychologists' });
  } finally {
    sql.close();
  }
});

// Get psychologist by ID
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
    const nameRegex = /^[a-zA-Z0-9_.]{5,}$/;
    if (!nameRegex.test(firstName) || !nameRegex.test(lastName)) {
        return res.status(400).json({ 
            success: false, 
            message: 'El nombre y apellido deben tener al menos 5 caracteres y solo pueden contener letras, números, _ y .' 
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









// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});