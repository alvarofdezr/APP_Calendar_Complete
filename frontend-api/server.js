/**
 * @file server.js
 * @description Servidor HTTPS y API RESTful para el sistema bancario seguro
 * 
 * Este módulo implementa un servidor Express que proporciona:
 * - API REST segura con autenticación JWT
 * - Comunicación TLS 1.3 con el servidor de transacciones
 * - Validación y sanitización de entradas
 * - Rate limiting y protección contra ataques
 * - Logging detallado de operaciones
 * 
 * Características de Seguridad:
 * - TLS 1.3 forzado para todas las conexiones
 * - HMAC-SHA256 para firmar mensajes
 * - Sistema de nonces para prevenir replay attacks
 * - Sanitización de entradas y validación estricta
 * - Headers de seguridad via Helmet
 * 
 * @author Álvaro Fernandez Ramos
 * @version 2.0.0
 * @license MIT
 */

require('dotenv').config({ path: "../.env" });
require('global-agent/bootstrap');

const express = require('express');
const fs = require('fs');
const https = require('https');
const path = require('path');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit'); 
const helmet = require('helmet'); 
const tls = require('tls'); 
const jwt = require('jsonwebtoken');
const compression = require('compression');

const app = express();

// ==============================
// Configuración del servidor HTTPS
// ==============================
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'server.key')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'server.cert')),
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3'
};

const PORT = process.env.PORT || 5031;
const PYTHON_SERVER_HOST = process.env.PYTHON_SERVER_HOST || '127.0.0.1';
const PYTHON_SERVER_PORT = process.env.PYTHON_SERVER_PORT || 5030;

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`\n=== Servidor Node.js (HTTPS) ===`);
  console.log(`Escuchando en: https://localhost:${PORT}`);
  console.log(`Protocolo TLS: 1.3`);
  console.log(`Conectará a Python: ${PYTHON_SERVER_HOST}:${PYTHON_SERVER_PORT}`);
  console.log(`================================\n`);
});

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS) || 12;
const MAX_PASSWORD_LENGTH = parseInt(process.env.MAX_PASSWORD_LENGTH) || 128;
const MIN_PASSWORD_LENGTH = parseInt(process.env.MIN_PASSWORD_LENGTH) || 6;

// ==============================
// Middleware de Seguridad
// ==============================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
      imgSrc: ["'self'", 'https://www.us.es', 'data:'],
      fontSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      connectSrc: ["'self'"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(compression());
app.use(express.json({ limit: '10kb' })); 

if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });
}

// ==============================
// Configuración de la Base de Datos (PostgreSQL)
// ==============================

// --- CAMBIO: Usar 'new Pool()' de 'pg' ---
const dbPool = new Pool({
  max: parseInt(process.env.DB_POOL_SIZE) || 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT || 5432), // <-- Puerto PG
  connectionTimeoutMillis: 10000
});

// --- CAMBIO: Ping de conexión a PG ---
dbPool.query('SELECT NOW()')
  .then(res => {
    console.log(`✓ Conexión a base de datos PostgreSQL establecida (hora: ${res.rows[0].now})`);
  })
  .catch(err => {
    console.error('✗ Error conectando a la base de datos PostgreSQL:', err.message);
    process.exit(1);
  });

// ==============================
// Funciones Criptográficas de Apoyo
// ==============================
function generateNonceHex(lenBytes = 16) { 
  return crypto.randomBytes(lenBytes).toString('hex'); 
}

function hmacSha256Hex(key, data) { 
  return crypto.createHmac('sha256', key).update(data).digest('hex'); 
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.trim().replace(/[<>'"]/g, '');
}

// ==============================
// Endpoint de Registro de Usuario
// ==============================
app.post('/api/register', async (req, res, next) => {
  try {
    let { usuario, clave } = req.body;
    usuario = sanitizeInput(usuario);

    // ... (Validaciones sin cambios) ...
    if (!usuario || !clave) 
      return res.status(400).json({ error: 'usuario y clave requeridos' });
    if (usuario.length < 3 || usuario.length > 32) 
      return res.status(400).json({ error: 'usuario inválido (3-32 caracteres)' });
    if (clave.length < MIN_PASSWORD_LENGTH) 
      return res.status(400).json({ error: `clave muy corta (mínimo ${MIN_PASSWORD_LENGTH} caracteres)` });
    if (clave.length > MAX_PASSWORD_LENGTH)
      return res.status(400).json({ error: `clave muy larga (máximo ${MAX_PASSWORD_LENGTH} caracteres)` });
    if (!/^[a-zA-Z0-9_-]+$/.test(usuario)) {
      return res.status(400).json({ error: 'usuario solo puede contener letras, números, guiones y guiones bajos' });
    }
    // ... (Fin Validaciones) ...

    const hashed = await bcrypt.hash(clave, SALT_ROUNDS);

    // --- CAMBIO: 'query' con '$1' y recepción de 'rows' ---
    const { rows: existingUser } = await dbPool.query(
      'SELECT id FROM usuarios WHERE usuario = $1', 
      [usuario]
    );
    
    if (existingUser.length > 0) {
      console.warn(`[REGISTRO] Intento de registro duplicado: ${usuario}`);
      return res.json({ exito: false, mensaje: 'Usuario ya registrado.' });
    }

    // --- CAMBIO: 'query' con '$1, $2' ---
    await dbPool.query(
      'INSERT INTO usuarios (usuario, clave) VALUES ($1, $2)', 
      [usuario, hashed]
    );
    
    console.log(`[REGISTRO] Usuario registrado exitosamente: ${usuario}`);
    return res.json({ exito: true, mensaje: 'Usuario registrado exitosamente.' });

  } catch (err) {
    // --- CAMBIO: Manejo de error de 'pg' (código 23505 = unique_violation) ---
    if (err.code === '23505') {
      console.warn(`[REGISTRO] Intento de registro duplicado (race condition): ${req.body.usuario}`);
      return res.json({ exito: false, mensaje: 'Usuario ya registrado.' });
    }
    next(err);
  }
});

// ==============================
// Endpoint de Login de Usuario
// ==============================
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 10 * 60 * 1000, 
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 5,
  message: { error: "Demasiados intentos de login. Intenta de nuevo más tarde." },
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/login', loginLimiter, async (req, res, next) => {
  try {
    let { usuario, clave } = req.body;
    usuario = sanitizeInput(usuario);

    if (!usuario || !clave) 
      return res.status(400).json({ error: 'usuario y clave requeridos' });

    // --- CAMBIO: 'query' con '$1' y recepción de 'rows' ---
    const { rows: results } = await dbPool.query(
      'SELECT clave FROM usuarios WHERE usuario = $1', 
      [usuario]
    );
    
    if (!results.length) {
      console.warn(`[LOGIN] Intento fallido - usuario no existe: ${usuario} desde IP: ${req.ip}`);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const hash = results[0].clave;
    const isMatch = await bcrypt.compare(clave, hash);
    
    if (!isMatch) {
      console.warn(`[LOGIN] Intento fallido - contraseña incorrecta: ${usuario} desde IP: ${req.ip}`);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    
    // ... (Generación de JWT sin cambios) ...
    const payload = { usuario: usuario };
    const secret = process.env.JWT_SECRET;
    const options = { 
      expiresIn: process.env.JWT_EXPIRATION || '1h',
      issuer: 'PAI2-ST32'
    };
    const token = jwt.sign(payload, secret, options);
    console.log(`[LOGIN] Login exitoso: ${usuario} desde IP: ${req.ip}`);
    res.json({ 
      exito: true, 
      mensaje: 'Login correcto', 
      token: token 
    });

  } catch (err) {
    next(err);
  }
});

// ==============================
// Middleware de Verificación de Token
// ==============================
function verificarToken(req, res, next) {
  // ... (Sin cambios aquí) ...
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    console.warn(`[AUTH] Acceso denegado sin token desde IP: ${req.ip}`);
    return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.warn(`[AUTH] Token inválido/expirado desde IP: ${req.ip}`);
      return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
    req.usuario = user; 
    next();
  });
}

// ==============================
// Endpoint de Envío de Movimiento
// ==============================
app.post('/api/send', verificarToken, async (req, res, next) => {
  // --- ¡ESTE ENDPOINT NO TOCA LA BASE DE DATOS! ---
  // --- Habla con el servidor Python, así que NO HAY CAMBIOS ---
  try { 
    const { mensaje } = req.body;
    const usuariodelToken = req.usuario.usuario;
    if (!mensaje) {
      return res.status(400).json({ error: 'Falta el campo mensaje' });
    }
    if (typeof mensaje !== 'string' || mensaje.length > 250) { 
      return res.status(400).json({ error: 'mensaje inválido o excede los 250 caracteres' });
    }
    const sanitizedMensaje = sanitizeInput(mensaje);
    const partes = sanitizedMensaje.split(',');
    if (partes.length !== 4) { 
      return res.status(400).json({ error: 'Formato de mensaje inválido. Esperado: tipo,cantidad,categoria,descripcion' });
    }
    const tipo = partes[0];
    if (tipo !== 'ingreso' && tipo !== 'gasto') {
        return res.status(400).json({ error: 'El tipo debe ser "ingreso" o "gasto"' });
    }
    const cantidad = parseFloat(partes[1]);
    if (isNaN(cantidad) || cantidad <= 0) {
      return res.status(400).json({ error: 'La cantidad debe ser un número positivo' });
    }
    console.log(`[MOVIMIENTO] Usuario ${usuariodelToken} inicia movimiento: ${sanitizedMensaje}`);
    const respuestaServidor = await enviarTransaccionTCP(usuariodelToken, sanitizedMensaje);
    console.log(`[MOVIMIENTO] Respuesta del servidor Python: ${respuestaServidor}`);
    res.json({ respuesta: respuestaServidor });
  } catch (err) {
    if (err.code && err.code.startsWith('ERR_TLS_')) {
      return res.status(500).json({ error: 'Error de comunicación segura con el servidor de transacciones.' });
    }
    if (err.code === 'ECONNREFUSED') {
      return res.status(503).json({ error: 'Servidor de transacciones no disponible. Intente más tarde.' });
    }
    next(err);
  }
});

// ==============================
// Función de Envío de Transacción Vía TLS
// ==============================
function enviarTransaccionTCP(usuario, mensaje) {
  // --- ¡ESTA FUNCIÓN NO TOCA LA BASE DE DATOS! ---
  // --- Habla con el servidor Python, así que NO HAY CAMBIOS ---
  return new Promise((resolve, reject) => {
    const HMAC_KEY = process.env.HMAC_KEY;
    if (!HMAC_KEY) 
      return reject(new Error('HMAC_KEY no configurada'));
    const nonce = generateNonceHex(16);
    const timestamp = Math.floor(Date.now() / 1000);
    const dataToSign = `${nonce}|${timestamp}|${usuario}|${mensaje}`;
    const mac = hmacSha256Hex(HMAC_KEY, dataToSign);
    const payload = JSON.stringify({ 
      tipo: 'MSG', 
      usuario, 
      mensaje, 
      nonce, 
      timestamp, 
      mac 
    });
    const tlsOptions = {
      host: PYTHON_SERVER_HOST,
      port: PYTHON_SERVER_PORT,
      ca: [fs.readFileSync(path.join(__dirname, 'certs', 'rootCA.pem'))], 
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
      timeout: parseInt(process.env.TLS_TIMEOUT_MS) || 5000
    };
    const socket = tls.connect(tlsOptions, () => {
      const cipher = socket.getCipher();
      console.log(`[TLS] Conectado al servidor Python - Protocolo: ${socket.getProtocol()}, Cipher: ${cipher.name}`);
      socket.write(payload + '\n'); 
    });
    socket.setEncoding('utf8');
    socket.setTimeout(parseInt(process.env.TLS_TIMEOUT_MS) || 5000);
    socket.on('data', (data) => {
        socket.end();
        resolve(data.toString().trim()); 
    });
    socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Timeout de conexión con servidor de transacciones'));
    });
    socket.on('error', (err) => {
        socket.end();
        reject(err); 
    });
  });
}

// ==============================
// Endpoint de Health Check
// ==============================
app.get('/api/health', (req, res) => {
  // ... (Sin cambios aquí) ...
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0.0'
  });
});

// ==============================
// Endpoint para OBTENER Movimientos
// ==============================
app.get('/api/movimientos', verificarToken, async (req, res, next) => {
  try {
    const usuario = req.usuario.usuario;

    // --- CAMBIO: 'query' con '$1' y recepción de 'rows' ---
    const { rows: movimientos } = await dbPool.query(
      'SELECT tipo, cantidad, categoria, descripcion, fecha FROM movimientos WHERE nombre_usuario_fk = $1 ORDER BY fecha DESC LIMIT 50',
      [usuario]
    );

    res.json({ exito: true, movimientos: movimientos });

  } catch (err) {
    next(err);
  }
});

// ==============================
// --- ¡NUEVO ENDPOINT! ---
// Endpoint para OBTENER Estadísticas
// ==============================
app.get('/api/estadisticas', verificarToken, async (req, res, next) => {
  try {
    const usuario = req.usuario.usuario;

    // Usamos la VISTA que creamos en setup_database.js
    const { rows } = await dbPool.query(
      'SELECT * FROM v_estadisticas_usuario WHERE usuario = $1',
      [usuario]
    );

    if (rows.length === 0) {
      // Caso de usuario sin movimientos
      return res.json({ 
        exito: true, 
        stats: {
          usuario: usuario,
          total_movimientos: 0,
          total_ingresos: 0,
          total_gastos: 0,
          balance_total: 0,
          ultimo_movimiento: null
        } 
      });
    }

    // Devolvemos las estadísticas del primer (y único) resultado
    res.json({ exito: true, stats: rows[0] });

  } catch (err) {
    next(err); // Dejamos que el manejador de errores global se ocupe
  }
});

// ==============================
// Servir Archivos Estáticos
// ==============================
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==============================
// Middleware Global de Manejo de Errores
// ==============================
app.use((err, req, res, _next) => { 
  console.error('=== ERROR GENERAL ===');
  // ... (Sin cambios) ...
  console.error('Error:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ==============================
// Manejo de señales de terminación
// ==============================
let isShuttingDown = false;
async function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`\n[${signal}] Cerrando servidor gracefully...`);
  try {
    // --- CAMBIO: dbPool.end() es el mismo comando para 'pg' ---
    await dbPool.end(); 
    console.log('✓ Pool de BD (PostgreSQL) cerrado');
  } catch (err) {
    console.error('✗ Error cerrando el pool de BD (PostgreSQL):', err.message);
  } finally {
    console.log('Servidor detenido.');
    const exitCode = signal === 'SIGINT' ? 130 : 0;
    process.exit(exitCode);
  }
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));