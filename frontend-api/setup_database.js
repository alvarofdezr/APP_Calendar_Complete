/*
  setup_database.js
  -------------------
  Script de inicialización de la base de datos para entornos de desarrollo.
  (ADAPTADO PARA POSTGRESQL)

  Autor: Álvaro Fernandez Ramos
*/

require("dotenv").config({ path: "../.env" });
const bcrypt = require("bcryptjs");
// --- CAMBIO: Importar 'pg' (Client) en lugar de 'mysql2' ---
const { Client } = require("pg");
const fs = require("fs");

// Configuración
const SALT_ROUNDS = 12;
const usuarios = [{ usuario: "admin", clave: "admin" }];

console.log("\n╔════════════════════════════════════════════════╗");
console.log("║   CONFIGURADOR DE BASE DE DATOS (POSTGRESQL)   ║");
console.log("╚════════════════════════════════════════════════╝\n");

async function setupDatabase() {
  // --- CAMBIO: Usar 'client' de 'pg' ---
  let client;

  try {
    // PASO 1: Generar hashes bcrypt
    console.log("📝 PASO 1: Generando hashes bcrypt...\n");

    const hashResults = [];
    for (const user of usuarios) {
      const hash = await bcrypt.hash(user.clave, SALT_ROUNDS);
      hashResults.push({
        usuario: user.usuario,
        clave: user.clave,
        hash: hash,
      });
      console.log(
        `   ✓ ${user.usuario.padEnd(20)} -> ${hash.substring(0, 30)}...`,
      );
    }

    // PASO 2: Conectar a PostgreSQL (con bucle de reintentos)
    console.log("\n🔌 PASO 2: Conectando a PostgreSQL...\n");

    const maxRetries = 10;
    const retryDelay = 2000; // 2 segundos

    for (let i = 1; i <= maxRetries; i++) {
      try {
        // --- CAMBIO: Configuración del cliente de 'pg' ---
        client = new Client({
          host: process.env.DB_HOST || "localhost",
          user: process.env.DB_USER || "PAI2-alv",
          password: process.env.DB_PASSWORD || "",
          database: process.env.DB_NAME, // <-- Conecta directo a la BD
          port: parseInt(process.env.DB_PORT) || 5432, // <-- Puerto PG
          connectionTimeoutMillis: 5000
        });

        await client.connect(); // <--- Intento de conexión
        
        console.log(
          `   ✓ Conectado a PostgreSQL en ${process.env.DB_HOST}:${process.env.DB_PORT} (intento ${i}/${maxRetries})`
        );
        break; // ¡Conexión exitosa!
        
      } catch (err) {
        console.warn(`   ... Intento ${i}/${maxRetries} fallido. Esperando ${retryDelay}ms... (Error: ${err.code})`);
        if (i === maxRetries) {
          throw err;
        }
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }

    // PASO 3 (antes 4): Crear tablas
    console.log("\n📊 PASO 3: Creando tablas...\n");
    
    // Borrar en orden: vistas, tablas hijas, tablas padre
    await client.query("DROP VIEW IF EXISTS v_estadisticas_usuario");
    console.log('   ~ Vista "v_estadisticas_usuario" anterior eliminada (si existía)');

    await client.query("DROP TABLE IF EXISTS movimientos");
    console.log('   ~ Tabla "movimientos" anterior eliminada (si existía)');
    
    await client.query("DROP TABLE IF EXISTS nonces_usados");
    console.log('   ~ Tabla "nonces_usados" anterior eliminada (si existía)');

    await client.query("DROP TABLE IF EXISTS usuarios");
    console.log('   ~ Tabla "usuarios" anterior eliminada (si existía)');

    // --- Ahora creamos las tablas (padre primero) ---

    // Tabla usuarios (Sintaxis PG)
    await client.query(`
    CREATE TABLE usuarios (
      id SERIAL PRIMARY KEY, -- <-- CAMBIO: SERIAL
      usuario VARCHAR(32) NOT NULL UNIQUE, -- <-- CAMBIO: UNIQUE aquí
      clave VARCHAR(255) NOT NULL,
      fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await client.query("CREATE INDEX IF NOT EXISTS idx_usuario ON usuarios(usuario)");
    console.log('   ✓ Tabla "usuarios" creada');

    // Tabla movimientos (Sintaxis PG)
    await client.query(`
    CREATE TABLE movimientos (
      id SERIAL PRIMARY KEY, -- <-- CAMBIO: SERIAL
      nombre_usuario_fk VARCHAR(32) NOT NULL,
      -- --- CAMBIO: ENUM se reemplaza por CHECK constraint ---
      tipo VARCHAR(10) NOT NULL CHECK (tipo IN ('ingreso', 'gasto')),
      cantidad DECIMAL(10, 2) NOT NULL,
      categoria VARCHAR(50) NOT NULL,
      descripcion VARCHAR(100),
      fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      nonce VARCHAR(64) NOT NULL,
      
      FOREIGN KEY (nombre_usuario_fk) REFERENCES usuarios(usuario) ON DELETE CASCADE
    )`);
    await client.query("CREATE INDEX IF NOT EXISTS idx_usuario_fecha ON movimientos(nombre_usuario_fk, fecha DESC)");
    await client.query("CREATE INDEX IF NOT EXISTS idx_tipo ON movimientos(tipo)");
    await client.query("CREATE INDEX IF NOT EXISTS idx_categoria ON movimientos(categoria)");
    console.log('   ✓ Tabla "movimientos" creada');

    // Tabla nonces_usados (Sintaxis PG)
    await client.query(`
    CREATE TABLE nonces_usados (
      id SERIAL PRIMARY KEY, -- <-- CAMBIO: SERIAL
      usuario VARCHAR(32) NOT NULL,
      nonce VARCHAR(64) UNIQUE NOT NULL,
      fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await client.query("CREATE INDEX IF NOT EXISTS idx_usuario_nonce ON nonces_usados(usuario, nonce)");
    console.log('   ✓ Tabla "nonces_usados" creada');

    // PASO 4 (antes 5): Insertar usuarios pre-registrados
    console.log("\n👥 PASO 4: Insertando usuarios pre-registrados...\n");

    for (const result of hashResults) {
      // --- CAMBIO: Sintaxis de 'INSERT' con 'ON CONFLICT' y placeholders '$1, $2' ---
      const insertQuery = `
        INSERT INTO usuarios (usuario, clave) 
        VALUES ($1, $2)
        ON CONFLICT (usuario) 
        DO UPDATE SET clave = EXCLUDED.clave
      `;
      await client.query(insertQuery, [result.usuario, result.hash]);
      console.log(
        `   ✓ Usuario "${result.usuario}" insertado/actualizado (contraseña: ${result.clave})`,
      );
    }

    // PASO 5 (antes 6): Crear vista de estadísticas
    console.log("\n📈 PASO 5: Creando vista de estadísticas...\n");

    // --- El SQL de la vista era compatible ---
    await client.query(`
      CREATE OR REPLACE VIEW v_estadisticas_usuario AS
      SELECT 
        u.usuario,
        COUNT(m.id) AS total_movimientos,
        COALESCE(SUM(CASE WHEN m.tipo = 'ingreso' THEN m.cantidad ELSE 0 END), 0) AS total_ingresos,
        COALESCE(SUM(CASE WHEN m.tipo = 'gasto' THEN m.cantidad ELSE 0 END), 0) AS total_gastos,
        (COALESCE(SUM(CASE WHEN m.tipo = 'ingreso' THEN m.cantidad ELSE 0 END), 0) - 
         COALESCE(SUM(CASE WHEN m.tipo = 'gasto' THEN m.cantidad ELSE 0 END), 0)) AS balance_total,
        MAX(m.fecha) AS ultimo_movimiento
      FROM usuarios u
      LEFT JOIN movimientos m ON u.usuario = m.nombre_usuario_fk
      GROUP BY u.usuario
    `);
    console.log('   ✓ Vista "v_estadisticas_usuario" creada');

    // PASO 6 (antes 7): Verificar instalación
    console.log("\n✅ PASO 6: Verificando instalación...\n");

    // --- CAMBIO: 'table_schema' ahora es 'public' (el default de PG) ---
    const { rows: tables } = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    `);
    console.log(`   ✓ Tablas encontradas: ${tables.length}`);
    tables.forEach((t) =>
      console.log(`      - ${t.table_name}`),
    );

    const { rows: users } = await client.query(
      "SELECT COUNT(*) as total FROM usuarios",
    );
    console.log(`\n   ✓ Usuarios pre-registrados: ${users[0].total}`);

    // --- CAMBIO: 'DATE_FORMAT' es 'to_char' en PG ---
    const { rows: userList } = await client.query(`
      SELECT usuario, to_char(fecha_registro, 'YYYY-MM-DD HH24:MI:SS') as fecha 
      FROM usuarios
    `);
    userList.forEach((u) =>
      console.log(`      - ${u.usuario} (registrado: ${u.fecha})`),
    );

    // PASO 7 (antes 8): Guardar información de referencia
    console.log("\n📄 PASO 7: Generando archivo de referencia...\n");

    const refContent = `
=== USUARIOS PRE-REGISTRADOS ===
Generado: ${new Date().toISOString()}

${hashResults
  .map(
    (r) => `
Usuario: ${r.usuario}
Contraseña: ${r.clave}
Hash bcrypt: ${r.hash}
`,
  )
  .join("\n")}

=== INFORMACIÓN DE CONEXIÓN ===
Host: ${process.env.DB_HOST}
Puerto: ${process.env.DB_PORT}
Base de datos: ${process.env.DB_NAME}
Usuario PostgreSQL: ${process.env.DB_USER}

=== COMANDOS ÚTILES ===

# Ver todos los usuarios:
SELECT * FROM usuarios;

# Ver estadísticas por usuario:
SELECT * FROM v_estadisticas_usuario;

# Ver últimos movimientos:
SELECT * FROM movimientos ORDER BY fecha DESC LIMIT 10;
`;

    fs.writeFileSync("database_setup_info.txt", refContent);
    console.log('   ✓ Archivo "database_setup_info.txt" creado');

    console.log("\n╔════════════════════════════════════════════════╗");
    console.log("║         ✅ CONFIGURACIÓN COMPLETADA             ║");
    console.log("╚════════════════════════════════════════════════╝\n");

  } catch (_error) {
    console.error("\n❌ ERROR durante la configuración de PostgreSQL:\n");
    console.error(_error);
    console.error("\n💡 SOLUCIONES POSIBLES:\n");
    console.error("   - Verificar que PostgreSQL está ejecutándose");
    console.error("   - Revisar credenciales en el archivo .env");
    console.error("   - Verificar que el usuario PG tiene permisos");
    console.error("   - Comprobar que el puerto 5432 está disponible\n");
    process.exit(1);
  } finally {
    if (client) {
      // --- CAMBIO: client.end() ---
      await client.end();
      console.log("🔌 Conexión a PostgreSQL cerrada\n");
    }
  }
}

// Ejecutar configuración
setupDatabase();