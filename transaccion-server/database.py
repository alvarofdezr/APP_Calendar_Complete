"""
Módulo de Acceso y Gestión de Base de Datos

Este módulo proporciona una capa de abstracción segura para interactuar
con la base de datos PostgreSQL. Implementa un pool de conexiones thread-safe
y manejo transaccional robusto.

Características:
---------------
- Pool de conexiones thread-safe
- Manejo automático de transacciones
- Limpieza periódica de datos antiguos
- Verificación de integridad de esquema
- Estadísticas y monitorización
- Gestión de nonces para seguridad

Funcionalidades Principales:
--------------------------
1. Gestión de conexiones:
   - Pool de conexiones configurable
   - Context managers para uso seguro
   - Manejo automático de rollback

2. Operaciones de datos:
   - Inserción de movimientos
   - Verificación de nonces
   - Estadísticas de transacciones
   - Limpieza de datos antiguos

3. Integridad y mantenimiento:
   - Verificación de esquema
   - Limpieza programada
   - Monitorización de estado

Autor: Álvaro Fernandez Ramos
Versión: 2.0.0
Licencia: MIT
"""

from datetime import timedelta, datetime
import os
import time
from contextlib import contextmanager
from dotenv import load_dotenv
import psycopg2
from psycopg2 import Error as PgError
from psycopg2 import pool
from typing import Tuple, Any

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# === Configuración de la base de datos leída desde .env ===
DB_HOST: str = os.getenv('DB_HOST')
DB_USER: str = os.getenv('DB_USER')
DB_PASSWORD: str = os.getenv('DB_PASSWORD')
DB_NAME: str = os.getenv('DB_NAME')
DB_PORT: int = int(os.getenv('DB_PORT', 5432)) # <-- Puerto cambiado
DB_POOL_SIZE: int = int(os.getenv('DB_POOL_SIZE', 5))
CLEAN_DB_ON_START: bool = os.getenv('CLEAN_DB_ON_START', 'false').lower() == 'true'

# === Pool de conexiones a la base de datos (MODIFICADO para PostgreSQL) ===
# Usamos un pool seguro para hilos (ThreadedConnectionPool)
try:
    print(f"Creando pool de conexiones para PG en {DB_HOST}:{DB_PORT} (DB: {DB_NAME})")
    db_pool: psycopg2.pool.ThreadedConnectionPool = pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=DB_POOL_SIZE,
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
        port=DB_PORT,
        connect_timeout=5
    )
except (PgError, pool.PoolError) as e:
    print(f"Error fatal: No se pudo conectar al pool de PostgreSQL: {e}")
    exit(1)


@contextmanager
def db_cursor() -> Tuple[Any, Any]: 
    """ Context manager para obtener una conexión y un cursor del pool (Versión PG)."""
    conn, cursor = None, None
    try:
        # Obtener conexión del pool
        conn = db_pool.getconn()
        conn.autocommit = False # Asegurar que estamos en modo transacción
        cursor = conn.cursor()
        
        # Entregar el control
        yield conn, cursor
        
        # Si todo fue bien, se hace commit (aunque las funciones lo hacen)
        conn.commit()

    except (PgError, psycopg2.pool.PoolError) as e:
        print(f"Error de base de datos: {e}")
        if conn:
            conn.rollback() # Revertir cambios en caso de error
        raise 
    finally: 
        if cursor is not None:
            cursor.close()
        if conn is not None:
            # Devolver la conexión al pool
            db_pool.putconn(conn)

def is_nonce_used(nonce: str) -> bool:
    """ Verifica si un nonce ya ha sido utilizado. (SQL idéntico)"""
    with db_cursor() as (conn, cursor):
        cursor.execute("SELECT id FROM nonces_usados WHERE nonce = %s", (nonce,))
        return cursor.fetchone() is not None

def mark_nonce_as_used(usuario: str, nonce: str) -> None:
    """ Registra un nonce como utilizado en la base de datos. (SQL idéntico)"""
    with db_cursor() as (conn, cursor):
        cursor.execute("INSERT INTO nonces_usados (usuario, nonce) VALUES (%s, %s)", (usuario, nonce))
        conn.commit()

def insert_movimiento(tipo: str, cantidad: float, categoria: str, descripcion: str, usuario: str, nonce: str) -> None:
    """ Inserta un nuevo movimiento en la base de datos. (SQL idéntico)"""
    with db_cursor() as (conn, cursor):
        cursor.execute(
            "INSERT INTO movimientos (tipo, cantidad, categoria, descripcion, nombre_usuario_fk, nonce) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (tipo, cantidad, categoria, descripcion, usuario, nonce)
        )
        conn.commit()

def borrar_tablas_al_inicio() -> None:
    """ Limpia las tablas de movimientos y nonces al iniciar. (Adaptado a PG)"""
    print("Limpiando tablas 'movimientos' y 'nonces_usados'...")
    with db_cursor() as (conn, cursor):
        # En PG, TRUNCATE es más eficiente y reinicia secuencias
        cursor.execute("TRUNCATE TABLE movimientos, nonces_usados RESTART IDENTITY;")
        conn.commit()
    print("✓ Tablas limpiadas.")

def limpiar_nonces_antiguos(max_timestamp_window: int = 86400) -> int:
    """ Elimina nonces antiguos basados en la columna 'fecha'. (SQL idéntico)"""
    deleted_count = 0 
    try:
        with db_cursor() as (conn, cursor):
            cutoff_time: datetime = datetime.now() - timedelta(seconds=max_timestamp_window)
            cutoff_time_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute(
                "DELETE FROM nonces_usados WHERE fecha < %s",
                (cutoff_time,)
            )
            deleted_count = cursor.rowcount
            conn.commit()

        if deleted_count > 0:
            print(f"Limpiados {deleted_count} nonces antiguos (anteriores a {cutoff_time_str})")
        else:
            print("No se encontraron nonces antiguos para limpiar.")

    except PgError as e:
        print(f"Error al limpiar nonces antiguos: {e}")

    return deleted_count

def get_movimientos_count(usuario: str) -> int:
    """ Obtiene el número total de movimientos de un usuario. (SQL idéntico)"""
    with db_cursor() as (conn, cursor):
        cursor.execute(
            "SELECT COUNT(*) FROM movimientos WHERE nombre_usuario_fk = %s", 
            (usuario,)
        )
        result = cursor.fetchone()
        return result[0] if result else 0
    
def get_transaction_stats() -> dict:
    """ Obtiene estadísticas generales de movimientos. (SQL idéntico)"""
    with db_cursor() as (conn, cursor):
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM movimientos")
        stats['total_movimientos'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT nombre_usuario_fk) FROM movimientos")
        stats['usuarios_activos'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(cantidad) FROM movimientos WHERE tipo = 'ingreso'")
        result_ingresos = cursor.fetchone()
        stats['suma_ingresos'] = float(result_ingresos[0]) if result_ingresos[0] else 0.0
        
        cursor.execute("SELECT SUM(cantidad) FROM movimientos WHERE tipo = 'gasto'")
        result_gastos = cursor.fetchone()
        stats['suma_gastos'] = float(result_gastos[0]) if result_gastos[0] else 0.0

        stats['balance_total'] = stats['suma_ingresos'] - stats['suma_gastos']
        
        cursor.execute("SELECT COUNT(*) FROM nonces_usados")
        stats['nonces_almacenados'] = cursor.fetchone()[0]
        
        return stats

def verify_database_integrity() -> Tuple[bool, str]:
    """ Verifica la integridad básica del esquema de la base de datos. (Adaptado a PG)"""
    try:
        with db_cursor() as (conn, cursor):
            required_tables = ['usuarios', 'movimientos', 'nonces_usados']
            
            # Consultar el catálogo de PG (schema 'public' por defecto)
            cursor.execute("""
                SELECT tablename FROM pg_tables 
                WHERE schemaname = 'public'
            """)
            existing_tables = [table[0] for table in cursor.fetchall()]
            
            for table in required_tables:
                if table not in existing_tables:
                    return False, f"Falta la tabla requerida: {table}"
            
            # Verificar columnas en 'movimientos'
            cursor.execute("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'movimientos' AND table_schema = 'public'
            """)
            columns = [col[0] for col in cursor.fetchall()]
            required_columns = ['id', 'tipo', 'cantidad', 'categoria', 'nombre_usuario_fk', 'nonce']
            
            for col in required_columns:
                if col not in columns:
                    return False, f"Falta la columna '{col}' en la tabla movimientos"
            
            return True, "Integridad de la base de datos verificada correctamente"
            
    except PgError as e:
        return False, f"Error al verificar integridad: {str(e)}"
    
def get_user_movimientos(usuario: str, limit: int = 10) -> list:
    """ Obtiene las últimas transacciones de un usuario. (Adaptado a PG)"""
    with db_cursor() as (conn, cursor):
        cursor.execute(
            """
            SELECT id, tipo, categoria, descripcion, cantidad, fecha, nonce 
            FROM movimientos 
            WHERE nombre_usuario_fk = %s 
            ORDER BY fecha DESC 
            LIMIT %s
            """, 
            (usuario, limit)
        )
        
        # Obtenemos los nombres de las columnas del cursor
        columns = [desc[0] for desc in cursor.description]
        movimientos = []
        
        for row in cursor.fetchall():
            movimiento = dict(zip(columns, row))
            if movimiento['fecha']:
                movimiento['fecha'] = movimiento['fecha'].isoformat()
            movimientos.append(movimiento)
        
        return movimientos
    
def initialize_database() -> bool:
    """ Inicializa la base de datos verificando integridad y realizando limpieza inicial."""
    print("\n=== Inicializando Base de Datos (PostgreSQL) ===")
    
    # Bucle de reintento para la verificación de integridad
    max_retries = 10
    retry_delay = 2 # segundos
    for i in range(max_retries):
        try:
            is_valid, message = verify_database_integrity()
            if not is_valid:
                print(f"✗ Error de integridad (intento {i+1}/{max_retries}): {message}")
                if i == max_retries - 1: return False # Fallo final
                time.sleep(retry_delay)
                continue
            
            print(f"✓ {message}")
            
            if CLEAN_DB_ON_START:
                borrar_tablas_al_inicio()
            
            # Limpia nonces de más de 1h
            limpiar_nonces_antiguos(max_timestamp_window=3600) 
            
            stats = get_transaction_stats()
            print(f"✓ Estadísticas iniciales:")
            print(f"  - Movimientos totales: {stats['total_movimientos']}")
            print(f"  - Usuarios activos: {stats['usuarios_activos']}")
            print(f"  - Balance total: {stats['balance_total']:.2f} €")
            print(f"  - Nonces almacenados: {stats['nonces_almacenados']}")
            
            print("=== Base de Datos Lista ===\n")
            return True # ¡Éxito!
        
        except (PgError, psycopg2.pool.PoolError) as e:
            print(f"✗ Error conectando a BD (intento {i+1}/{max_retries}): {e}")
            if i == max_retries - 1: 
                print("Error fatal: No se pudo inicializar la base de datos.")
                return False # Fallo final
            time.sleep(retry_delay)
            
    return False # No debería llegar aquí, pero por si acaso