"""
Servidor de Procesamiento de Transacciones Seguro (TLS)

Este módulo implementa un servidor de socket TLS que actúa como backend
de procesamiento para el sistema bancario. Recibe y valida transacciones
firmadas desde el servidor web Node.js.

Características de Seguridad:
-----------------------------
- TLS 1.3 forzado para todas las conexiones
- Validación HMAC-SHA256 de cada mensaje
- Sistema de nonces para prevención de replay attacks
- Ventana de tiempo configurable para timestamps
- Validación estricta de tipos y formatos
- Logging detallado de operaciones y errores

Flujo de Procesamiento:
----------------------
1. Recepción de conexión TLS
2. Validación del mensaje JSON
3. Verificación de timestamp
4. Validación de firma HMAC
5. Verificación de nonce único
6. Procesamiento de la transacción
7. Persistencia en base de datos

Dependencias:
------------
- database.py: Gestión de persistencia y pool de conexiones
- SSL/TLS: Certificados y configuración de seguridad
- Threading: Manejo concurrente de conexiones
- JSON: Procesamiento de mensajes
- HMAC: Validación criptográfica

Autor: Álvaro Fernandez Ramos
Versión: 2.0.0
Licencia: MIT
"""

import socket
import os
import json
import hmac
import hashlib
import logging
import ssl
import time
from dotenv import load_dotenv
import threading
from typing import Tuple, Optional
import database as db

# Configuración del sistema de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s"
)

# Cargar las variables de entorno
load_dotenv()

# === Variables de configuración ===
HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
PORT: int = int(os.getenv("SERVER_PORT", 5030))
HMAC_KEY: str = os.getenv('HMAC_KEY')
MAX_MSG_SIZE: int = int(os.getenv('MAX_MESSAGE_SIZE', 8192))
MAX_TIMESTAMP_WINDOW: int = int(os.getenv('MAX_TIMESTAMP_WINDOW', 300))  # 5 MINUTOS

if not HMAC_KEY:
    raise RuntimeError("Falta la variable de entorno HMAC_KEY")

# === Rutas a los certificados TLS ===
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__)) 
CERT: str = os.path.join(BASE_DIR, 'certs', 'server.cert') # Ruta corregida para subir un nivel
KEY: str = os.path.join(BASE_DIR, 'certs', 'server.key') # Ruta corregida para subir un nivel

# === Contexto TLS del servidor ===
context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile=CERT, keyfile=KEY)

# === Funciones de validación ===
def hmac_validate(key: str, nonce: str, timestamp: int, usuario: str, mensaje: str, mac_hex: str) -> bool:
    data: bytes = f"{nonce}|{timestamp}|{usuario}|{mensaje}".encode('utf-8')
    computed: str = hmac.new(key.encode('utf-8'), data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, mac_hex)

def validate_timestamp(timestamp: int) -> Tuple[bool, str]:
    current_time: int = int(time.time())
    time_diff: int = abs(current_time - timestamp)
    if time_diff > MAX_TIMESTAMP_WINDOW:
        logging.warning(f"Timestamp invalido: {timestamp} (diferencia {time_diff} segundos)")
        return False, f"ERROR timestamp fuera de rango"
    return True, ""

def validate_and_parse_message(obj: dict) -> Tuple[Optional[tuple], Optional[str]]:
    """Valida la estructura, tipos y contenido básico del JSON recibido."""
    required: list[str] = ['usuario', 'mensaje', 'nonce', 'timestamp', 'mac']
    if not all(k in obj for k in required):
        return None, "ERROR campos faltantes"

    try:
        usuario: str = obj['usuario']
        mensaje: str = obj['mensaje']
        nonce: str = obj['nonce']
        if not isinstance(obj['timestamp'], int):
            raise TypeError("Timestamp debe ser un entero")
        timestamp: int = obj['timestamp']
        mac: str = obj['mac']

        if not all(isinstance(val, str) for val in [usuario, mensaje, nonce, mac]):
            return None, "ERROR tipo de dato incorrecto en los campos"
        
        if not all([usuario, mensaje, nonce, mac]):
            return None, "ERROR campos no pueden estar vacíos"

        return (usuario, mensaje, nonce, timestamp, mac), None
    
    except KeyError as e:
        return None, f"ERROR campo requerido ausente: {e}"
    except (ValueError, TypeError) as e:
        logging.warning(f"Error de tipo o valor en el mensaje: {e}")
        return None, "ERROR en el formato o tipo de los campos"

# === Manejo de conexión con el cliente ===
def handle_client(conn: ssl.SSLSocket, addr: tuple) -> None:
    """Procesa una conexión de cliente individual."""
    conn.settimeout(10)
    try:
        raw: bytes = conn.recv(MAX_MSG_SIZE)

        if not raw:
            logging.warning(f"Conexión de {addr} cerrada sin enviar datos.")
            return

        data_str: str = raw.decode('utf-8').strip()
        logging.info(f"Datos recibidos: {data_str[:100]}...")

        try:
            obj: dict = json.loads(data_str)

            if obj.get('tipo') != 'MSG':
                conn.sendall(b"ERROR tipo no soportado")
                return

            # 1. Validar y parsear mensaje
            datos, err = validate_and_parse_message(obj)
            if err:
                logging.warning(f"Validación fallida para {addr}: {err}")
                conn.sendall(err.encode('utf-8'))
                return
            
            usuario, mensaje, nonce, timestamp, mac = datos

            # 2. Validar timestamp
            timestamp_valid, ts_err = validate_timestamp(timestamp)
            if not timestamp_valid:
                logging.warning(f"Timestamp invalido de {addr}: {timestamp}")
                conn.sendall(ts_err.encode('utf-8'))
                return
            
            # 3. Validar HMAC
            if not hmac_validate(HMAC_KEY, nonce, timestamp, usuario, mensaje, mac):
                logging.warning(f"MAC inválido para usuario {usuario} desde {addr}")
                conn.sendall(b"ERROR MAC invalido")
                return
            
            # 4. Validar Nonce (anti-replay)
            if db.is_nonce_used(nonce):
                logging.warning(f"Nonce reutilizado detectado para usuario {usuario}: {nonce}")
                conn.sendall(b"ERROR nonce ya usado")
                return
            
            # Si todo es válido, marcamos el nonce como usado
            db.mark_nonce_as_used(usuario, nonce)

            # 5. Procesar el movimiento (¡CAMBIO AQUÍ!)
            partes: list[str] = [p.strip() for p in mensaje.split(',')]
            if len(partes) != 4: # Ahora son 4 partes
                conn.sendall(b"ERROR formato mensaje")
                return
            
            tipo, cantidad_str, categoria, descripcion = partes
            
            # Validar tipo
            if tipo not in ('ingreso', 'gasto'):
                conn.sendall(b"ERROR tipo invalido (ingreso/gasto)")
                return

            cantidad = float(cantidad_str) 
            if cantidad <= 0:
                raise ValueError("La cantidad debe ser positiva")

            # 6. Registrar el movimiento en la base de datos
            db.insert_movimiento(tipo, cantidad, categoria, descripcion, usuario, nonce)
            
            # Devolver el nuevo total de movimientos
            total_movs = db.get_movimientos_count(usuario)
            respuesta = f"OK Movimiento registrado (Total: {total_movs})"
            
            conn.sendall(respuesta.encode('utf-8'))
            logging.info(f"Movimiento registrado: {usuario} -> {mensaje} (Total: {total_movs})")

        except json.JSONDecodeError:
            logging.error(f"Error decodificando JSON de {addr}")
            conn.sendall(b"ERROR JSON invalido")
        except ValueError as e:
            logging.error(f"Error de valor en el mensaje de {addr}: {e}")
            conn.sendall(b"ERROR Cantidad invalida")
        except Exception as e:
            logging.error(f"Error en el formato del mensaje de {addr}: {e}")
            conn.sendall(b"ERROR Formato de mensaje incorrecto")

    except socket.timeout:
        logging.error(f"Timeout en la conexión con {addr}")
    except Exception as e:
        logging.exception(f"Error inesperado procesando la conexión de {addr}: {e}")
        try:
            conn.sendall(b"ERROR interno del servidor")
        except Exception:
            pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except (OSError, socket.error):
            pass 
        conn.close()

# === Funciones de arranque ===
def handle_client_wrapper(conn: socket.socket, addr: tuple) -> None:
    try:
        with context.wrap_socket(conn, server_side=True) as tls_conn:
            cipher = tls_conn.cipher()
            version = tls_conn.version()
            logging.info(f"Conexión TLS establecida desde: {addr} con {cipher}, versión {version}")
            handle_client(tls_conn, addr)
    except ssl.SSLError as e:
        logging.error(f"Error de SSL con {addr}: {e}")
    except Exception as e:
        logging.error(f"Error inesperado en el hilo del cliente {addr}: {e}")
    finally:
        if conn.fileno() != -1:
            conn.close()

# === Bucle principal del servidor ===
def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(100)
        print(f"Servidor TCP+TLS escuchando en {HOST}:{PORT}")
        print(f"Configuración de seguridad:")
        print(f"  - Protocolo mínimo: TLS 1.3")
        print(f"  - Cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256")
        print(f"  - Ventana de timestamp: {MAX_TIMESTAMP_WINDOW} segundos")
        while True:
            conn, addr = sock.accept()
            logging.info(f"Nueva conexión entrante desde: {addr}")
            client_thread = threading.Thread(
                target=handle_client_wrapper,
                args=(conn, addr),
                daemon=True
            )
            client_thread.start()

# === Punto de entrada del programa ===
if __name__ == "__main__":
    # La función initialize_database ya se encarga de todo
    db.initialize_database()
    main()