# 🏦 Sistema Seguro de Transacciones con Microservicios

<div align="center">

  ![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
  ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
  ![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
  ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
  ![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
  ![TLS](https://img.shields.io/badge/TLS%201.3-004880?style=for-the-badge&logo=internet-security&logoColor=white)
  ![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white)

  <br />

  [![Estado](https://img.shields.io/badge/Estado-Estable-green?style=flat-square)](./)
  [![Seguridad](https://img.shields.io/badge/Seguridad-Verificada-blue?style=flat-square)](./)
  [![Licencia](https://img.shields.io/badge/Licencia-MIT-purple?style=flat-square)](./LICENSE)

  <p align="center">
    <a href="#-sobre-el-proyecto">Sobre el Proyecto</a> •
    <a href="#-arquitectura">Arquitectura</a> •
    <a href="#️-instalación-y-despliegue">Instalación</a> •
    <a href="#-api-rest">API</a> •
    <a href="#-desarrollo">Desarrollo</a>
  </p>

</div>

## 📋 Índice

- [Sobre el Proyecto](#-sobre-el-proyecto)
- [Características Principales](#-características-principales)
- [Tecnologías](#-tecnologías)
- [Arquitectura](#-arquitectura)
- [Instalación y Despliegue](#️-instalación-y-despliegue)
- [Estructura de Archivos](#-estructura-de-archivos)
- [API REST](#-api-rest)
- [Desarrollo](#-desarrollo)
- [Licencia](#-licencia)

## 🎯 Sobre el Proyecto

Este proyecto implementa una plataforma segura de **gestión de finanzas personales** utilizando una arquitectura de microservicios. El sistema está diseñado con un fuerte enfoque en la seguridad, garantizando la integridad y confidencialidad de las transacciones financieras.

El sistema se divide en dos componentes principales:
1.  Un **Servidor API (Node.js)** que actúa como *frontend*, sirviendo la interfaz de usuario (HTML/JS) y gestionando la autenticación (registro y login).
2.  Un **Servidor de Transacciones (Python)** que actúa como *backend* seguro, recibiendo y procesando los movimientos financieros a través de un socket TLS 1.3.

Ambos servicios se conectan a una base de datos **PostgreSQL** compartida y están completamente orquestados por **Docker Compose** para un despliegue sencillo y unificado.

---

## 🚀 Características Principales

- **Arquitectura de Microservicios:** Un servidor `Node.js (Express)` maneja la API pública y el frontend, mientras que un servidor `Python` independiente y aislado procesa la lógica de negocio crítica.
- **Seguridad Multi-capa:**
  - **Autenticación:** Sistema de registro y login basado en `JWT` (JSON Web Tokens).
  - **Contraseñas:** Hasheo seguro de contraseñas en la base de datos usando `bcrypt`.
  - **Comunicaciones Cifradas:** `HTTPS` para el cliente y `TLS 1.3` forzado para la comunicación interna entre los servidores Node y Python.
  - **Integridad y Anti-Replay:** Verificación de cada transacción mediante `HMAC-SHA256` y uso de `Nonces` únicos para prevenir ataques.
- **Contenerización Completa:** Configuración con `Docker` y `Docker Compose` para un despliegameinto y orquestación sencillos de todos los servicios (Node, Python y PostgreSQL).
- **Base de Datos Robusta:** Utiliza `PostgreSQL` con un esquema bien definido y un script de inicialización automático.
- **Despliegue Automatizado:** Incluye un servicio `db-setup` en Docker Compose que inicializa la base de datos y crea las tablas necesarias al arrancar, simplificando la configuración inicial.

---

## 🛠️ Tecnologías

| Categoría | Tecnología | Propósito |
| :--- | :--- | :--- |
| **Backend API** | Node.js, Express | Servir frontend, API de autenticación y proxy de transacciones. |
| | `bcryptjs`, `jsonwebtoken` | Hashing de claves y gestión de sesiones JWT. |
| | `helmet`, `express-rate-limit` | Seguridad de cabeceras HTTP y Rate Limiting. |
| | `pg` | Conexión a PostgreSQL. |
| **Backend Transaccional**| Python 3.11 | Servidor de socket seguro (TLS) para procesar la lógica de negocio. |
| | `psycopg2-binary` | Pool de conexiones a PostgreSQL. |
| | `python-dotenv` | Gestión de variables de entorno. |
| **Base de Datos** | PostgreSQL 15 | Almacenamiento persistente de usuarios, movimientos y nonces. |
| **DevOps** | Docker, Docker Compose | Contenerización y orquestación de servicios. |
| **Seguridad** | OpenSSL | Generación de certificados y cifrado TLS 1.3. |

---

## 🏛️ Arquitectura

```text
  +------------------+      HTTPS      +------------------------+      TLS 1.3      +----------------------+
  |                  | <------------> |                        | <---------------> |                      |
  |  Cliente         |                |   Servidor Node.js     |                   |   Servidor Python    |
  |  (Navegador)     |                |   (API & Frontend)     |                   |   (Transaccional)    |
  |                  |                |                        |                   |   (python-socket)    |
  +------------------+                +-----------+------------+                   +-----------+----------+
                                                  |                                            |
                                                  | Autenticación, Frontend                    | Validación y
                                                  | y Conexión a BD                            | Procesamiento
                                                  v                                            v
                                            +----------------------------------------------------+
                                            |                                                    |
                                            |               PostgreSQL Database (db)             |
                                            |         (Usuarios, Movimientos, Nonces)            |
                                            +----------------------------------------------------+
```

---

## ⚙️ Instalación y Despliegue

### Prerrequisitos

- Docker (`≥ 20.x`)
- Docker Compose (`≥ 2.x`)

### 1. Estructura de Archivos

Asegúrate de que tu proyecto sigue esta estructura:

```text
APP_Calendar_Complete/
│
├── .env 
├── docker-compose.yml 
│
├── certs/ 
│ ├── server.cert
│ ├── server.key
│ └── rootCA.pem
│
├── frontend-api/
│ ├── Dockerfile
│ ├── package.json
│ ├── server.js
│ ├── setup_database.js
│ └── public/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   └── movimientos.html
│
└── transaccion-server/
    ├── Dockerfile
    ├── requirements.txt
    ├── serversocket.py
    └── database.py
```

---

## 🔗 API REST

El servidor `frontend-api` expone los siguientes endpoints para la gestión de usuarios y la interacción con el backend de transacciones.

### Autenticación

*   `POST /api/register`
    *   **Descripción:** Registra un nuevo usuario en el sistema.
    *   **Body:** `{ "username": "user", "password": "password" }`
    *   **Respuesta Exitosa:** `201 Created` - `{ "message": "Usuario registrado exitosamente" }`

*   `POST /api/login`
    *   **Descripción:** Autentica a un usuario y devuelve un token JWT.
    *   **Body:** `{ "username": "user", "password": "password" }`
    *   **Respuesta Exitosa:** `200 OK` - `{ "token": "jwt_token" }`

### Transacciones

*   `POST /api/movimientos`
    *   **Descripción:** Envía una nueva transacción (ingreso o gasto) al servidor seguro de Python para su procesamiento.
    *   **Headers:** `{ "Authorization": "Bearer jwt_token" }`
    *   **Body:** `{ "tipo": "ingreso", "monto": 100.00, "descripcion": "Depósito" }`
    *   **Respuesta Exitosa:** `200 OK` - `{ "message": "Transacción recibida" }`

*   `GET /api/movimientos`
    *   **Descripción:** Obtiene el historial de transacciones del usuario autenticado.
    *   **Headers:** `{ "Authorization": "Bearer jwt_token" }`
    *   **Respuesta Exitosa:** `200 OK` - `[{ "id": 1, "tipo": "ingreso", ... }, ...]`

---
