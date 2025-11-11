# Usar una imagen oficial de Python
FROM python:3.11-slim

# Establecer el directorio de trabajo
WORKDIR /usr/src/app

# Copiar el archivo de requisitos
COPY requirements.txt ./

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código (serversocket.py, database.py)
COPY . .

# Exponer el puerto del socket
EXPOSE 5030

# Comando por defecto para iniciar el servidor
CMD [ "python", "serversocket.py" ]