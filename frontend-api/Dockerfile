# Usar una imagen oficial de Node.js
FROM node:18-alpine

# Establecer el directorio de trabajo
WORKDIR /usr/src/app

# Copiar el package.json y package-lock.json (si existe)
COPY package*.json ./

# Instalar dependencias
RUN npm install

# Copiar el resto del código de la app (server.js, setup_database.js, y la carpeta public/)
COPY . .

# Exponer el puerto en el que corre la app
EXPOSE 5031

# Comando por defecto para iniciar el servidor
CMD [ "node", "server.js" ]