# Aplicación de Login - Cifrado Híbrido + ECC

## Setup rápido

### 1. BD en XAMPP
- Abre `http://localhost/phpmyadmin`
- Pestaña SQL → pega contenido de `database.sql` → Ejecuta

### 2. Instalar dependencias
```bash
npm install
```

### 3. Correr
```bash
npm start
```

Abre `http://localhost:3000`

## Para ver el cifrado en Network

1. Abre DevTools (F12)
2. Pestaña **Network**
3. Ve a Login
4. Haz login
5. Busca `POST /login` en la tabla
6. Haz clic y verás:
   - **Headers**: X-Cipher-Type, X-Hash-Algorithm, X-ECC-Curve, etc.
   - **Request**: { email, password }
   - **Response**: JSON con cifrado y tokenes cifrados
