# Funcionalidades Adicionales Implementadas

Este documento describe las nuevas funcionalidades que han sido replicadas del repositorio de referencia [Ng17Dotnet8RoleBaseAuthJWT](https://github.com/pushpa-raj-dangi/Ng17Dotnet8RoleBaseAuthJWT.git) en tu proyecto AuthAPI.

## 🚀 Nuevas Funcionalidades

### 1. **Refresh Tokens**
- **Endpoint**: `POST /api/account/refresh-token`
- **Descripción**: Permite renovar el access token usando un refresh token válido
- **Autenticación**: No requiere autenticación
- **Body**:
```json
{
  "refreshToken": "token-de-refresh"
}
```

### 2. **Revocar Tokens**
- **Endpoint**: `POST /api/account/revoke-token`
- **Descripción**: Revoca todos los refresh tokens del usuario autenticado
- **Autenticación**: Requiere autenticación
- **Uso**: Para logout seguro

### 3. **Recuperación de Contraseña (Forgot Password)**
- **Endpoint**: `POST /api/account/forgot-password`
- **Descripción**: Envía un email con enlace para resetear contraseña
- **Autenticación**: No requiere autenticación
- **Body**:
```json
{
  "email": "usuario@ejemplo.com"
}
```

### 4. **Reset de Contraseña**
- **Endpoint**: `POST /api/account/reset-password`
- **Descripción**: Resetea la contraseña usando el token enviado por email
- **Autenticación**: No requiere autenticación
- **Body**:
```json
{
  "email": "usuario@ejemplo.com",
  "token": "token-del-email",
  "newPassword": "nueva-contraseña",
  "confirmPassword": "confirmar-contraseña"
}
```

### 5. **Cambio de Contraseña**
- **Endpoint**: `POST /api/account/change-password`
- **Descripción**: Permite al usuario autenticado cambiar su contraseña
- **Autenticación**: Requiere autenticación
- **Body**:
```json
{
  "currentPassword": "contraseña-actual",
  "newPassword": "nueva-contraseña",
  "confirmPassword": "confirmar-contraseña"
}
```

### 6. **Listar Todos los Usuarios**
- **Endpoint**: `GET /api/account/users`
- **Descripción**: Obtiene la lista de todos los usuarios (solo para administradores)
- **Autenticación**: Requiere rol "Admin"
- **Respuesta**: Lista de usuarios con sus roles

## 📧 Configuración de Email

Para que funcione la recuperación de contraseña, necesitas configurar SMTP en `appsettings.json`:

```json
{
  "SmtpSettings": {
    "SmtpServer": "smtp.gmail.com",
    "SmtpPort": 587,
    "SmtpUsername": "tu-email@gmail.com",
    "SmtpPassword": "tu-app-password"
  }
}
```

### Configuración para Gmail:
1. Activa la verificación en dos pasos
2. Genera una contraseña de aplicación
3. Usa esa contraseña en `SmtpPassword`

## 🔄 Flujo de Refresh Tokens

1. **Login**: El usuario recibe un access token y un refresh token
2. **Uso**: El access token se usa para las peticiones
3. **Renovación**: Cuando el access token expira, usar el refresh token para obtener uno nuevo
4. **Logout**: Revocar todos los refresh tokens

## 📊 Nuevos DTOs Creados

- `ForgotPasswordDto`: Para solicitar recuperación de contraseña
- `ResetPasswordDto`: Para resetear contraseña
- `ChangePasswordDto`: Para cambiar contraseña
- `UserListDto`: Para listar usuarios
- `TokenDto`: Para manejar tokens
- `RefreshTokenDto`: Para refresh tokens

## 🗄️ Nuevos Modelos

- `RefreshToken`: Modelo para almacenar refresh tokens en la base de datos

## 🔧 Cambios en la Base de Datos

Se agregó la tabla `RefreshTokens` con los campos:
- `Token` (Primary Key)
- `UserId` (Foreign Key)
- `ExpiryDate`
- `IsRevoked`
- `CreatedDate`

## 🚀 Cómo Probar las Funcionalidades

### 1. Login con Refresh Token
```bash
POST /api/account/login
{
  "email": "usuario@ejemplo.com",
  "password": "contraseña"
}
```

### 2. Renovar Token
```bash
POST /api/account/refresh-token
{
  "refreshToken": "token-recibido-en-login"
}
```

### 3. Recuperar Contraseña
```bash
POST /api/account/forgot-password
{
  "email": "usuario@ejemplo.com"
}
```

### 4. Listar Usuarios (Admin)
```bash
GET /api/account/users
Authorization: Bearer {token}
```

## ⚠️ Notas Importantes

1. **Configuración de Email**: Asegúrate de configurar correctamente SMTP para que funcione la recuperación de contraseña
2. **Seguridad**: Los refresh tokens tienen una validez de 7 días
3. **Roles**: Algunos endpoints requieren rol "Admin"
4. **Base de Datos**: Se aplicó la migración para crear la tabla RefreshTokens

## 🎯 Beneficios de las Nuevas Funcionalidades

- **Seguridad mejorada**: Refresh tokens para renovación automática
- **Experiencia de usuario**: Recuperación de contraseña por email
- **Gestión de usuarios**: Listado completo para administradores
- **Logout seguro**: Revocación de tokens
- **Flexibilidad**: Cambio de contraseña para usuarios autenticados

¡Tu API de autenticación ahora tiene todas las funcionalidades del repositorio de referencia! 