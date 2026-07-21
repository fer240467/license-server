# Super Downloader - License Server

Servidor de licencias para Super Downloader. Maneja trial de 30 días y licencias de 1 año.

## Estructura

```
license-server/
├── api/
│   ├── server.py          # Flask API principal
│   ├── requirements.txt   # Dependencias
│   └── render.yaml        # Configuración para Render.com
├── README.md
└── .gitignore
```

## Setup Local

1. Instalar dependencias:
```bash
pip install -r api/requirements.txt
```

2. Configurar variables de entorno (opcional para desarrollo):
```bash
set EMAIL_USER=tu@gmail.com
set EMAIL_PASS=contraseña-de-aplicación
```

3. Ejecutar servidor:
```bash
cd api
python server.py
```

El servidor corre en `http://localhost:5000`

## Deploy en Render.com

1. Crear cuenta en [render.com](https://render.com)
2. Crear un "Web Service"
3. Conectar repositorio de GitHub
4. Configurar:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn server:app`
   - Environment Variables:
     - `SECRET_KEY`: clave secreta (se genera automáticamente)
     - `EMAIL_USER`: tu email de Gmail
     - `EMAIL_PASS`: contraseña de aplicación de Gmail

## Variables de Entorno

| Variable | Descripción |
|----------|-------------|
| `SECRET_KEY` | Clave para firmar JWT tokens |
| `EMAIL_USER` | Email para enviar códigos |
| `EMAIL_PASS` | Contraseña de aplicación de Gmail |
| `DB_PATH` | Ruta de SQLite (default: `licenses.db`) |

## API Endpoints

### Health Check
```
GET /api/health
Response: { "status": "ok", "version": "1.0" }
```

### Activar (enviar código)
```
POST /api/activate
Body: { "email": "user@gmail.com", "hwid": "ABC123..." }
Response: { "success": true, "message": "Código enviado" }
```

### Verificar código
```
POST /api/verify
Body: { "email": "user@gmail.com", "code": "482951", "hwid": "ABC123..." }
Response: { "success": true, "token": "eyJ...", "expires": "2025-..." }
```

### Validar token
```
POST /api/check
Body: { "token": "eyJ...", "hwid": "ABC123..." }
Response: { "valid": true, "email": "user@gmail.com", "expires": "..." }
```

### Webhook MercadoPago
```
POST /api/webhook
Body: { "type": "payment", "data": { "id": 12345 } }
Response: { "received": true }
```

## Flujo de Activación

1. **Primer día**: App muestra "Período de prueba: 30 días restantes"
2. **Día 30**: App muestra "Tu período de prueba ha expirado"
3. **Usuario paga**: Botón "Pagar con MercadoPago" → abre navegador
4. **Pago aprobado**: MercadoPago envía webhook al servidor
5. **Servidor envía código**: Email con código de 6 dígitos
6. **Usuario activa**: Ingresa email + código en la app
7. **App valida**: Envía al servidor, recibe token JWT
8. **Token guardado**: App funciona por 1 año

## Seguridad

- JWT tokens con expiración de 1 año
- Rate limiting: máximo 5 intentos por hora
- Códigos expiran en 15 minutos
- Máximo 3 intentos por código
- HWID vincula licencia a una PC

## Gmail Setup

Para enviar emails necesitás una "Contraseña de Aplicación":

1. Ir a https://myaccount.google.com/apppasswords
2. Habilitar verificación en 2 pasos
3. Crear contraseña de aplicación
4. Usar esa contraseña en `EMAIL_PASS`

## MercadoPago Setup

1. Crear cuenta en https://www.mercadopago.com.ar
2. Ir a https://www.mercadopago.com.ar/developers
3. Crear aplicación
4. Obtener Access Token de producción
5. Configurar webhook URL: `https://tu-super-downloader-license.onrender.com/api/webhook`
