"""
Super Downloader - License Server
Flask API que valida licencias por email + código
"""
import os
import sqlite3
import hashlib
import secrets
import smtplib
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

# Configuración
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.environ.get("DB_PATH", "/tmp/licenses.db")
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
CODE_EXPIRY_MINUTES = 15
TOKEN_EXPIRY_DAYS = 365

print(f"[CONFIG] EMAIL_USER={EMAIL_USER}, EMAIL_PASS={'SET' if EMAIL_PASS else 'EMPTY'}, DB={DB_PATH}")

init_db()

# ─────────────────────────────────────────────
# BASE DE DATOS
# ─────────────────────────────────────────────
def init_db():
    """Crea las tablas si no existen"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Usuarios registrados
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hwid TEXT,
            token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)

    # Códigos de verificación temporales
    c.execute("""
        CREATE TABLE IF NOT EXISTS codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            hwid TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            attempts INTEGER DEFAULT 0
        )
    """)

    # Log de intentos (anti-brute force)
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────
def generate_code():
    """Genera un código de 6 dígitos"""
    return str(secrets.randbelow(900000) + 100000)

def generate_token(email, hwid):
    """Genera un JWT token que dura 1 año"""
    payload = {
        "email": email,
        "hwid": hwid,
        "exp": datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    """Verifica si un token es válido"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

def send_email(to_email, code):
    """Envía el código por email (usa Gmail SMTP)"""
    print(f"[EMAIL] EMAIL_USER={EMAIL_USER}, EMAIL_PASS={'***' if EMAIL_PASS else 'EMPTY'}")
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"[DEV] Código para {to_email}: {code}")
        return True  # En desarrollo, solo imprime

    msg = MIMEText(f"""
Tu código de activación es: {code}

Este código expira en {CODE_EXPIRY_MINUTES} minutos.
Si no solicitaste este código, ignorá este email.

Super Downloader Team
    """)
    msg["Subject"] = "Super Downloader - Tu código de activación"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print(f"[EMAIL] Email enviado a {to_email}")
        return True
    except Exception as e:
        print(f"[EMAIL] Error enviando email: {e}")
        return False

def check_rate_limit(email, ip_address):
    """Anti-brute force: máximo 5 intentos por hora"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    c.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE (email = ? OR ip_address = ?) AND created_at > ?
    """, (email, ip_address, one_hour_ago))

    count = c.fetchone()[0]
    conn.close()

    return count < 5  # True = puede intentar

def log_attempt(email, ip_address):
    """Registra un intento"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO login_attempts (email, ip_address) VALUES (?, ?)
    """, (email, ip_address))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Health check"""
    return jsonify({"status": "ok", "version": "1.0"})

@app.route("/api/activate", methods=["POST"])
def activate():
    """
    Paso 1: Usuario pide activación
    Envía: { "email": "user@gmail.com", "hwid": "ABC123..." }
    Responde: { "success": true, "message": "Código enviado" }
    """
    try:
        data = request.json
        email = data.get("email", "").strip().lower()
        hwid = data.get("hwid", "")

        if not email or "@" not in email:
            return jsonify({"success": False, "error": "Email inválido"}), 400

        ip = request.remote_addr

        # Rate limit
        if not check_rate_limit(email, ip):
            log_attempt(email, ip)
            return jsonify({"success": False, "error": "Demasiados intentos. Esperá 1 hora."}), 429

        log_attempt(email, ip)

        # Generar código
        code = generate_code()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Borrar códigos viejos de este email
        c.execute("DELETE FROM codes WHERE email = ?", (email,))

        # Guardar nuevo código
        c.execute("""
            INSERT INTO codes (email, code, hwid) VALUES (?, ?, ?)
        """, (email, code, hwid))
        conn.commit()
        conn.close()

        # Enviar email
        email_ok = send_email(email, code)
        if email_ok:
            return jsonify({"success": True, "message": "Código enviado a tu email"})
        else:
            # Si falla el email, devolver el código directamente (modo fallback)
            return jsonify({"success": True, "message": "Código generado", "code": code})

    except Exception as e:
        print(f"[ERROR] activate: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/verify", methods=["POST"])
def verify():
    """
    Paso 2: Usuario ingresa el código
    Envía: { "email": "user@gmail.com", "code": "482951", "hwid": "ABC123..." }
    Responde: { "success": true, "token": "eyJ..." }
    """
    data = request.json
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()
    hwid = data.get("hwid", "")

    if not email or not code:
        return jsonify({"success": False, "error": "Email y código requeridos"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Buscar código
    c.execute("""
        SELECT id, code, hwid, created_at FROM codes
        WHERE email = ? ORDER BY id DESC LIMIT 1
    """, (email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"success": False, "error": "No hay código pendiente para este email"}), 400

    db_id, db_code, db_hwid, created_at = row

    # Verificar código
    if db_code != code:
        # Incrementar intentos
        c.execute("UPDATE codes SET attempts = attempts + 1 WHERE id = ?", (db_id,))
        conn.commit()

        # Si falló 3 veces, borrar código
        c.execute("SELECT attempts FROM codes WHERE id = ?", (db_id,))
        attempts = c.fetchone()[0]
        if attempts >= 3:
            c.execute("DELETE FROM codes WHERE id = ?", (db_id,))
            conn.commit()
            conn.close()
            return jsonify({"success": False, "error": "Código incorrecto 3 veces. Pedí uno nuevo."}), 400

        conn.close()
        return jsonify({"success": False, "error": f"Código incorrecto ({attempts}/3)"}), 400

    # Verificar que no expiró
    created = datetime.fromisoformat(created_at)
    if datetime.utcnow() - created > timedelta(minutes=CODE_EXPIRY_MINUTES):
        c.execute("DELETE FROM codes WHERE id = ?", (db_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": False, "error": "Código expirado. Pedí uno nuevo."}), 400

    # ¡Éxito! Generar token
    token = generate_token(email, hwid)

    # Guardar en users
    c.execute("""
        INSERT OR REPLACE INTO users (email, hwid, token, expires_at)
        VALUES (?, ?, ?, ?)
    """, (email, hwid, token, (datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()))

    # Borrar código usado
    c.execute("DELETE FROM codes WHERE id = ?", (db_id,))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "token": token,
        "expires": (datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()
    })

@app.route("/api/check", methods=["POST"])
def check():
    """
    Paso 3: App valida token existente
    Envía: { "token": "eyJ...", "hwid": "ABC123..." }
    Responde: { "valid": true, "email": "user@gmail.com" }
    """
    data = request.json
    token = data.get("token", "")
    hwid = data.get("hwid", "")

    if not token:
        return jsonify({"valid": False, "error": "Token requerido"}), 400

    payload = verify_token(token)
    if not payload:
        return jsonify({"valid": False, "error": "Token inválido o expirado"}), 401

    # Verificar HWID
    if payload.get("hwid") != hwid:
        return jsonify({"valid": False, "error": "Token no válido para esta PC"}), 403

    return jsonify({
        "valid": True,
        "email": payload["email"],
        "expires": payload["exp"]
    })

# ─────────────────────────────────────────────
# MERCADOPAGO WEBHOOK
# ─────────────────────────────────────────────
@app.route("/api/webhook", methods=["POST"])
def webhook():
    """
    Recibe notificaciones de MercadoPago cuando alguien paga
    """
    data = request.json

    if data.get("type") == "payment":
        payment_id = data.get("data", {}).get("id")

        # Obtener detalles del pago
        import os
        mp_token = os.environ.get("MP_ACCESS_TOKEN", "")
        if not mp_token:
            print("[WEBHOOK] No MP_ACCESS_TOKEN configured")
            return jsonify({"received": True})

        url = f"https://api.mercadopago.com/v1/payments/{payment_id}"
        headers = {"Authorization": f"Bearer {mp_token}"}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            payment = response.json()

            if payment.get("status") == "approved":
                email = payment.get("payer", {}).get("email")
                hwid = payment.get("metadata", {}).get("hwid", "")

                if email:
                    # Generar código y enviar
                    code = generate_code()
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute("DELETE FROM codes WHERE email = ?", (email,))
                    c.execute("INSERT INTO codes (email, code, hwid) VALUES (?, ?, ?)",
                             (email, code, hwid))
                    conn.commit()
                    conn.close()

                    send_email(email, code)
                    print(f"[WEBHOOK] Código enviado a {email}")

        except Exception as e:
            print(f"[WEBHOOK] Error: {e}")

    return jsonify({"received": True})

@app.route("/api/payment/success", methods=["GET"])
def payment_success():
    """Página de éxito después del pago"""
    return """
    <html>
    <head><title>Pago Exitoso</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>¡Pago realizado con éxito!</h1>
        <p>Revisá tu email para obtener el código de activación.</p>
        <p>Podés cerrar esta ventana.</p>
    </body>
    </html>
    """

# ─────────────────────────────────────────────
# INICIAR
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("License Server started on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
