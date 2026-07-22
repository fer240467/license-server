"""
Super Downloader - License Server
Flask API que valida licencias por email + codigo
"""
import os
import sqlite3
import hashlib
import secrets
import smtplib
import time
import requests
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_KEY = os.environ.get("ADMIN_KEY", "superdownloader_admin_2024")
DB_PATH = os.environ.get("DB_PATH", "/tmp/licenses.db")
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
CODE_EXPIRY_MINUTES = 15
TOKEN_EXPIRY_DAYS = 365

print(f"[CONFIG] EMAIL_USER={EMAIL_USER}, EMAIL_PASS={'SET' if EMAIL_PASS else 'EMPTY'}, DB={DB_PATH}")

# ─────────────────────────────────────────────
# BASE DE DATOS
# ─────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
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
    c.execute("""
        CREATE TABLE IF NOT EXISTS trial_dates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE NOT NULL,
            install_date TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
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

init_db()

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────
def generate_code():
    return str(secrets.randbelow(900000) + 100000)

def generate_token(email, hwid):
    payload = {
        "email": email,
        "hwid": hwid,
        "exp": datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def send_email(to_email, code):
    print(f"[EMAIL] EMAIL_USER={EMAIL_USER}, EMAIL_PASS={'***' if EMAIL_PASS else 'EMPTY'}")
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"[DEV] Codigo para {to_email}: {code}")
        return True

    msg = MIMEText(f"""
Tu codigo de activacion es: {code}

Este codigo expira en {CODE_EXPIRY_MINUTES} minutos.
Si no solicitaste este codigo, ignora este email.

Super Downloader Team
    """)
    msg["Subject"] = "Super Downloader - Tu codigo de activacion"
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    c.execute("""
        SELECT COUNT(*) FROM login_attempts
        WHERE (email = ? OR ip_address = ?) AND created_at > ?
    """, (email, ip_address, one_hour_ago))
    count = c.fetchone()[0]
    conn.close()
    return count < 5

def log_attempt(email, ip_address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO login_attempts (email, ip_address) VALUES (?, ?)",
              (email, ip_address))
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "2.0"})


@app.route("/api/admin/clear-trial", methods=["POST"])
def admin_clear_trial():
    """Admin: limpia datos de prueba de un HWID"""
    data = request.get_json()
    admin_key = data.get("admin_key", "")
    hwid = data.get("hwid", "")

    if admin_key != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    if not hwid:
        return jsonify({"error": "hwid required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM trial_dates WHERE hwid = ?", (hwid,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Trial data cleared for {hwid}"})


@app.route("/api/trial-register", methods=["POST"])
def trial_register():
    data = request.get_json()
    hwid = data.get("hwid")
    install_date = data.get("date")

    if not hwid or not install_date:
        return jsonify({"error": "hwid and date required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT install_date FROM trial_dates WHERE hwid = ?", (hwid,))
    existing = c.fetchone()

    if existing:
        conn.close()
        return jsonify({"date": existing[0], "existing": True})

    c.execute("INSERT INTO trial_dates (hwid, install_date) VALUES (?, ?)",
              (hwid, install_date))
    conn.commit()
    conn.close()
    return jsonify({"date": install_date, "existing": False})


@app.route("/api/trial-date", methods=["GET"])
def trial_date():
    hwid = request.args.get("hwid")
    if not hwid:
        return jsonify({"error": "hwid required"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT install_date FROM trial_dates WHERE hwid = ?", (hwid,))
    row = c.fetchone()
    conn.close()

    if row:
        return jsonify({"date": row[0]})
    return jsonify({"date": None})


@app.route("/api/activate", methods=["POST"])
def activate():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    hwid = data.get("hwid", "")

    if not email or "@" not in email:
        return jsonify({"error": "Email invalido"}), 400

    ip = request.remote_addr or "unknown"

    if not check_rate_limit(email, ip):
        return jsonify({"error": "Demasiados intentos. Espera una hora."}), 429

    log_attempt(email, ip)

    code = generate_code()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM codes WHERE email = ?", (email,))
    c.execute("INSERT INTO codes (email, code, hwid) VALUES (?, ?, ?)",
              (email, code, hwid))
    conn.commit()
    conn.close()

    send_email(email, code)
    return jsonify({"success": True, "message": "Codigo enviado a tu email"})


@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()
    hwid = data.get("hwid", "")

    if not email or not code:
        return jsonify({"error": "Email y codigo requeridos"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT id, code, hwid, created_at, attempts FROM codes
        WHERE email = ? ORDER BY id DESC LIMIT 1
    """, (email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "No hay codigo pendiente para este email"})

    code_id, stored_code, stored_hwid, created_at, attempts = row

    if attempts >= 3:
        conn.close()
        return jsonify({"error": "Demasiados intentos. Solicita un nuevo codigo."})

    c.execute("UPDATE codes SET attempts = attempts + 1 WHERE id = ?", (code_id,))
    conn.commit()

    created = datetime.fromisoformat(created_at)
    if datetime.utcnow() - created > timedelta(minutes=CODE_EXPIRY_MINUTES):
        conn.close()
        return jsonify({"error": "El codigo expiro. Solicita uno nuevo."})

    if code != stored_code:
        conn.close()
        return jsonify({"error": "Codigo incorrecto"})

    token = generate_token(email, hwid)
    expires = (datetime.utcnow() + timedelta(days=TOKEN_EXPIRY_DAYS)).isoformat()

    c.execute("DELETE FROM codes WHERE email = ?", (email,))
    c.execute("""
        INSERT OR REPLACE INTO users (email, hwid, token, expires_at)
        VALUES (?, ?, ?, ?)
    """, (email, hwid, token, expires))
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "token": token,
        "expires": expires
    })


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json()
    token = data.get("token", "")
    hwid = data.get("hwid", "")

    if not token:
        return jsonify({"valid": False, "error": "Token requerido"})

    payload = verify_token(token)
    if not payload:
        return jsonify({"valid": False, "error": "Token invalido o expirado"})

    if payload.get("hwid") != hwid:
        return jsonify({"valid": False, "error": "Token no valido para esta PC"})

    return jsonify({
        "valid": True,
        "email": payload.get("email"),
        "expires": str(payload.get("exp"))
    })


# ─────────────────────────────────────────────
# MERCADOPAGO WEBHOOK
# ─────────────────────────────────────────────
@app.route("/api/webhook", methods=["POST"])
def webhook():
    data = request.json

    if data.get("type") == "payment":
        payment_id = data.get("data", {}).get("id")
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
                    code = generate_code()
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute("DELETE FROM codes WHERE email = ?", (email,))
                    c.execute("INSERT INTO codes (email, code, hwid) VALUES (?, ?, ?)",
                              (email, code, hwid))
                    conn.commit()
                    conn.close()
                    send_email(email, code)
                    print(f"[WEBHOOK] Codigo enviado a {email}")

        except Exception as e:
            print(f"[WEBHOOK] Error: {e}")

    return jsonify({"received": True})


@app.route("/api/payment/success", methods=["GET"])
def payment_success():
    return """
    <html>
    <head><title>Pago Exitoso</title></head>
    <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1>Pago realizado con exito!</h1>
        <p>Revisa tu email para obtener el codigo de activacion.</p>
        <p>Podes cerrar esta ventana.</p>
    </body>
    </html>
    """


if __name__ == "__main__":
    print("License Server started on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
