#!/usr/bin/env python
# coding: utf-8

# In[8]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyratasDev API — controle de licenças (30 dias automáticos)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import sqlite3
import hashlib
import uuid
import json
import os

DB_PATH = "licenses.db"
API_VERSION = "1.1.0"

app = FastAPI(title="PyratasDev License API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============== UTILIDADES ===================
def db_conn():
    return sqlite3.connect(DB_PATH)

def now_utc():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def hash_key(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()

def table_exists(conn, table):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None

def ensure_activation_table():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS activation (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key_hash TEXT,
        device_id TEXT,
        token TEXT,
        fingerprint TEXT,
        activated_at TEXT,
        expires_at TEXT,
        UNIQUE(license_key_hash, device_id)
    )
    """)
    conn.commit()
    conn.close()

ensure_activation_table()

# =============== ENDPOINTS ===================

@app.get("/")
def home():
    return {"status": "ok", "msg": "API PyratasDev rodando.", "version": API_VERSION}


@app.post("/activate")
def activate(data: dict):
    """
    Ativa licença com validade automática de 30 dias.
    """
    license_key = data.get("license_key")
    device_id = data.get("device_id")
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    lic_hash = hash_key(license_key)

    conn = db_conn()
    cur = conn.cursor()

    # Confere se a licença existe
    if not table_exists(conn, "license"):
        raise HTTPException(status_code=500, detail="Banco de licenças não inicializado.")
    cur.execute("SELECT license_key_hash, status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Licença inválida.")

    status = row[1]
    max_devices = row[2] or 1
    if status != "active":
        conn.close()
        raise HTTPException(status_code=403, detail="Licença inativa.")

    # Conta quantos dispositivos já ativaram
    cur.execute("SELECT COUNT(*) FROM activation WHERE license_key_hash=?", (lic_hash,))
    qtd = cur.fetchone()[0]

    if qtd >= max_devices:
        # Se já tem o mesmo device, pode renovar
        cur.execute("SELECT * FROM activation WHERE license_key_hash=? AND device_id=?", (lic_hash, device_id))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=403, detail="Licença já está em uso em outro computador.")

    # Gera novo token com validade de 30 dias
    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
    INSERT OR REPLACE INTO activation (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (lic_hash, device_id, token, json.dumps(fingerprint), now_utc(), expires_at))

    conn.commit()
    conn.close()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}


@app.post("/validate")
def validate(data: dict):
    """
    Valida o token e a expiração (30 dias)
    """
    token = data.get("token")
    device_id = data.get("device_id")
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Token e device_id são obrigatórios.")

    conn = db_conn()
    cur = conn.cursor()

    cur.execute("SELECT expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    conn.close()

    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    exp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > exp:
        return {"valid": False, "reason": "Token expirado."}

    return {"valid": True, "reason": "Token válido."}


@app.post("/renew")
def renew(data: dict):
    """
    Renova a licença por +30 dias (manual)
    """
    token = data.get("token")
    device_id = data.get("device_id")
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT license_key_hash FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Ativação não encontrada.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE activation SET expires_at=? WHERE token=?", (new_exp, token))
    conn.commit()
    conn.close()

    return {"status": "ok", "new_expires_at": new_exp}


@app.get("/licenses")
def list_licenses():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices FROM license")
    rows = cur.fetchall()
    conn.close()
    return {"count": len(rows), "licenses": rows}

