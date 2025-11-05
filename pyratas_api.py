#!/usr/bin/env python
# coding: utf-8

# In[10]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyratasDev API — controle de licenças (30 dias automáticos)
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import hashlib
import uuid
import json
import os
import threading
import re

API_VERSION = "1.1.2"

# ===== Caminho do DB: env > arquivo ao lado do código =====
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))

# Conexão global + lock para threads do servidor
_conn = None
_conn_lock = threading.Lock()

def _connect_once() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _conn_lock:
            if _conn is None:
                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                _conn = conn
    return _conn

# ====== UTILS ======
def normalize_key(raw: str) -> str:
    """Normaliza chave: remove espaços, converte para maiúsculas e filtra caracteres inválidos"""
    if not raw:
        return ""
    s = raw.strip().upper()
    s = re.sub(r"[^A-Z0-9\-]", "", s)
    return s

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def now_utc_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None

def require_license_table(conn: sqlite3.Connection):
    if not table_exists(conn, "license"):
        raise HTTPException(status_code=500, detail="Banco de licenças não inicializado.")

def ensure_activation_table(conn: sqlite3.Connection):
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

# =============== APP ===============
app = FastAPI(title="PyratasDev License API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    conn = _connect_once()
    ensure_activation_table(conn)

# =============== ENDPOINTS ===================

@app.get("/")
def home():
    return {"status": "ok", "msg": "API PyratasDev rodando.", "version": API_VERSION, "db_path": DB_PATH}

@app.get("/healthz")
def healthz():
    try:
        conn = _connect_once()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('license','licenses','activation')")
        tables = [r["name"] for r in cur.fetchall()]
        total = None
        if "license" in tables:
            cur.execute("SELECT COUNT(1) AS c FROM license")
            total = cur.fetchone()["c"]
        return {"ok": True, "db_path": DB_PATH, "tables": tables, "licenses_in_license": total}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

@app.post("/debug/check_key")
def debug_check_key(body: dict):
    """
    Debug: envia {"license_key": "..."} e retorna hash + confirmação se existe no DB.
    """
    license_key = normalize_key(body.get("license_key") or "")
    if not license_key:
        raise HTTPException(status_code=400, detail="Informe 'license_key'.")

    h = sha256(license_key)
    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM license WHERE license_key_hash=?", (h,))
    exists = cur.fetchone() is not None
    return {"normalized": license_key, "hash": h, "exists_in_db": exists}

@app.post("/activate")
def activate(data: dict):
    """
    Ativa licença com validade automática de 30 dias.
    """
    license_key = normalize_key(data.get("license_key") or "")
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    lic_hash = sha256(license_key)
    conn = _connect_once()
    cur = conn.cursor()

    require_license_table(conn)

    cur.execute("SELECT license_key_hash, status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Licença inválida.")

    status = row["status"]
    max_devices = row["max_devices"] or 1
    if status != "active":
        raise HTTPException(status_code=403, detail="Licença inativa.")

    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE license_key_hash=?", (lic_hash,))
    qtd = cur.fetchone()["c"]

    if qtd >= max_devices:
        cur.execute("SELECT 1 FROM activation WHERE license_key_hash=? AND device_id=?", (lic_hash, device_id))
        if cur.fetchone() is None:
            raise HTTPException(status_code=403, detail="Licença já está em uso em outro computador.")

    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT OR REPLACE INTO activation
        (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now_utc_str(), expires_at))
    conn.commit()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

@app.post("/validate")
def validate(data: dict):
    """
    Valida o token e a expiração (30 dias)
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Token e device_id são obrigatórios.")

    conn = _connect_once()
    cur = conn.cursor()

    cur.execute("SELECT expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()

    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > exp:
        return {"valid": False, "reason": "Token expirado."}

    return {"valid": True, "reason": "Token válido."}

@app.post("/renew")
def renew(data: dict):
    """
    Renova a licença por +30 dias (manual)
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    conn = _connect_once()
    cur = conn.cursor()

    cur.execute("SELECT license_key_hash FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Ativação não encontrada.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE activation SET expires_at=? WHERE token=?", (new_exp, token))
    conn.commit()

    return {"status": "ok", "new_expires_at": new_exp}

@app.get("/licenses")
def list_licenses():
    """
    Lista licenças existentes na tabela 'license'
    """
    conn = _connect_once()
    require_license_table(conn)

    cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices FROM license")
    rows = cur.fetchall()
    licenses = [
        {"license_key_hash": r["license_key_hash"], "status": r["status"], "max_devices": r["max_devices"]}
        for r in rows
    ]
    return {"count": len(licenses), "licenses": licenses}

# Exec local
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("pyratas_api:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))


# In[ ]:




