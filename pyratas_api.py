#!/usr/bin/env python
# coding: utf-8

# In[10]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyratasDev API — licenças com ativação 30d + métricas/uso
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3, hashlib, uuid, json, os, threading

API_VERSION = "1.2.0"

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))

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

def now_utc_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

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

def ensure_usage_table(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,          -- e.g. 'run', 'validate_ok'
            meta TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")
    conn.commit()

app = FastAPI(title="PyratasDev License API", version=API_VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def _startup():
    conn = _connect_once()
    ensure_activation_table(conn)
    ensure_usage_table(conn)

@app.get("/")
def home():
    return {"status": "ok", "msg": "API PyratasDev rodando.", "version": API_VERSION, "db_path": DB_PATH}

@app.get("/healthz")
def healthz():
    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('license','licenses','activation','usage')")
    tables = [r["name"] for r in cur.fetchall()]
    total = None
    if "license" in tables:
        cur.execute("SELECT COUNT(1) AS c FROM license")
        total = cur.fetchone()["c"]
    return {"ok": True, "db_path": DB_PATH, "tables": tables, "licenses_in_license": total}

@app.post("/activate")
def activate(data: dict):
    license_key = (data.get("license_key") or "").strip()
    device_id   = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    lic_hash = sha256(license_key)
    conn = _connect_once()
    cur = conn.cursor()
    require_license_table(conn)

    cur.execute("SELECT status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Licença inválida.")
    if (row["status"] or "") != "active":
        raise HTTPException(status_code=403, detail="Licença inativa.")
    max_devices = row["max_devices"] or 1

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

    # log de uso: ativação
    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), lic_hash, device_id, "activate", "{}"))
    conn.commit()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

@app.post("/validate")
def validate(data: dict):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Token e device_id são obrigatórios.")

    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    valid = datetime.utcnow() <= exp
    # loga tentativa de validação
    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), row["license_key_hash"], device_id, "validate_ok" if valid else "validate_expired", "{}"))
    conn.commit()

    if not valid:
        return {"valid": False, "reason": "Token expirado."}
    return {"valid": True, "reason": "Token válido."}

@app.post("/renew")
def renew(data: dict):
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

    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), row["license_key_hash"], device_id, "renew", json.dumps({"new_expires_at": new_exp})))
    conn.commit()

    return {"status": "ok", "new_expires_at": new_exp}

@app.get("/licenses")
def list_licenses():
    conn = _connect_once()
    require_license_table(conn)
    cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices FROM license")
    rows = cur.fetchall()
    return {"count": len(rows), "licenses": [dict(r) for r in rows]}

@app.get("/activations")
def list_activations(limit: int = 100):
    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, license_key_hash, device_id, token, activated_at, expires_at
        FROM activation
        ORDER BY id DESC
        LIMIT ?
    """, (max(1, min(limit, 1000)),))
    rows = cur.fetchall()
    return {"rows": [dict(r) for r in rows]}

@app.post("/usage")
def add_usage(data: dict):
    # opcional: o robô chama este endpoint quando inicia uma execução
    lic_hash = (data.get("license_key_hash") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    event = (data.get("event") or "run").strip()
    meta = json.dumps(data.get("meta", {}), ensure_ascii=False)
    if not lic_hash or not device_id:
        raise HTTPException(status_code=400, detail="license_key_hash e device_id obrigatórios.")
    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), lic_hash, device_id, event, meta))
    conn.commit()
    return {"status": "ok"}

@app.get("/stats")
def stats():
    conn = _connect_once()
    cur = conn.cursor()
    # total licenses
    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    # active activations
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]
    # unique devices
    cur.execute("SELECT COUNT(DISTINCT device_id) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    unique_devices = cur.fetchone()["c"]
    # expiring in 7d
    cur.execute(\"\"\"\n        SELECT COUNT(*) AS c\n        FROM activation\n        WHERE datetime(expires_at) BETWEEN datetime('now') AND datetime('now','+7 days')\n    \"\"\")\n    expiring_7d = cur.fetchone()[\"c\"]\n    # usage last 24h\n    cur.execute(\"\"\"\n        SELECT COUNT(*) AS c FROM usage\n        WHERE datetime(ts) > datetime('now','-1 day')\n    \"\"\")\n    usage_24h = cur.fetchone()[\"c\"]\n    return {\n        \"total_licenses\": total_licenses,\n        \"active_activations\": active_activations,\n        \"unique_devices\": unique_devices,\n        \"expiring_7d\": expiring_7d,\n        \"usage_24h\": usage_24h,\n    }\n\n# Exec local (opcional)\nif __name__ == \"__main__\":\n    import uvicorn\n    uvicorn.run(\"pyratas_api:app\", host=\"0.0.0.0\", port=int(os.getenv(\"PORT\", 8000)))\n```\n\n**Deploy:** é só substituir seu arquivo no Render e confirmar que o `licenses.db` está no mesmo diretório (ou setar `LICENSE_DB` no Render para o caminho certo). O CORS já está liberado para o painel.\n\n---\n\n# B) Ping de uso no robô (contagem de vezes que roda)\n\nDepois de **validar/ativar** com sucesso, manda um POST `/usage` com o `license_key_hash` e `device_id`. O robô já tem a chave em texto — transforme em hash (mesma sha256 da API):\n\n```python\nimport hashlib, requests\n\nAPI_BASE = \"https://pyratas-api.onrender.com\"  # ajuste se usar outro domínio\n\ndef sha256(s: str) -> str:\n    import hashlib\n    return hashlib.sha256(s.encode(\"utf-8\")).hexdigest()\n\n# ... após validar/ativar com sucesso:\nlic_hash = sha256(license_key)\ntry:\n    requests.post(f\"{API_BASE}/usage\", json={\n        \"license_key_hash\": lic_hash,\n        \"device_id\": device_id,\n        \"event\": \"run\",\n        \"meta\": {\n            \"profiles\": NUM_PERFIS,\n            \"port_start\": PORTA_BASE\n        }\n    }, timeout=5)\nexcept Exception:\n    pass  # não quebra o robô se métrica falhar\n```\n\nSe preferir **não** calcular o hash no robô, você pode alterar o `/usage` para aceitar `license_key` plaintext e hashear no servidor — me avisa que te mando a variante.\n\n---\n\n# C) Painel administrativo (online, tempo real)\n\nJá deixei no **canvas** um dashboard React “Pyratas Admin Dashboard (React)”. Ele:\n- Lê de `GET /stats`, `GET /licenses`, `GET /activations?limit=100`, `GET /healthz`.\n- Tem campo de **API Base** (salva no `localStorage`), **auto-refresh** (5–60s), filtros, e tabelas de Licenças/Ativações.\n\nPara usar, basta publicar esse componente (ou copiar para um seu projeto). Se quiser, eu mando uma versão vanilla HTML+JS (sem build) também.\n\n---\n\n## Testes rápidos (via curl)\n\n```bash\n# saúde\ncurl -s https://pyratas-api.onrender.com/healthz | jq\n\n# stats\ncurl -s https://pyratas-api.onrender.com/stats | jq\n\n# lista licenças\ncurl -s https://pyratas-api.onrender.com/licenses | jq\n\n# ativa (troque pelos seus valores)\ncurl -s -X POST https://pyratas-api.onrender.com/activate \\\n  -H 'content-type: application/json' \\\n  -d '{\"license_key\":\"PYR-...\",\"device_id\":\"PC-TESTE\",\"fingerprint\":{\"os\":\"Windows\"}}' | jq\n\n# registrar uso\ncurl -s -X POST https://pyratas-api.onrender.com/usage \\\n  -H 'content-type: application/json' \\\n  -d '{\"license_key_hash\":\"<sha256_da_chave>\",\"device_id\":\"PC-TESTE\",\"event\":\"run\"}' | jq\n```\n\n---\n\nSe quiser, eu também coloco **/usage/top** (rank por licença), **/activations/by-license/{hash}**, etc. Mas com isso você já tem: painel vivo, stats agregadas e contagem de usos por dia. Quer que eu já gere a versão HTML pura (sem React) pra subir direto no Hostinger/Render Static?
::contentReference[oaicite:0]{index=0}


# In[ ]:




