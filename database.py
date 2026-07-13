import sqlite3

def init_db():
    conn = sqlite3.connect("vault.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY, password_hash BLOB, salt BLOB, totp_secret TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_name TEXT, username TEXT, encrypted_password BLOB,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT, detail TEXT, ip_address TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP)""")
    # migration safeguard for existing DBs created before this column existed
    try:
        c.execute("ALTER TABLE vault ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()

def save_master(password_hash, salt, totp_secret):
    conn = sqlite3.connect("vault.db")
    conn.execute("INSERT INTO master (password_hash, salt, totp_secret) VALUES (?, ?, ?)", (password_hash, salt, totp_secret))
    conn.commit()
    conn.close()

def get_master():
    conn = sqlite3.connect("vault.db")
    row = conn.execute("SELECT password_hash, salt, totp_secret FROM master LIMIT 1").fetchone()
    conn.close()
    return row

def add_entry(site, username, encrypted_pw):
    conn = sqlite3.connect("vault.db")
    conn.execute(
        "INSERT INTO vault (site_name, username, encrypted_password, created_at) VALUES (?, ?, ?, datetime('now'))",
        (site, username, encrypted_pw))
    conn.commit()
    conn.close()

def get_all_entries():
    conn = sqlite3.connect("vault.db")
    rows = conn.execute("SELECT id, site_name, username, encrypted_password, created_at FROM vault").fetchall()
    conn.close()
    return rows

def delete_entry(entry_id):
    conn = sqlite3.connect("vault.db")
    conn.execute("DELETE FROM vault WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()

def log_action(action, detail="", ip_address=""):
    conn = sqlite3.connect("vault.db")
    conn.execute("INSERT INTO audit_log (action, detail, ip_address) VALUES (?, ?, ?)",
                 (action, detail, ip_address))
    conn.commit()
    conn.close()

def get_audit_log(limit=50):
    conn = sqlite3.connect("vault.db")
    rows = conn.execute(
        "SELECT action, detail, ip_address, timestamp FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()
    conn.close()
    return rows