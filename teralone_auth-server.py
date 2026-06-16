import http.server
import socketserver
import json
import time
import hashlib
import secrets
import threading
import sys
import sqlite3
import os
from pathlib import Path
from urllib.parse import urlparse

PORT = 8000
DB_FILE = os.getenv("AUTH_SERVER_DB", str(Path(__file__).parent / "auth_server.db"))
lock = threading.Lock()
_v = getattr(sys, 'frozen', False)

def init_db():
    if _v or "__compiled__" in globals(): sys.exit(0)
    # Tự động cập nhật code từ GitHub khi khởi động
    try:
        os.system("git pull")
    except: pass
    
    with lock:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (user TEXT PRIMARY KEY, pw TEXT, salt TEXT, data TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS tokens 
                     (at TEXT PRIMARY KEY, user TEXT, exp REAL, rt TEXT, ip TEXT, env TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions 
                     (st TEXT PRIMARY KEY, user TEXT, ip TEXT, exp REAL)''')
        conn.commit()
        conn.close()

def cleanup_db():
    with lock:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        now = time.time()
        c.execute("DELETE FROM tokens WHERE exp < ?", (now,))
        c.execute("DELETE FROM sessions WHERE exp < ?", (now,))
        conn.commit()
        conn.close()

def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return h.hex(), salt

def is_same_network(ip1, ip2):
    # Heuristic: Compare first two octets (usually enough for ISP changes)
    p1 = ip1.split('.')
    p2 = ip2.split('.')
    if len(p1) < 2 or len(p2) < 2: return ip1 == ip2
    return p1[:2] == p2[:2]

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def get_client_ip(self):
        cf_ip = self.headers.get('CF-Connecting-IP')
        forwarded = self.headers.get('X-Forwarded-For')
        return cf_ip or (forwarded.split(',')[0].strip() if forwarded else self.client_address[0])

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_POST(self):
        # Fragmentation check
        if _v: sys.exit(1)
        
        ip = self.get_client_ip()
        content_length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(content_length).decode())
        except:
            return self._send_json({"success": False, "message": "Invalid JSON"}, 400)

        path = urlparse(self.path).path.rstrip('/')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()

        if path == "/check":
            user = body.get("user")
            c.execute("SELECT 1 FROM users WHERE user=?", (user,))
            exists = c.fetchone() is not None
            conn.close()
            return self._send_json({"exists": exists})

        if path == "/auth":
            user, pw, action, env = body.get("user"), body.get("pass"), body.get("action"), body.get("env", "Unknown")
            if action == "register":
                c.execute("SELECT 1 FROM users WHERE user=?", (user,))
                if c.fetchone():
                    conn.close()
                    return self._send_json({"success": False, "message": "User exists"}, 400)
                hpw, salt = hash_pw(pw)
                c.execute("INSERT INTO users VALUES (?,?,?,?)", (user, hpw, salt, "{}"))
            elif action == "login":
                c.execute("SELECT pw, salt FROM users WHERE user=?", (user,))
                row = c.fetchone()
                if not row or hash_pw(pw, row[1])[0] != row[0]:
                    conn.close()
                    return self._send_json({"success": False, "message": "Invalid credentials"}, 401)
            
            at, rt, exp = secrets.token_hex(32), secrets.token_hex(32), time.time() + 3*24*3600
            # Remove redundant sessions from same IP/Env to prevent bloat
            c.execute("DELETE FROM tokens WHERE user=? AND ip=? AND env=?", (user, ip, env))
            c.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?)", (at, user, exp, rt, ip, env))
            conn.commit()
            conn.close()
            cleanup_db()
            return self._send_json({"success": True, "at": at, "rt": rt, "exp": exp})

        if path == "/session":
            at = body.get("at")
            c.execute("SELECT user, exp, ip FROM tokens WHERE at=?", (at,))
            row = c.fetchone()
            if not row or row[1] < time.time() or not is_same_network(row[2], ip):
                if row:
                    c.execute("DELETE FROM tokens WHERE user=?", (row[0],))
                    c.execute("DELETE FROM sessions WHERE user=?", (row[0],))
                    conn.commit()
                conn.close()
                return self._send_json({"success": False, "message": "Invalid/Expired/IP Mismatch"}, 401)
            
            user = row[0]
            # Clear previous short-lived sessions for this user/IP
            c.execute("DELETE FROM sessions WHERE user=? AND ip=?", (user, ip))
            st, exp = secrets.token_hex(16), time.time() + 15*60
            c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (st, user, ip, exp))
            conn.commit()
            conn.close()
            return self._send_json({"success": True, "st": st})

        if path == "/refresh":
            rt, env = body.get("rt"), body.get("env", "Unknown")
            c.execute("SELECT user, ip FROM tokens WHERE rt=?", (rt,))
            row = c.fetchone()
            if not row or not is_same_network(row[1], ip):
                if row:
                    c.execute("DELETE FROM tokens WHERE user=?", (row[0],))
                    c.execute("DELETE FROM sessions WHERE user=?", (row[0],))
                    conn.commit()
                conn.close()
                return self._send_json({"success": False, "message": "Invalid RT or IP Mismatch"}, 401)
            
            user = row[0]
            c.execute("DELETE FROM tokens WHERE rt=?", (rt,))
            at, nrt, exp = secrets.token_hex(32), secrets.token_hex(32), time.time() + 3*24*3600
            c.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?)", (at, user, exp, nrt, ip, env))
            conn.commit()
            conn.close()
            return self._send_json({"success": True, "at": at, "rt": nrt, "exp": exp})

        if path == "/sessions/list":
            at = body.get("at")
            c.execute("SELECT user FROM tokens WHERE at=?", (at,))
            row = c.fetchone()
            if not row:
                conn.close()
                return self._send_json({"success": False, "message": "Unauthorized"}, 401)
            user = row[0]
            c.execute("SELECT at, ip, env, exp FROM tokens WHERE user=?", (user,))
            rows = c.fetchall()
            sessions = [{"id": r[0][:8], "ip": r[1], "env": r[2], "exp": r[3], "current": (r[0] == at)} for r in rows]
            conn.close()
            return self._send_json({"success": True, "sessions": sessions})

        if path == "/sessions/revoke":
            at, target_id = body.get("at"), body.get("target_id")
            c.execute("SELECT user FROM tokens WHERE at=?", (at,))
            row = c.fetchone()
            if not row:
                conn.close()
                return self._send_json({"success": False, "message": "Unauthorized"}, 401)
            user = row[0]
            c.execute("DELETE FROM tokens WHERE user=? AND at LIKE ?", (user, target_id + "%"))
            conn.commit()
            conn.close()
            return self._send_json({"success": True})

        if path == "/passwd":
            user, old_pw, new_pw = body.get("user"), body.get("old_pass"), body.get("new_pass")
            c.execute("SELECT pw, salt FROM users WHERE user=?", (user,))
            row = c.fetchone()
            if not row or hash_pw(old_pw, row[1])[0] != row[0]:
                conn.close()
                return self._send_json({"success": False, "message": "Invalid old password"}, 401)
            
            nhpw, nsalt = hash_pw(new_pw)
            c.execute("UPDATE users SET pw=?, salt=? WHERE user=?", (nhpw, nsalt, user))
            c.execute("DELETE FROM tokens WHERE user=?", (user,))
            c.execute("DELETE FROM sessions WHERE user=?", (user,))
            conn.commit()
            conn.close()
            return self._send_json({"success": True, "message": "Password updated"})

        if path == "/sync":
            st, client_data = body.get("st"), body.get("data")
            c.execute("SELECT user, ip, exp FROM sessions WHERE st=?", (st,))
            row = c.fetchone()
            if not row:
                conn.close()
                return self._send_json({"success": False, "message": "Invalid session"}, 401)
            if not is_same_network(row[1], ip):
                c.execute("DELETE FROM tokens WHERE user=?", (row[0],))
                c.execute("DELETE FROM sessions WHERE user=?", (row[0],))
                conn.commit()
                conn.close()
                return self._send_json({"success": False, "message": "IP mismatch, session revoked"}, 403)
            if row[2] < time.time():
                c.execute("DELETE FROM sessions WHERE st=?", (st,))
                conn.commit()
                conn.close()
                return self._send_json({"success": False, "message": "Session expired"}, 401)

            user = row[0]
            c.execute("SELECT data FROM users WHERE user=?", (user,))
            db_data = json.loads(c.fetchone()[0])
            if client_data:
                db_data.update(client_data)
                c.execute("UPDATE users SET data=? WHERE user=?", (json.dumps(db_data), user))
                conn.commit()
            conn.close()
            return self._send_json({"success": True, "data": db_data})

        conn.close()
        self._send_json({"message": "Not Found"}, 404)

if __name__ == "__main__":
    init_db()
    print(f"Server starting on port {PORT}...")
    with socketserver.TCPServer(("", PORT), AuthHandler) as httpd:
        httpd.serve_forever()
