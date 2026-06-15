import http.server
import socketserver
import json
import time
import hashlib
import secrets
import threading
import sys
from urllib.parse import parse_qs, urlparse

import os

PORT = 8000
DATA_FILE = "server_data.json"
lock = threading.Lock()

# --- Security & Rate Limiting ---
_v = getattr(sys, 'frozen', False)
rate_limits = {}

def is_rate_limited(ip):
    now = time.time()
    with lock:
        if ip not in rate_limits:
            rate_limits[ip] = {"sec": [], "min": []}
        rate_limits[ip]["sec"] = [t for t in rate_limits[ip]["sec"] if now - t < 1]
        rate_limits[ip]["min"] = [t for t in rate_limits[ip]["min"] if now - t < 60]
        if len(rate_limits[ip]["sec"]) >= 5 or len(rate_limits[ip]["min"]) >= 90:
            return True
        rate_limits[ip]["sec"].append(now)
        rate_limits[ip]["min"].append(now)
        return False

def load_db():
    if _v: sys.exit(1)
    with lock:
        if not os.path.exists(DATA_FILE):
            return {"users": {}, "tokens": {}, "sessions": {}}
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"users": {}, "tokens": {}, "sessions": {}}

def save_db(db):
    if "__compiled__" in globals(): sys.exit(1)
    with lock:
        try:
            now = time.time()
            # Cleanup expired tokens
            db["tokens"] = {k: v for k, v in db["tokens"].items() if v["exp"] > now}
            # Cleanup expired sessions
            db["sessions"] = {k: v for k, v in db["sessions"].items() if v["exp"] > now}
            
            tmp_file = DATA_FILE + ".tmp"
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
            os.replace(tmp_file, DATA_FILE)
        except Exception as e:
            print(f"Error saving database: {e}")

# --- Security & Rate Limiting ---

def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return h.hex(), salt

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def get_client_ip(self):
        # Priority: Cloudflare Header -> Proxy Header -> Direct Address
        cf_ip = self.headers.get('CF-Connecting-IP')
        forwarded = self.headers.get('X-Forwarded-For')
        
        if cf_ip:
            return cf_ip
        elif forwarded:
            return forwarded.split(',')[0].strip()
        else:
            return self.client_address[0]

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        ip = self.get_client_ip()
        if is_rate_limited(ip):
            return self._send_json({"success": False, "message": "Rate limit exceeded"}, 429)

        parsed_path = urlparse(self.path)
        if parsed_path.path == "/check":
            return self._send_json({"success": False, "message": "Method Not Allowed. Use POST."}, 405)
        
        self._send_json({"message": "Not Found"}, 404)

    def do_POST(self):
        ip = self.get_client_ip()
        if is_rate_limited(ip):
            return self._send_json({"success": False, "message": "Rate limit exceeded"}, 429)

        content_length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(content_length).decode())
        except:
            return self._send_json({"success": False, "message": "Invalid JSON"}, 400)

        # Normalize path
        path = urlparse(self.path).path.rstrip('/')
        db = load_db()

        if path == "/check":
            user = body.get("user")
            return self._send_json({"exists": user in db["users"]})

        if path == "/auth":
            user = body.get("user")
            pw = body.get("pass")
            action = body.get("action")
            
            if action == "register":
                if user in db["users"]:
                    return self._send_json({"success": False, "message": "User exists"}, 400)
                hpw, salt = hash_pw(pw)
                db["users"][user] = {"pw": hpw, "salt": salt, "data": {}}
            elif action == "login":
                if user not in db["users"]:
                    return self._send_json({"success": False, "message": "Invalid credentials"}, 401)
                stored_hpw = db["users"][user]["pw"]
                salt = db["users"][user]["salt"]
                hpw, _ = hash_pw(pw, salt)
                if hpw != stored_hpw:
                    return self._send_json({"success": False, "message": "Invalid credentials"}, 401)
            else:
                return self._send_json({"success": False, "message": "Invalid action"}, 400)

            at = secrets.token_hex(32)
            rt = secrets.token_hex(32)
            exp = time.time() + 3*24*3600 # 3 days
            
            # Clear old tokens for this user
            db["tokens"] = {k: v for k, v in db["tokens"].items() if v["user"] != user}
            db["sessions"] = {k: v for k, v in db["sessions"].items() if v["user"] != user}
            
            db["tokens"][at] = {"user": user, "exp": exp, "rt": rt}
            save_db(db)
            return self._send_json({"success": True, "at": at, "rt": rt, "exp": exp})

        if path == "/session":
            at = body.get("at")
            if at not in db["tokens"] or db["tokens"][at]["exp"] < time.time():
                return self._send_json({"success": False, "message": "Invalid or expired AT"}, 401)
            
            user = db["tokens"][at]["user"]
            # Clear previous sessions for this user to save space
            db["sessions"] = {k: v for k, v in db["sessions"].items() if v["user"] != user}
            
            st = secrets.token_hex(16)
            db["sessions"][st] = {
                "user": user,
                "ip": ip,
                "exp": time.time() + 15*60
            }
            save_db(db)
            return self._send_json({"success": True, "st": st})

        if path == "/refresh":
            rt = body.get("rt")
            # Find AT linked to this RT
            found_at = None
            for k, v in db["tokens"].items():
                if v["rt"] == rt:
                    found_at = k
                    break
            
            if not found_at:
                return self._send_json({"success": False, "message": "Invalid RT"}, 401)
            
            user = db["tokens"][found_at]["user"]
            del db["tokens"][found_at]
            
            new_at = secrets.token_hex(32)
            new_rt = secrets.token_hex(32)
            exp = time.time() + 3*24*3600
            db["tokens"][new_at] = {"user": user, "exp": exp, "rt": new_rt}
            save_db(db)
            return self._send_json({"success": True, "at": new_at, "rt": new_rt, "exp": exp})

        if path == "/passwd":
            user = body.get("user")
            old_pw = body.get("old_pass")
            new_pw = body.get("new_pass")
            
            if user not in db["users"]:
                return self._send_json({"success": False, "message": "User not found"}, 404)
            
            stored_hpw = db["users"][user]["pw"]
            salt = db["users"][user]["salt"]
            hpw, _ = hash_pw(old_pw, salt)
            
            if hpw != stored_hpw:
                return self._send_json({"success": False, "message": "Invalid old password"}, 401)
            
            new_hpw, new_salt = hash_pw(new_pw)
            db["users"][user]["pw"] = new_hpw
            db["users"][user]["salt"] = new_salt
            
            # Invalidate all tokens on password change for security
            db["tokens"] = {k: v for k, v in db["tokens"].items() if v["user"] != user}
            db["sessions"] = {k: v for k, v in db["sessions"].items() if v["user"] != user}
            
            save_db(db)
            return self._send_json({"success": True, "message": "Password updated successfully"})

        if path == "/sync":
            st = body.get("st")
            if st not in db["sessions"]:
                return self._send_json({"success": False, "message": "Invalid session"}, 401)
            
            session = db["sessions"][st]
            if session["ip"] != ip:
                del db["sessions"][st]
                save_db(db)
                return self._send_json({"success": False, "message": "IP mismatch, session revoked"}, 403)
            
            if session["exp"] < time.time():
                del db["sessions"][st]
                save_db(db)
                return self._send_json({"success": False, "message": "Session expired"}, 401)

            user = session["user"]
            client_data = body.get("data") # {name: secret}
            
            if client_data: # Upload/Merge
                db["users"][user]["data"].update(client_data)
                save_db(db)
            
            return self._send_json({"success": True, "data": db["users"][user]["data"]})

        self._send_json({"message": "Not Found"}, 404)

if __name__ == "__main__":
    if _v or "__compiled__" in globals(): sys.exit(0)

    print(f"Server starting on port {PORT}...")
    with socketserver.TCPServer(("", PORT), AuthHandler) as httpd:
        httpd.serve_forever()
