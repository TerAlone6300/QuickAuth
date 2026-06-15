import http.server
import socketserver
import json
import time
import hashlib
import secrets
import threading
import sys
from urllib.parse import parse_qs, urlparse

PORT = 8000
DATA_FILE = "server_data.json"
lock = threading.Lock()

# Rate limiting: {ip: {"sec": [timestamps], "min": [timestamps]}}
rate_limits = {}

def is_rate_limited(ip):
    now = time.time()
    with lock:
        if ip not in rate_limits:
            rate_limits[ip] = {"sec": [], "min": []}
        
        # Cleanup
        rate_limits[ip]["sec"] = [t for t in rate_limits[ip]["sec"] if now - t < 1]
        rate_limits[ip]["min"] = [t for t in rate_limits[ip]["min"] if now - t < 60]
        
        if len(rate_limits[ip]["sec"]) >= 5 or len(rate_limits[ip]["min"]) >= 90:
            return True
        
        rate_limits[ip]["sec"].append(now)
        rate_limits[ip]["min"].append(now)
        return False

def load_db():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"users": {}, "tokens": {}, "sessions": {}}

def save_db(db):
    with open(DATA_FILE, "w") as f:
        json.dump(db, f, indent=2)

def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000)
    return h.hex(), salt

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        ip = self.client_address[0]
        if is_rate_limited(ip):
            return self._send_json({"success": False, "message": "Rate limit exceeded"}, 429)

        parsed_path = urlparse(self.path)
        if parsed_path.path == "/check":
            query = parse_qs(parsed_path.query)
            user = query.get("user", [None])[0]
            db = load_db()
            return self._send_json({"exists": user in db["users"]})
        
        self._send_json({"message": "Not Found"}, 404)

    def do_POST(self):
        ip = self.client_address[0]
        if is_rate_limited(ip):
            return self._send_json({"success": False, "message": "Rate limit exceeded"}, 429)

        content_length = int(self.headers.get('Content-Length', 0))
        try:
            body = json.loads(self.rfile.read(content_length).decode())
        except:
            return self._send_json({"success": False, "message": "Invalid JSON"}, 400)

        path = self.path.rstrip('/')
        db = load_db()

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
            # AT expires in 3 days, RT doesn't expire in this simple impl
            db["tokens"][at] = {"user": user, "exp": time.time() + 3*24*3600, "rt": rt}
            save_db(db)
            return self._send_json({"success": True, "at": at, "rt": rt})

        if path == "/session":
            at = body.get("at")
            if at not in db["tokens"] or db["tokens"][at]["exp"] < time.time():
                return self._send_json({"success": False, "message": "Invalid or expired AT"}, 401)
            
            st = secrets.token_hex(16)
            db["sessions"][st] = {
                "user": db["tokens"][at]["user"],
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
            db["tokens"][new_at] = {"user": user, "exp": time.time() + 3*24*3600, "rt": new_rt}
            save_db(db)
            return self._send_json({"success": True, "at": new_at, "rt": new_rt})

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
    # Prevent running if compiled/frozen
    if getattr(sys, 'frozen', False) or "__compiled__" in globals():
        print("Error: Server cannot be run as a compiled binary for security/transparency reasons.")
        print("Please run using a standard Python interpreter.")
        sys.exit(1)

    print(f"Server starting on port {PORT}...")
    with socketserver.TCPServer(("", PORT), AuthHandler) as httpd:
        httpd.serve_forever()
