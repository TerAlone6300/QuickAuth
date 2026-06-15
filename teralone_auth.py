#!/usr/bin/env python3
# teralone_auth.py
# Yêu cầu: Python 3.8+
# Giao diện TUI & Command Mode có màu, hỗ trợ phím mũi tên, multi-select và chuột.
# Không dùng thư viện ngoài, tự implement TOTP và TUI.

import time
import hmac
import hashlib
import struct
import json
import base64
import threading
import sys
import os
import select
import urllib.request
import urllib.parse
from pathlib import Path

# --- Terminal Styles ---
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    REVERSE = "\033[7m"
    
    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Shortcuts
    HEADER = f"{BOLD}{MAGENTA}"
    OK = f"{BOLD}{GREEN}"
    FAIL = f"{BOLD}{RED}"
    WARN = f"{BOLD}{YELLOW}"
    INFO = f"{BOLD}{CYAN}"
    HL = f"{REVERSE}{CYAN}" # Highlight for menu

# --- Environment Detection ---
IS_COMPILED = getattr(sys, 'frozen', False) or "__compiled__" in globals()

# --- Storage Logic ---
def get_storage_paths():
    if IS_COMPILED:
        base_dir = Path.home() / ".teralone_auth"
        try:
            base_dir.mkdir(parents=True, exist_ok=True)
            return base_dir / "auth.json", base_dir / "config.json", base_dir / "token.json"
        except Exception:
            return Path("auth.json"), Path("config.json"), Path("token.json")
    return Path("auth.json"), Path("auth.json"), Path("auth.json")

AUTH_FILE, CONFIG_FILE, TOKEN_FILE = get_storage_paths()
TIME_STEP = 30
DIGITS = 6
lock = threading.Lock()

def load_data(file_path):
    if not file_path.exists():
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_data(file_path, data):
    with lock:
        try:
            # Create file with 0600 permissions if it doesn't exist
            if not file_path.exists():
                file_path.touch(mode=0o600)
            else:
                os.chmod(file_path, 0o600)
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"{Style.FAIL}Error saving file: {e}{Style.RESET}")

def load_store():
    auth_data = load_data(AUTH_FILE)
    if AUTH_FILE == CONFIG_FILE:
        return auth_data
    
    config_data = load_data(CONFIG_FILE)
    # Merge for runtime use, but we'll need to keep track of what goes where
    full_store = auth_data.copy()
    full_store.update(config_data)
    return full_store

def save_store(store):
    if AUTH_FILE == CONFIG_FILE:
        save_data(AUTH_FILE, store)
        return

    # Split: config is keys starting with __, auth is others
    auth_data = {k: v for k, v in store.items() if not k.startswith("__")}
    config_data = {k: v for k, v in store.items() if k.startswith("__")}
    
    save_data(AUTH_FILE, auth_data)
    save_data(CONFIG_FILE, config_data)

# --- TOTP Logic ---
def normalize_base32(s: str) -> str:
    return "".join(s.upper().split()).replace("=", "")

def decode_secret(secret_str: str) -> bytes:
    s = secret_str.strip()
    try:
        cleaned = normalize_base32(s)
        pad = '=' * ((8 - len(cleaned) % 8) % 8)
        return base64.b32decode(cleaned + pad, casefold=True)
    except Exception:
        pass
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    return s.encode("utf-8")

def totp_code(secret_bytes: bytes, for_time: int = None, digits: int = DIGITS, step: int = TIME_STEP) -> (str, int):
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time // step)
    b = struct.pack(">Q", counter)
    hmac_hash = hmac.new(secret_bytes, b, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7FFFFFFF
    code = str(code_int % (10 ** digits)).zfill(digits)
    rem = step - (for_time % step)
    return code, rem

# --- Raw Terminal Input ---
class RawTerminal:
    def __enter__(self):
        import termios, tty
        self.fd = sys.stdin.fileno()
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        # Enable mouse reporting (SGR mode)
        sys.stdout.write("\033[?1000h\033[?1006h")
        sys.stdout.flush()
        return self

    def __exit__(self, type, value, traceback):
        import termios
        # Disable mouse reporting
        sys.stdout.write("\033[?1000l\033[?1006l")
        sys.stdout.flush()
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)

    def get_key(self):
        if not select.select([sys.stdin], [], [], 0.1)[0]:
            return None
        c = sys.stdin.read(1)
        if c == '\033':
            # Escape sequence
            c2 = sys.stdin.read(1)
            if c2 == '[':
                c3 = sys.stdin.read(1)
                if c3 == 'A': return "UP"
                elif c3 == 'B': return "DOWN"
                elif c3 == 'C': return "RIGHT"
                elif c3 == 'D': return "LEFT"
                elif c3 == '<': # Mouse SGR
                    # Read until 'm' or 'M'
                    mouse_data = ""
                    while True:
                        char = sys.stdin.read(1)
                        mouse_data += char
                        if char in ('m', 'M'): break
                    return ("MOUSE", mouse_data)
            return "ESC"
        elif c == '\r' or c == '\n': return "ENTER"
        elif c == ' ': return "SPACE"
        elif c == '\t': return "TAB"
        elif c == '\x03': return "CTRL_C"
        elif c == '\x7f': return "BACKSPACE"
        return c

def parse_mouse_sgr(data):
    # data format: "button;x;yM" or "button;x;ym"
    # button: 0=left click, 32=scroll up, 33=scroll down
    try:
        pressed = data.endswith('M')
        parts = data[:-1].split(';')
        btn = int(parts[0])
        x = int(parts[1])
        y = int(parts[2])
        return btn, x, y, pressed
    except:
        return None

# --- TUI Menu System ---
class TUI:
    @staticmethod
    def banner():
        env_type = "Native" if IS_COMPILED else "Python VM"
        print(f" {Style.HEADER}✨ TerAlone's Auth ✨{Style.RESET}", end="\r\n")
        print(f" {Style.DIM}---------------------{Style.RESET}", end="\r\n")
        print(f" Environment: {Style.INFO}{env_type}{Style.RESET}", end="\r\n")

    @staticmethod
    def clear():
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()

    @staticmethod
    def get_input(prompt, password=False):
        current = ""
        with RawTerminal() as rt:
            while True:
                sys.stdout.write(f"\r\x1b[K {prompt} ")
                if password:
                    sys.stdout.write("*" * len(current))
                else:
                    sys.stdout.write(current)
                sys.stdout.flush()
                
                key = rt.get_key()
                if key == "ENTER":
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return current
                elif key == "BACKSPACE":
                    current = current[:-1]
                elif key == "CTRL_C":
                    sys.stdout.write("\r\n")
                    raise KeyboardInterrupt
                elif isinstance(key, str) and len(key) == 1:
                    current += key

    @staticmethod
    def smart_input(prompt_char, commands_dict, history=None):
        # commands_dict is {cmd: [args...]}
        if history is None: history = []
        current = ""
        suggestion_idx = 0
        history_idx = len(history)
        with RawTerminal() as rt:
            while True:
                # 1. Suggestions logic
                suggestions = []
                if current:
                    parts = current.split()
                    if " " not in current:
                        # Typing the command
                        suggestions = [c for c in commands_dict.keys() if c.startswith(current.lower())]
                    else:
                        # Typing arguments
                        cmd = parts[0].lower()
                        if cmd in commands_dict:
                            if current.endswith(" "):
                                suggestions = commands_dict[cmd]
                            else:
                                last_part = parts[-1].lower()
                                suggestions = [a for a in commands_dict[cmd] if a.startswith(last_part)]
                
                if suggestion_idx >= len(suggestions): suggestion_idx = 0
                
                parts_for_render = current.split()
                cmd_word = parts_for_render[0].lower() if parts_for_render else ""

                # 2. Render Input Line
                sys.stdout.write(f"\r\x1b[K {Style.BOLD}{prompt_char}{Style.RESET} ")
                if not cmd_word:
                    sys.stdout.write(current)
                elif cmd_word in commands_dict:
                    sys.stdout.write(f"{Style.OK}{cmd_word}{Style.RESET}{current[len(cmd_word):]}")
                else:
                    sys.stdout.write(f"{Style.FAIL}{current}{Style.RESET}")
                
                # 3. Draw suggestions line below
                sys.stdout.write("\n\x1b[K")
                if suggestions:
                    s_line = "   "
                    for i, s in enumerate(suggestions):
                        if i == suggestion_idx:
                            s_line += f"{Style.HL} {s} {Style.RESET} "
                        else:
                            s_line += f"{Style.DIM}{s}{Style.RESET} "
                    sys.stdout.write(s_line)
                
                # 4. Restore cursor to input line
                sys.stdout.write(f"\x1b[A\r\x1b[{3 + len(current)}C")
                sys.stdout.flush()

                key = rt.get_key()
                if key == "ENTER":
                    sys.stdout.write("\r\n\x1b[K\r\n")
                    sys.stdout.flush()
                    return current
                elif key == "BACKSPACE":
                    current = current[:-1]
                    suggestion_idx = 0
                    history_idx = len(history)
                elif key == "TAB":
                    if suggestions:
                        if " " not in current:
                            current = suggestions[suggestion_idx] + " "
                        else:
                            p = current.rsplit(" ", 1)
                            current = p[0] + " " + suggestions[suggestion_idx] + " "
                        suggestion_idx = 0
                elif key == "DOWN":
                    if suggestions:
                        suggestion_idx = (suggestion_idx + 1) % len(suggestions)
                    elif history and history_idx < len(history) - 1:
                        history_idx += 1
                        current = history[history_idx]
                    elif history_idx == len(history) - 1:
                        history_idx = len(history)
                        current = ""
                elif key == "UP":
                    if suggestions:
                        suggestion_idx = (suggestion_idx - 1) % len(suggestions)
                    elif history and history_idx > 0:
                        history_idx -= 1
                        current = history[history_idx]
                elif key == "RIGHT":
                    if suggestions: suggestion_idx = (suggestion_idx + 1) % len(suggestions)
                elif key == "LEFT":
                    if suggestions: suggestion_idx = (suggestion_idx - 1) % len(suggestions)
                elif isinstance(key, str) and len(key) == 1:
                    current += key
                    suggestion_idx = 0
                    history_idx = len(history)
                elif key == "CTRL_C":
                    sys.stdout.write("\n\x1b[K\n")
                    raise KeyboardInterrupt
                elif key == "SPACE":
                    current += " "
                    suggestion_idx = 0

    @staticmethod
    def menu(options, title="Menu", multi=False):
        selected_idx = 0
        multi_selected = set()
        
        with RawTerminal() as rt:
            while True:
                TUI.clear()
                TUI.banner()
                print(f" {Style.INFO}{title}:{Style.RESET}", end="\r\n")
                print(f" {Style.DIM}(Arrows: move, Space: select, Enter: confirm, ESC: back){Style.RESET}", end="\r\n")
                print(end="\r\n")
                
                for i, opt in enumerate(options):
                    prefix = ""
                    if multi:
                        prefix = "[x] " if i in multi_selected else "[ ] "
                    
                    if i == selected_idx:
                        print(f" {Style.HL}> {prefix}{opt} {Style.RESET}", end="\r\n")
                    else:
                        print(f"   {prefix}{opt}", end="\r\n")
                
                key = rt.get_key()
                if key == "UP":
                    selected_idx = (selected_idx - 1) % len(options)
                elif key == "DOWN":
                    selected_idx = (selected_idx + 1) % len(options)
                elif key == "SPACE" and multi:
                    if selected_idx in multi_selected:
                        multi_selected.remove(selected_idx)
                    else:
                        multi_selected.add(selected_idx)
                elif key == "ENTER":
                    if multi:
                        return list(multi_selected) if multi_selected else [selected_idx]
                    return selected_idx
                elif key == "ESC" or key == "q":
                    return None
                elif isinstance(key, tuple) and key[0] == "MOUSE":
                    m = parse_mouse_sgr(key[1])
                    if m and m[3]: # Pressed
                        # Lines offset: banner(3) + title(1) + instr(1) + blank(1) = 6 lines.
                        # Option 0 is on line 7.
                        click_y = m[2] - 7
                        if 0 <= click_y < len(options):
                            selected_idx = click_y
                            if multi:
                                if selected_idx in multi_selected: multi_selected.remove(selected_idx)
                                else: multi_selected.add(selected_idx)
                            else:
                                return selected_idx

# --- Sync Logic ---
def sync_request(url, endpoint, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(f"{url.rstrip('/')}/{endpoint}", data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as f:
            return json.loads(f.read().decode('utf-8'))
    except Exception as e:
        return {"success": False, "message": str(e)}

def refresh_session(store):
    tokens = load_data(TOKEN_FILE)
    at = tokens.get("at")
    rt = tokens.get("rt")
    url = store.get("__sync_url__")
    
    if not at or not url: return None

    # 1. Try get Session Token
    res = sync_request(url, "session", {"at": at})
    if res.get("success"):
        tokens["st"] = res["st"]
        save_data(TOKEN_FILE, tokens)
        return res["st"]
    
    # 2. If AT expired, try refresh AT
    res = sync_request(url, "refresh", {"rt": rt})
    if res.get("success"):
        tokens["at"] = res["at"]
        tokens["rt"] = res["rt"]
        save_data(TOKEN_FILE, tokens)
        # Try session again
        res = sync_request(url, "session", {"at": res["at"]})
        if res.get("success"):
            tokens["st"] = res["st"]
            save_data(TOKEN_FILE, tokens)
            return res["st"]
    
    return None

def perform_sync(store, force=False):
    if not store.get("__sync_enabled__"): return store
    
    st = refresh_session(store)
    if not st:
        print(f" {Style.FAIL}Sync failed: Session expired or invalid. Please re-setup sync.{Style.RESET}")
        return store
    
    url = store.get("__sync_url__")
    # Prepare data to upload (only accounts, no config)
    accounts = {k: v for k, v in store.items() if not k.startswith("__")}
    
    # On force/initial setup, we definitely send current local accounts to server
    res = sync_request(url, "sync", {"st": st, "data": accounts})
    if res.get("success"):
        # Merge downloaded data into local store
        if res.get("data"):
            # Update local with server data (server takes precedence for existing keys, 
            # but local new keys are already on server now)
            store.update(res["data"])
            save_store(store)
            print(f" {Style.OK}Sync completed! ({len(res['data'])} accounts total){Style.RESET}")
        return store
    else:
        print(f" {Style.FAIL}Sync error: {res.get('message')}{Style.RESET}")
        return store

def check_user_exists(url, user):
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/check?user={urllib.parse.quote(user)}", timeout=5) as f:
            resp = json.loads(f.read().decode('utf-8'))
            return resp.get("exists", False)
    except:
        return False

def setup_sync(store):
    if store.get("__sync_enabled__") is not None:
        return perform_sync(store) # Sync once on startup
    
    while True:
        TUI.clear()
        TUI.banner()
        choice = TUI.menu(["Yes (Enable Sync)", "No (Local Only)"], "Enable Code Sync?")
        if choice == 1 or choice is None:
            store["__sync_enabled__"] = False
            save_store(store)
            return store
        
        url = TUI.get_input(f"{Style.INFO}Server URL (http/https):{Style.RESET}").strip()
        if not url: continue
        if not url.startswith(("http://", "https://")):
            print(f" {Style.FAIL}URL must start with http:// or https://{Style.RESET}")
            time.sleep(1)
            continue
        
        if url.startswith("http://"):
            print(f" {Style.FAIL}⚠️ WARNING: YOU ARE USING INSECURE HTTP!{Style.RESET}")
            print(f" {Style.FAIL}Passwords and TOTP secrets can be intercepted.{Style.RESET}")
            conf = TUI.get_input(f" {Style.WARN}Proceed anyway? (y/N):{Style.RESET}").lower()
            if conf != 'y': continue
        
        user = TUI.get_input(f"{Style.INFO}Username:{Style.RESET}").strip()
        if not user: continue
        
        exists = check_user_exists(url, user)
        if exists:
            pwd = TUI.get_input(f"{Style.INFO}Password:{Style.RESET}", password=True)
            res = sync_request(url, "auth", {"user": user, "pass": pwd, "action": "login"})
        else:
            print(f" {Style.WARN}User not found. Creating new account...{Style.RESET}")
            pwd = TUI.get_input(f"{Style.INFO}Create a new password:{Style.RESET}", password=True)
            pwd_conf = TUI.get_input(f"{Style.INFO}Submit your password:{Style.RESET}", password=True)
            if pwd != pwd_conf:
                print(f" {Style.FAIL}Passwords do not match!{Style.RESET}")
                time.sleep(2)
                continue
            res = sync_request(url, "auth", {"user": user, "pass": pwd, "action": "register"})
            
        if res.get("success"):
            store["__sync_enabled__"] = True
            store["__sync_url__"] = url
            store["__sync_user__"] = user
            save_store(store)
            
            # Save tokens
            save_data(TOKEN_FILE, {"at": res["at"], "rt": res["rt"]})
            
            print(f" {Style.OK}Sync configured successfully!{Style.RESET}")
            time.sleep(1)
            return perform_sync(store)
        else:
            print(f" {Style.FAIL}Error: {res.get('message')}{Style.RESET}")
            time.sleep(2)

# --- Logic Actions ---
def show_live_otps(store, keys):
    if not keys: return
    stop_event = threading.Event()
    def wait_input():
        with RawTerminal(): # temporarily enter raw to catch any key
            sys.stdin.read(1)
            stop_event.set()
    
    t = threading.Thread(target=wait_input, daemon=True)
    t.start()
    
    try:
        while not stop_event.is_set():
            TUI.clear()
            TUI.banner()
            print(f"{Style.INFO}🔑 Live codes (Press any key to stop):{Style.RESET}", end="\r\n")
            print(end="\r\n")
            
            now = int(time.time())
            min_rem = TIME_STEP
            for k in keys:
                secret = store[k]
                try:
                    code, rem = totp_code(decode_secret(secret), now)
                    min_rem = min(min_rem, rem)
                    print(f" {Style.BOLD}{k:15}{Style.RESET}: {Style.OK}{code}{Style.RESET} ({rem}s)", end="\r\n")
                except:
                    print(f" {k:15}: {Style.FAIL}Error{Style.RESET}", end="\r\n")
            
            # Progress bar
            bar_len = 20
            filled = int((min_rem / TIME_STEP) * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)
            sys.stdout.write(f"\r\n [{bar}] Refresh in {min_rem}s\r")
            sys.stdout.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass

# --- Command Mode Actions ---
def cmd_imp(args, store, tui=False):
    once = ("--once" in args)
    if once:
        if tui:
            TUI.clear()
            TUI.banner()
        secret = TUI.get_input(f"{Style.INFO}Secret Key>{Style.RESET}").strip()
        if not secret: return store
        try:
            secret_bytes = decode_secret(secret)
            code, rem = totp_code(secret_bytes)
            print(f" {Style.OK}OTP Code: {code}{Style.RESET} (expires in {rem}s)")
            if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        except Exception as e:
            print(f" {Style.FAIL}Error: {e}{Style.RESET}")
            if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return store

    if tui:
        TUI.clear()
        TUI.banner()
    secret = TUI.get_input(f"{Style.INFO}Secret Key>{Style.RESET}").strip()
    name = TUI.get_input(f"{Style.INFO}Name/Account>{Style.RESET}").strip()
    if not name:
        print(f" {Style.FAIL}Name cannot be empty.{Style.RESET}")
        if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        return store
    store[name] = secret
    save_store(store)
    print(f" {Style.OK}Saved `{name}` successfully! ✨{Style.RESET}")
    if tui: TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
    return store

def cmd_key(args, store):
    if not args:
        print(f" {Style.WARN}Usage: key <all | name> [--loop]{Style.RESET}")
        return
    target = args[0]
    loop = "--loop" in args
    names = sorted([k for k in store.keys() if not k.startswith("__")]) if target == "all" else ([target] if target in store and not target.startswith("__") else [])
    
    if not names:
        print(f" {Style.FAIL}No keys found.{Style.RESET}")
        return

    if loop:
        show_live_otps(store, names)
    else:
        now = int(time.time())
        for n in names:
            code, rem = totp_code(decode_secret(store[n]), now)
            print(f" {Style.BOLD}{n:15}{Style.RESET}: {Style.OK}{code}{Style.RESET} ({rem}s)")

# --- Main Loops ---
def run_command_mode(store):
    TUI.clear()
    TUI.banner()
    history = []
    print(f" {Style.HEADER}--- Command mode ---{Style.RESET}")
    print(f" {Style.DIM}Type 'help' for commands, 'exit' to quit.{Style.RESET}")
    while True:
        try:
            # Metadata for suggestions
            cmds = {
                "imp": ["--once"],
                "key": ["all", "--loop"] + sorted([k for k in store.keys() if not k.startswith("__")]),
                "resync": [],
                "mchange": [],
                "help": [],
                "exit": [],
                "quit": []
            }
            raw = TUI.smart_input(">", cmds, history).strip()
            if not raw: continue
            if not history or history[-1] != raw:
                history.append(raw)
            parts = raw.split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd in ("exit", "quit"):
                print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
                sys.exit(0)
            elif cmd == "resync":
                store = perform_sync(store)
            elif cmd == "mchange":
                store["__mode__"] = '2'
                save_store(store)
                print(f" {Style.INFO}Mode changed to TUI. Restarting...{Style.RESET}")
                return store, True # True means mode changed
            elif cmd == "imp": store = cmd_imp(args, store)
            elif cmd == "key": cmd_key(args, store)
            elif cmd == "help":
                print(f"""
 {Style.INFO}Commands:{Style.RESET}
  imp            -> Import and save a key
  imp --once     -> Quick OTP (don't save)
  key all        -> Show all codes
  key <name>     -> Show code for a specific key
  key ... --loop -> Live updating codes
  resync         -> Synchronize data with server
  mchange        -> Switch to TUI mode
  exit           -> Quit application
""")
            else: print(f" {Style.WARN}Unknown command. Type 'help'.{Style.RESET}")
        except KeyboardInterrupt:
            print()
            sys.exit(0)
    return store, False

def run_tui_mode(store):
    while True:
        options = ["Show live codes", "Import new key", "Quick OTP (Once)", "Resync", "Mode Change", "Exit"]
        choice = TUI.menu(options, "Main Menu")
        
        if choice == 0: # Show keys
            keys = sorted([k for k in store.keys() if not k.startswith("__")])
            if not keys:
                TUI.clear()
                TUI.banner()
                TUI.get_input(f"{Style.WARN}No keys found. Press Enter...{Style.RESET}")
                continue
            sel_indices = TUI.menu(keys, "Select keys (Space to multi-select)", multi=True)
            if sel_indices is not None:
                selected_keys = [keys[i] for i in sel_indices]
                show_live_otps(store, selected_keys)
        elif choice == 1: # Import
            store = cmd_imp([], store, tui=True)
        elif choice == 2: # Once
            store = cmd_imp(["--once"], store, tui=True)
        elif choice == 3: # Resync
            store = perform_sync(store)
            TUI.get_input(f"{Style.DIM}Press Enter to continue...{Style.RESET}")
        elif choice == 4: # Mode change
            store["__mode__"] = '1'
            save_store(store)
            return store, True
        elif choice == 5 or choice is None:
            TUI.clear()
            TUI.banner()
            print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
            sys.exit(0)
    return store, False

def main():
    store = load_store()
    store = setup_sync(store)
    mode = store.get("__mode__")
    
    while True:
        if mode == '1':
            store, changed = run_command_mode(store)
            if changed: 
                mode = store.get("__mode__")
                continue
        elif mode == '2':
            store, changed = run_tui_mode(store)
            if changed:
                mode = store.get("__mode__")
                continue
        else:
            TUI.clear()
            TUI.banner()
            print(f" {Style.BOLD}Select mode:{Style.RESET}")
            print(f"  {Style.OK}[1]{Style.RESET} Command mode")
            print(f"  {Style.OK}[2]{Style.RESET} TUI mode")
            print(f"  {Style.FAIL}[0]{Style.RESET} Exit")
            
            try:
                choice = input(f"\n {Style.INFO}Choice> {Style.RESET}").strip()
            except KeyboardInterrupt:
                choice = '0'
            
            if choice == '1':
                store["__mode__"] = '1'
                save_store(store)
                mode = '1'
            elif choice == '2':
                store["__mode__"] = '2'
                save_store(store)
                mode = '2'
            elif choice == '0' or choice.lower() == 'exit':
                print(f" {Style.OK}Goodbye! 👋{Style.RESET}")
                break
            else:
                print(f" {Style.WARN}Invalid choice.{Style.RESET}")
                time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Style.OK}Bye!{Style.RESET}")
        sys.exit(0)
