import os, sys, time, json, re, uuid, hashlib, threading, signal
from datetime import datetime, timezone
from queue import Queue, Empty
from tkinter import (
    Tk, Frame, Label, Button, Text, Scrollbar, Entry, StringVar, END,
    messagebox, Checkbutton, IntVar, OptionMenu
)

import requests, psutil, pyautogui
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

import cloudinary, cloudinary.uploader
from pynput import keyboard, mouse
import win32gui, win32process
from PIL import Image

try:
    import mss
    MSS_OK = True
except Exception:
    MSS_OK = False

# ================== CONFIG ==================
APP_NAME = "Discovery Agent Logger"
WIN_W, WIN_H = 920, 640

MONGO_URI = "mongodb+srv://rm2022:RM2022btcs044@rm-powershell.v4vpfx3.mongodb.net/?retryWrites=true&w=majority"
DB_NAME = "Discovery_Agent"

# ✅ 4 collections (all keyed by mac_id)
COL_USERS = "users"               # _id = mac_id, full user profile
COL_LOGS = "logs"                 # _id = mac_id, activity logs by day
COL_SCREENSHOTS = "screenshots"   # _id = mac_id, screenshots by day
COL_DEPARTMENTS = "departments"   # _id = mac_id, department/role mapping (device-centric)

cloudinary.config(
    cloud_name="dswbji5qx",
    api_key="995579526978951",
    api_secret="yuqNEpBHaDnMvW1E8n3n2t_phqk"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_persist_dir():
    # Windows stable location: %APPDATA%\HealthplansAI\Logger
    appdata = os.getenv("APPDATA")
    if appdata:
        return os.path.join(appdata, "HealthplansAI", "Logger")
    # Fallback (non-Windows): ~/.healthplansai/logger
    return os.path.join(os.path.expanduser("~"), ".healthplansai", "logger")

PERSIST_DIR = get_persist_dir()
os.makedirs(PERSIST_DIR, exist_ok=True)

IDENTITY_FILE = os.path.join(PERSIST_DIR, "agent_identity.json")

SHOT_DIR = os.path.join(BASE_DIR, "Screenshots")
os.makedirs(SHOT_DIR, exist_ok=True)

# Local durability spool (lossless across restarts)
SPOOL_FILE = os.path.join(BASE_DIR, "agent_spool.ndjson")
SPOOL_OFFSET_FILE = os.path.join(BASE_DIR, "agent_spool.offset")

ROLE_OPTIONS = ["C_SUITE", "DEPARTMENT_HEAD", "DEPARTMENT_MEMBER"]
DEPT_OPTIONS = ["IT", "Testing", "Finance", "Claims", "HR"]

# Screenshots
SCREENSHOT_MIN_INTERVAL = 60
SHOT_MAX_WIDTH = 1280
JPEG_QUALITY = 55  # JPEG (smaller footprint)

# Sync tuning (optimized to reduce DB operations)
DB_FLUSH_SECONDS = 7.0
ACTIVITY_BATCH_MAX = 200
SCREENSHOT_BATCH_MAX = 30

# Typed capture: sentence-aware, masked, reliability-first
FLUSH_IDLE_SECONDS = 1.5
MAX_BUFFER_CHARS = 240
SENTENCE_END_CHARS = set([".", "!", "?", "\n"])
SOFT_FLUSH_CHARS = set([" ", "\t", ",", ";", ":"])

# Hard daily caps (archives to avoid unbounded docs)
MAX_EVENTS_PER_DAY = 3500
MAX_SS_PER_DAY = 700

LICENSE_VERSION = "1.3"
LICENSE_TEXT = f"""DISCOVERY AGENT PLUGIN LICENSE AGREEMENT (v{LICENSE_VERSION})

IMPORTANT — READ CAREFULLY

This software collects:
- Active application/window titles
- Mouse click events
- Periodic screenshots (uploaded to secure storage)
- Aggregated typed activity as masked “chunks” (NOT per-keystroke)

By clicking “I Accept”, you acknowledge that:
1) You have authorization from your organization to install and run this plugin.
2) You understand the plugin collects telemetry for monitoring and analytics.
3) Data may be transmitted to servers controlled by your organization.
4) You must comply with applicable laws and internal company policies.
5) You are responsible for safeguarding company credentials.

DISCLAIMER
The plugin is provided “AS IS” without warranty of any kind.
If you do not agree, click “Decline” and installation will not proceed.
"""


# ================== HELPERS ==================
PC_USERNAME = os.getlogin()

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def day_key():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def normalize_email(s: str) -> str:
    return (s or "").strip().lower()

def mac_id():
    try:
        node = uuid.getnode()
        mac = ":".join([f"{(node >> e) & 0xff:02x}" for e in range(40, -1, -8)])
        return mac.upper().replace(":", "-")
    except:
        raw = (os.getenv("COMPUTERNAME", "UNK") + "|" + PC_USERNAME).encode()
        return hashlib.sha256(raw).hexdigest()[:24].upper()


def load_identity():
    if os.path.exists(IDENTITY_FILE):
        try:
            with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {}


def save_identity(obj):
    os.makedirs(os.path.dirname(IDENTITY_FILE), exist_ok=True)
    with open(IDENTITY_FILE, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)



def get_or_create_device_id():
    """Create a stable device_id once and persist it."""
    ident = load_identity()
    did = ident.get("device_id")
    if did:
        return did

    seed = (
        os.getenv("COMPUTERNAME", "UNK")
        + "|"
        + PC_USERNAME
        + "|"
        + str(uuid.uuid4())
    ).encode()

    did = hashlib.sha256(seed).hexdigest()[:32].upper()
    ident["device_id"] = did
    save_identity(ident)
    return did


USER_MAC_ID = get_or_create_device_id()




SENSITIVE_PATTERNS = [
    r"\b\d{4,8}\b",                     # OTP / PIN
    r"\b\d{12,16}\b",                   # Card numbers
    r"\bCVV\b|\bCVC\b",                 # CVV keyword
    r"\bPIN\b",                         # PIN keyword
    r"\bOTP\b",                         # OTP keyword
    r"password\s*[:=]",                 # password=
    r"passcode\s*[:=]",
    r"secret\s*[:=]",
]

def contains_sensitive(text: str) -> bool:
    for p in SENSITIVE_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def smart_mask(text: str) -> dict:
    """
    Returns safe/plain text if not sensitive,
    else masked version.
    """
    if contains_sensitive(text):
        return {
            "text": re.sub(r"[A-Za-z0-9]", "*", text),
            "masked": True
        }
    else:
        return {
            "text": text,
            "masked": False
        }






DEBUG_LOG_FILE = os.path.join(BASE_DIR, "sync_debug.log")

def _debug_log(msg: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}")
    except:
        pass
class OnlineCache:
    def __init__(self):
        self.t = 0
        self.val = False

    def ok(self):
        # Cache result for a few seconds to avoid spamming checks
        if time.time() - self.t < 5:
            return self.val
        self.t = time.time()

        # Prefer checking MongoDB reachability (more relevant than Google in many networks)
        try:
            from pymongo import MongoClient as _MC
            _c = _MC(
                MONGO_URI,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000,
                socketTimeoutMS=2000
            )
            _c.admin.command("ping")
            self.val = True
            return self.val
        except Exception as e:
            _debug_log(f"Online check Mongo ping failed: {e!r}")

        # Fallback: general internet check
        try:
            requests.get("https://www.google.com", timeout=2)
            self.val = True
        except Exception as e:
            self.val = False
            _debug_log(f"Online check Google failed: {e!r}")
        return self.val

online = OnlineCache()

def active_window():
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            return psutil.Process(pid).name(), win32gui.GetWindowText(hwnd)
    except:
        pass
    return "", ""

# ================== MONGO ==================
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

users = db[COL_USERS]
logs = db[COL_LOGS]
screenshots = db[COL_SCREENSHOTS]
departments = db[COL_DEPARTMENTS]

IDENTITY = load_identity()

# --- Reconcile user identity with unique company_username_norm index ---
# If a user already exists for this email, reuse that document's _id so we don't violate the unique index.
try:
    _email_norm = normalize_email((IDENTITY or {}).get("company_username"))
    if _email_norm:
        _existing = users.find_one({"company_username_norm": _email_norm}, {"_id": 1})
        if _existing and _existing.get("_id") and _existing.get("_id") != USER_MAC_ID:
            USER_MAC_ID = _existing["_id"]
            IDENTITY["device_id"] = USER_MAC_ID
            IDENTITY["user_mac_id"] = USER_MAC_ID  # backward-compat
            save_identity(IDENTITY)
            _debug_log(f"Reused existing user _id for email {_email_norm}: {USER_MAC_ID}")
except Exception as e:
    _debug_log(f"Identity reconcile failed: {e!r}")

stop_flag = False

# ================== SPOOL (DURABLE QUEUE) ==================
_spool_lock = threading.Lock()

def _load_spool_offset() -> int:
    try:
        with open(SPOOL_OFFSET_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip() or "0")
    except:
        return 0

def _save_spool_offset(off: int):
    try:
        with open(SPOOL_OFFSET_FILE, "w", encoding="utf-8") as f:
            f.write(str(int(off)))
    except:
        pass

def spool_append(kind: str, payload: dict):
    """
    Append an event to durable spool (lossless across crash/restart).
    Writes one JSON object per line.
    """
    try:
        rec = {"kind": kind, "payload": payload}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with _spool_lock:
            with open(SPOOL_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except:
        # Even if spool fails, we must not crash the agent.
        pass

def spool_read_batch(offset: int, max_items: int):
    """
    Returns (items, new_offset). Items are decoded dicts with keys kind/payload.
    """
    items = []
    new_offset = offset
    if not os.path.exists(SPOOL_FILE):
        return items, offset

    try:
        with _spool_lock:
            with open(SPOOL_FILE, "r", encoding="utf-8") as f:
                f.seek(offset)
                while len(items) < max_items:
                    pos = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and "kind" in obj and "payload" in obj:
                            items.append(obj)
                            new_offset = f.tell()
                        else:
                            # skip malformed line
                            new_offset = f.tell()
                    except:
                        # skip malformed line
                        new_offset = f.tell()
    except:
        return [], offset

    return items, new_offset

def spool_compact_if_needed(offset: int):
    """
    If offset is large, rewrite remaining lines to keep file small.
    """
    try:
        if not os.path.exists(SPOOL_FILE):
            return
        size = os.path.getsize(SPOOL_FILE)
        # compact when processed > 1MB and at least 50% of file
        if offset < 1_000_000:
            return
        if offset < size * 0.5:
            return
        with _spool_lock:
            with open(SPOOL_FILE, "r", encoding="utf-8") as src:
                src.seek(offset)
                rest = src.read()
            tmp = SPOOL_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as dst:
                dst.write(rest)
            os.replace(tmp, SPOOL_FILE)
        _save_spool_offset(0)
    except:
        pass

# ================== DOC HELPERS ==================

def ensure_user_doc():
    """
    users collection. Upsert by company_username_norm to avoid DuplicateKeyError.
    """
    global USER_MAC_ID, IDENTITY

    email_norm = normalize_email(IDENTITY.get("company_username"))

    # If email is available, always anchor the user doc by company_username_norm
    if email_norm:
        # If a user already exists for this email, reuse that _id everywhere (critical!)
        try:
            existing = users.find_one({"company_username_norm": email_norm}, {"_id": 1})
            if existing and existing.get("_id") and existing["_id"] != USER_MAC_ID:
                USER_MAC_ID = existing["_id"]
                IDENTITY["device_id"] = USER_MAC_ID
                IDENTITY["user_mac_id"] = USER_MAC_ID  # backward-compat
                save_identity(IDENTITY)
        except Exception as e:
            _debug_log(f"ensure_user_doc lookup failed: {e!r}")

        set_doc = {
            "user_mac_id": USER_MAC_ID,
            "pc_username": PC_USERNAME,
            "company_username_norm": email_norm,
            "company_username": email_norm,
            "full_name": IDENTITY.get("full_name") or None,
            "role_key": IDENTITY.get("role_key") or None,
            "department": IDENTITY.get("department") if IDENTITY.get("role_key") != "C_SUITE" else None,
            "license_accepted": bool(IDENTITY.get("license_accepted", False)),
            "license_version": IDENTITY.get("license_version"),
            "license_accepted_at": IDENTITY.get("license_accepted_at"),
            "last_seen_at": now_iso(),
        }

        users.update_one(
            {"company_username_norm": email_norm},
            {
                "$set": set_doc,
                "$setOnInsert": {
                    "_id": USER_MAC_ID,
                    "created_at": now_iso()
                }
            },
            upsert=True
        )
        return

    # If email is not available yet, fall back to device _id upsert
    set_doc = {
        "user_mac_id": USER_MAC_ID,
        "pc_username": PC_USERNAME,
        "company_username_norm": None,
        "company_username": None,
        "full_name": IDENTITY.get("full_name") or None,
        "role_key": IDENTITY.get("role_key") or None,
        "department": IDENTITY.get("department") if IDENTITY.get("role_key") != "C_SUITE" else None,
        "license_accepted": bool(IDENTITY.get("license_accepted", False)),
        "license_version": IDENTITY.get("license_version"),
        "license_accepted_at": IDENTITY.get("license_accepted_at"),
        "last_seen_at": now_iso(),
    }

    users.update_one(
        {"_id": USER_MAC_ID},
        {"$set": set_doc, "$setOnInsert": {"created_at": now_iso()}},
        upsert=True
    )

def ensure_logs_doc():
    logs.update_one(
        {"_id": USER_MAC_ID},
        {"$setOnInsert": {"_id": USER_MAC_ID, "user_mac_id": USER_MAC_ID, "created_at": now_iso(), "logs": {}},
         "$set": {"updated_at": now_iso()}},
        upsert=True
    )

def ensure_screenshots_doc():
    screenshots.update_one(
        {"_id": USER_MAC_ID},
        {"$setOnInsert": {"_id": USER_MAC_ID, "user_mac_id": USER_MAC_ID, "created_at": now_iso(), "screenshots": {}},
         "$set": {"updated_at": now_iso()}},
        upsert=True
    )

def ensure_departments_doc():
    departments.update_one(
        {"_id": USER_MAC_ID},
        {"$setOnInsert": {"_id": USER_MAC_ID, "user_mac_id": USER_MAC_ID, "created_at": now_iso()},
         "$set": {
             "updated_at": now_iso(),
             "department": IDENTITY.get("department") if IDENTITY.get("role_key") != "C_SUITE" else None,
             "role_key": IDENTITY.get("role_key") or None,
             "company_username": normalize_email(IDENTITY.get("company_username")) or None,
             "pc_username": PC_USERNAME,
         }},
        upsert=True
    )

def _day_path(kind: str, d: str) -> str:
    return f"{kind}.{d}"

def _maybe_rotate_day_arrays(d: str):
    """
    If daily arrays exceed cap, archive into same collection with archive id.
    """
    try:
        # logs rotation
        docL = logs.find_one({"_id": USER_MAC_ID}, {"logs."+d: 1}) or {}
        ev = (((docL.get("logs") or {}).get(d)) or [])
        if len(ev) > MAX_EVENTS_PER_DAY:
            archive_id = f"{USER_MAC_ID}|archive|logs|{d}|{int(time.time())}"
            logs.insert_one({
                "_id": archive_id,
                "user_mac_id": USER_MAC_ID,
                "day": d,
                "archived_at": now_iso(),
                "logs": ev
            })
            logs.update_one({"_id": USER_MAC_ID}, {"$unset": {f"logs.{d}": ""}, "$set": {"updated_at": now_iso()}})

        # screenshots rotation
        docS = screenshots.find_one({"_id": USER_MAC_ID}, {"screenshots."+d: 1}) or {}
        ss = (((docS.get("screenshots") or {}).get(d)) or [])
        if len(ss) > MAX_SS_PER_DAY:
            archive_id = f"{USER_MAC_ID}|archive|screenshots|{d}|{int(time.time())}"
            screenshots.insert_one({
                "_id": archive_id,
                "user_mac_id": USER_MAC_ID,
                "day": d,
                "archived_at": now_iso(),
                "screenshots": ss
            })
            screenshots.update_one({"_id": USER_MAC_ID}, {"$unset": {f"screenshots.{d}": ""}, "$set": {"updated_at": now_iso()}})
    except:
        pass

def push_logs_many(log_items):
    if not log_items:
        return
    d = day_key()
    ensure_logs_doc()
    _maybe_rotate_day_arrays(d)
    upd = {"$set": {"updated_at": now_iso()}}
    upd.setdefault("$push", {})
    upd["$push"][_day_path("logs", d)] = {"$each": log_items}
    logs.update_one({"_id": USER_MAC_ID}, upd, upsert=True)

def push_screenshots_many(ss_items):
    if not ss_items:
        return
    d = day_key()
    ensure_screenshots_doc()
    _maybe_rotate_day_arrays(d)
    upd = {"$set": {"updated_at": now_iso()}}
    upd.setdefault("$push", {})
    upd["$push"][_day_path("screenshots", d)] = {"$each": ss_items}
    screenshots.update_one({"_id": USER_MAC_ID}, upd, upsert=True)

# ================== EVENT PRODUCERS ==================
# Notification queue to wake sync worker faster
wake_q = Queue()

def log_event(category, details, app, title, op):
    # Keep payload light: identity lives in users/departments collections
    rec = {
        "ts": now_iso(),
        "category": category,
        "details": details,
        "application": app,
        "window_title": title,
        "operation": op,
        "user_mac_id": USER_MAC_ID,
        "pc_username": PC_USERNAME,
    }
    spool_append("LOG", rec)
    try:
        wake_q.put_nowait(1)
    except:
        pass

def enqueue_screenshot_rec(rec: dict):
    spool_append("SS", rec)
    try:
        wake_q.put_nowait(1)
    except:
        pass

# ================== SYNC WORKER ==================
def sync_worker():
    """
    Reads durable spool and pushes in optimized batches.
    Uses offset checkpointing so we don't duplicate.
    """
    offset = _load_spool_offset()
    last_flush = time.time()

    while not stop_flag:
        # wake or periodic
        try:
            wake_q.get(timeout=0.5)
        except Empty:
            pass

        if not online.ok():
            # still compact occasionally (cheap)
            if (time.time() - last_flush) >= 30:
                spool_compact_if_needed(offset)
                last_flush = time.time()
            continue

        # Build a batch from spool
        items, new_offset = spool_read_batch(offset, max_items=max(ACTIVITY_BATCH_MAX, SCREENSHOT_BATCH_MAX) * 2)
        if not items:
            if (time.time() - last_flush) >= 30:
                spool_compact_if_needed(offset)
                last_flush = time.time()
            continue

        bufL, bufS = [], []
        for it in items:
            if it.get("kind") == "LOG":
                bufL.append(it.get("payload"))
            elif it.get("kind") == "SS":
                bufS.append(it.get("payload"))

        # throttle flush frequency to reduce DB operations
        due = (time.time() - last_flush) >= DB_FLUSH_SECONDS
        big = (len(bufL) >= ACTIVITY_BATCH_MAX) or (len(bufS) >= SCREENSHOT_BATCH_MAX)

        if due or big:
            try:
                # Keep identity docs alive but infrequent: only every flush window
                ensure_user_doc()
                ensure_departments_doc()
                if bufL:
                    push_logs_many(bufL)
                if bufS:
                    push_screenshots_many(bufS)

                # commit offset only after successful pushes
                offset = new_offset
                _save_spool_offset(offset)
                spool_compact_if_needed(offset)
                last_flush = time.time()
            except Exception as e:
                # don't advance offset; try later
                _debug_log(f"Sync flush failed: {e!r}")
                pass

def force_final_sync(max_seconds: float = 1.8):
    """
    Attempt to sync as much as possible before exiting.
    If offline, data is still safe in spool.
    """
    if not online.ok():
        return
    start = time.time()
    offset = _load_spool_offset()

    while time.time() - start < max_seconds:
        items, new_offset = spool_read_batch(offset, max_items=600)
        if not items:
            break
        bufL, bufS = [], []
        for it in items:
            if it.get("kind") == "LOG":
                bufL.append(it.get("payload"))
            elif it.get("kind") == "SS":
                bufS.append(it.get("payload"))
        try:
            ensure_user_doc()
            ensure_departments_doc()
            if bufL:
                push_logs_many(bufL)
            if bufS:
                push_screenshots_many(bufS)
            offset = new_offset
            _save_spool_offset(offset)
        except:
            break

# ================== SCREENSHOTS ==================
shot_q = Queue()

def save_screenshot_jpeg(path):
    # Always JPEG (smaller space). MSS preferred.
    if MSS_OK:
        with mss.mss() as sct:
            mon = sct.monitors[1]
            raw = sct.grab(mon)
            im = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
    else:
        im = pyautogui.screenshot()

    w, h = im.size
    if w > SHOT_MAX_WIDTH:
        im = im.resize((SHOT_MAX_WIDTH, int(h * (SHOT_MAX_WIDTH / float(w)))))
    im.save(path, format="JPEG", quality=JPEG_QUALITY, optimize=True)

def capture_screenshot(app, title, label):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fpath = os.path.join(SHOT_DIR, f"{PC_USERNAME}_{ts}_{label}.jpg")
    try:
        save_screenshot_jpeg(fpath)
        shot_q.put((app, title, label, fpath))
    except:
        pass

def upload_worker():
    while not stop_flag:
        try:
            app, title, label, fpath = shot_q.get(timeout=0.2)
        except Empty:
            continue

        url = fpath
        if online.ok():
            try:
                resp = cloudinary.uploader.upload(
                    fpath, folder="activity_screenshots", resource_type="image",
                    transformation=[{"fetch_format": "auto"}, {"quality": "auto:low"}],
                )
                url = resp.get("secure_url") or fpath
                if url != fpath:
                    try:
                        os.remove(fpath)
                    except:
                        pass
            except:
                pass

        rec = {
            "ts": now_iso(),
            "application": app,
            "window_title": title,
            "label": label,
            "file_path": fpath,
            "screenshot_url": url,
            "user_mac_id": USER_MAC_ID,
            "pc_username": PC_USERNAME,
        }
        enqueue_screenshot_rec(rec)

# ================== TYPING (SENTENCE-AWARE, MASKED) ==================
class TypedBuffer:
    """
    Privacy-safe capture:
    - does NOT store plaintext typed content
    - stores masked chunk + metrics
    - sentence-aware flush when '.', '?', '!', Enter
    - reliability: flush on window change, idle timeout, shutdown
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.buf = []
        self.last = 0
        self.day = day_key()
        self.seq = 0
        self.had_backspace = False
        self.had_paste = False
        threading.Thread(target=self._idle, daemon=True).start()
        threading.Thread(target=self._day_rollover, daemon=True).start()

    def _day_rollover(self):
        while not stop_flag:
            time.sleep(5)
            d = day_key()
            if d != self.day:
                self.flush("day_rollover")
                with self.lock:
                    self.day = d
                    self.seq = 0

    def add(self, ch, *, from_paste=False):
        with self.lock:
            self.last = time.time()
            if from_paste:
                self.had_paste = True
            self.buf.append(ch)

            # sentence-aware flush
            flush = (ch in SENTENCE_END_CHARS) or (len(self.buf) >= MAX_BUFFER_CHARS)
            chunk = "".join(self.buf).strip() if flush else None
            if flush:
                self.buf.clear()
                back = self.had_backspace
                paste = self.had_paste
                self.had_backspace = False
                self.had_paste = False
            else:
                back = paste = False

        if chunk:
            reason = "sentence_end" if ch in SENTENCE_END_CHARS else "max_chars"
            self.emit(chunk, reason, backspace=back, paste=paste)

    def note_backspace(self):
        with self.lock:
            self.had_backspace = True
            self.last = time.time()

    def note_paste(self):
        with self.lock:
            self.had_paste = True
            self.last = time.time()

    def flush(self, reason="forced"):
        with self.lock:
            chunk = "".join(self.buf).strip()
            self.buf.clear()
            back = self.had_backspace
            paste = self.had_paste
            self.had_backspace = False
            self.had_paste = False
        if chunk:
            self.emit(chunk, reason, backspace=back, paste=paste)

    def _idle(self):
        while not stop_flag:
            time.sleep(0.2)
            with self.lock:
                if self.buf and (time.time() - self.last) >= FLUSH_IDLE_SECONDS:
                    chunk = "".join(self.buf).strip()
                    self.buf.clear()
                    back = self.had_backspace
                    paste = self.had_paste
                    self.had_backspace = False
                    self.had_paste = False
                else:
                    chunk = None
            if chunk:
                self.emit(chunk, "idle_timeout", backspace=back, paste=paste)

    def emit(self, chunk, reason, *, backspace: bool, paste: bool):
        app, title = active_window()
        with self.lock:
            # sequence per day for gap detection
            if day_key() != self.day:
                self.day = day_key()
                self.seq = 0
            self.seq += 1
            seq = self.seq

        masked_result = smart_mask(chunk)

        payload = {
        "typed_text": masked_result["text"],
        "is_masked": masked_result["masked"],}



        log_event("KeystrokeChunk", json.dumps(payload, ensure_ascii=False), app, title, "Typed Chunk")

typed = TypedBuffer()

# --- keyboard tracking for paste/backspace (heuristic)
_ctrl_down = False
_shift_down = False

def key_to_char(k):
    try:
        if hasattr(k, "char") and k.char and k.char.isprintable():
            return k.char
    except:
        pass
    if k == keyboard.Key.space: return " "
    if k == keyboard.Key.enter: return "\n"
    if k == keyboard.Key.tab: return "\t"
    return None

def on_key_press(k):
    global _ctrl_down, _shift_down
    try:
        if k in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            _ctrl_down = True
        if k in (keyboard.Key.shift, keyboard.Key.shift_l, keyboard.Key.shift_r):
            _shift_down = True
        if k == keyboard.Key.backspace:
            typed.note_backspace()
            return

        # Ctrl+V paste heuristic: we can't see pasted content, but we can mark it so it's not "missed"
        if _ctrl_down and hasattr(k, "char") and (k.char or "").lower() == "v":
            typed.note_paste()
            # Flush current buffer so pasted burst doesn't get mixed
            typed.flush("paste_detected")
            app, title = active_window()
            log_event("Paste", "Ctrl+V", app, title, "Paste Detected")
            return

        ch = key_to_char(k)
        if ch:
            typed.add(ch)
    except:
        pass

def on_key_release(k):
    global _ctrl_down, _shift_down
    try:
        if k in (keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            _ctrl_down = False
        if k in (keyboard.Key.shift, keyboard.Key.shift_l, keyboard.Key.shift_r):
            _shift_down = False
    except:
        pass

def on_click(x, y, btn, pressed):
    if pressed:
        app, title = active_window()
        log_event("MouseClick", f"{btn} at ({x}, {y})", app, title, "Mouse Click")

def start_listeners():
    keyboard.Listener(on_press=on_key_press, on_release=on_key_release).start()
    mouse.Listener(on_click=on_click).start()

# ================== MONITOR ==================
def window_monitor():
    _, last_title = active_window()
    last_shot = 0
    while not stop_flag:
        app, title = active_window()
        try:
            if title and title != last_title:
                typed.flush("window_changed")
                log_event("ActiveWindow", title, app, title, "Window Switched")
                capture_screenshot(app, title, "SWITCH")
                last_title = title
                last_shot = time.time()
            elif title and (time.time() - last_shot) >= SCREENSHOT_MIN_INTERVAL:
                log_event("ActiveWindow", title, app, title, "Periodic Screenshot")
                capture_screenshot(app, title, "PERIODIC")
                last_shot = time.time()
        except:
            pass
        time.sleep(1)

def maintenance():
    """
    Low-frequency profile heartbeat; avoids constant writes.
    """
    while not stop_flag:
        time.sleep(300)
        try:
            ensure_user_doc()
            ensure_departments_doc()
        except:
            pass

# ================== GUI ==================
class Wizard(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(WIN_W, max(720, sw - 80))
        h = min(WIN_H, max(520, sh - 120))
        self.geometry(f"{w}x{h}")
        self.minsize(520, 420)

        header = Frame(self, padx=16, pady=10)
        header.pack(fill="x")
        Label(header, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        Label(
            header,
            text=f"Device detected automatically | PC: {PC_USERNAME} | Device ID: {USER_MAC_ID}",
            font=("Segoe UI", 10)
        ).pack(anchor="w")

        self.container = Frame(self, padx=16, pady=12)
        self.container.pack(fill="both", expand=True)
        self.show("license")

    def show(self, name):
        for c in self.container.winfo_children():
            c.destroy()
        if name == "license":
            LicensePage(self.container, lambda: self.show("setup")).pack(fill="both", expand=True)
        else:
            SetupPage(self.container, self.finish).pack(fill="both", expand=True)

    def finish(self, username, full_name, role, dept):
        """
        Per your requirement: DEPARTMENT_HEAD and C_SUITE are not mandatory to sign in via plugin.
        This wizard is primarily for DEPARTMENT_MEMBER devices.
        """
        global IDENTITY

        email_norm = normalize_email(username)

        # If C_SUITE: no department stored
        department_value = None if role == "C_SUITE" else dept

        prev = load_identity() or {}
        IDENTITY = {
            "company_username": email_norm,
            "full_name": full_name.strip(),
            "role_key": role,
            "department": department_value,

            # keep stable device_id (primary key) across runs
            "device_id": prev.get("device_id") or USER_MAC_ID,

            # backward-compatible fields
            "user_mac_id": prev.get("device_id") or USER_MAC_ID,
            "pc_username": PC_USERNAME,

            "license_accepted": True,
            "license_version": LICENSE_VERSION,
            "license_accepted_at": now_iso(),
        }
        save_identity(IDENTITY)

        try:
            ensure_user_doc()
            ensure_departments_doc()
            ensure_logs_doc()
            ensure_screenshots_doc()
        except:
            pass

        messagebox.showinfo(APP_NAME, "Setup completed. Logger will start now.")
        self.destroy()
        start_runtime()

class LicensePage(Frame):
    def __init__(self, parent, on_next):
        super().__init__(parent)
        self.on_next = on_next
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        Label(self, text="License Agreement", font=("Segoe UI", 14, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 8))

        tf = Frame(self, bd=1, relief="sunken")
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)
        sb = Scrollbar(tf)
        sb.grid(row=0, column=1, sticky="ns")
        tx = Text(tf, wrap="word", yscrollcommand=sb.set, font=("Consolas", 10))
        tx.grid(row=0, column=0, sticky="nsew")
        sb.config(command=tx.yview)
        tx.insert(END, LICENSE_TEXT)
        tx.config(state="disabled")

        self.accept = IntVar(value=0)
        Checkbutton(self, text="I Accept the License Agreement", variable=self.accept).grid(row=2, column=0, sticky="w", pady=(10, 6))

        br = Frame(self)
        br.grid(row=3, column=0, sticky="ew")
        self.next_btn = Button(br, text="Next", width=12, command=self.next, state="disabled")
        Button(br, text="Decline", width=12, command=lambda: sys.exit(0)).pack(side="right", padx=(8, 0))
        self.next_btn.pack(side="right")
        self.after(200, self.poll)

    def poll(self):
        self.next_btn.config(state=("normal" if self.accept.get() else "disabled"))
        self.after(200, self.poll)

    def next(self):
        self.on_next()

class SetupPage(Frame):
    def __init__(self, parent, on_finish):
        super().__init__(parent)
        self.on_finish = on_finish
        Label(self, text="Company Setup", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        f = Frame(self)
        f.pack(fill="x", pady=(12, 0))
        ident = load_identity()

        self.u = StringVar(value=ident.get("company_username", ""))

        self.full_name = StringVar(value=ident.get("full_name", ""))

        self.r = StringVar(value=ident.get("role_key", "DEPARTMENT_MEMBER"))
        if self.r.get() not in ROLE_OPTIONS:
            self.r.set("DEPARTMENT_MEMBER")

        self.d = StringVar(value=ident.get("department") or DEPT_OPTIONS[0])

        self.row(f, "Username (Email):", self.u)
        self.row(f, "Full Name:", self.full_name)

        rr = Frame(f)
        rr.pack(fill="x", pady=6)
        Label(rr, text="Role:", width=18, anchor="w").pack(side="left")
        OptionMenu(rr, self.r, *ROLE_OPTIONS, command=lambda *_: self._role_changed()).pack(side="left", fill="x", expand=True)

        dr = Frame(f)
        dr.pack(fill="x", pady=6)
        Label(dr, text="Department:", width=18, anchor="w").pack(side="left")
        self.dept_menu = OptionMenu(dr, self.d, *DEPT_OPTIONS)
        self.dept_menu.pack(side="left", fill="x", expand=True)

        br = Frame(self)
        br.pack(fill="x", pady=(14, 0))
        Button(br, text="Cancel", width=12, command=lambda: sys.exit(0)).pack(side="right", padx=(8, 0))
        Button(br, text="Finish & Start", width=14, command=self.finish).pack(side="right")

        self._role_changed()

    def _role_changed(self):
        if self.r.get() == "C_SUITE":
            try:
                self.dept_menu.configure(state="disabled")
            except:
                pass
        else:
            try:
                self.dept_menu.configure(state="normal")
            except:
                pass

    def row(self, parent, label, var, pwd=False):
        r = Frame(parent)
        r.pack(fill="x", pady=6)
        Label(r, text=label, width=18, anchor="w").pack(side="left")
        Entry(r, textvariable=var, show="*" if pwd else "").pack(side="left", fill="x", expand=True)

    def finish(self):
        u = self.u.get().strip()
        full_name = self.full_name.get().strip()
        role = self.r.get()
        dept = self.d.get()

        email_norm = normalize_email(u)

        if not email_norm:
            return messagebox.showerror(APP_NAME, "Username (Email) is required.")
        if not full_name:
            return messagebox.showerror(APP_NAME, "Full Name is required.")
        if role not in ROLE_OPTIONS:
            return messagebox.showerror(APP_NAME, "Select a valid Role.")
        if role != "C_SUITE" and dept not in DEPT_OPTIONS:
            return messagebox.showerror(APP_NAME, "Select a valid Department.")

        # Per requirement: This setup is mainly for members. Others can exist but aren't mandatory to sign in.
        self.on_finish(email_norm, full_name, role, dept)

# ================== RUNTIME ==================
def start_runtime():
    global IDENTITY
    IDENTITY = load_identity()
    if not IDENTITY.get("license_accepted"):
        return

    # If role is missing, still run in device-only mode (admin can fill later).
    role = IDENTITY.get("role_key")
    if role and role not in ROLE_OPTIONS:
        messagebox.showerror(APP_NAME, "Invalid role selected. Please re-run setup.")
        return

    if role == "C_SUITE":
        IDENTITY["department"] = None

    try:
        ensure_user_doc()
        ensure_departments_doc()
        ensure_logs_doc()
        ensure_screenshots_doc()
    except:
        pass

    log_event("System", "System Login", "OS", "", "User Logged In")

    threading.Thread(target=sync_worker, daemon=True).start()
    threading.Thread(target=upload_worker, daemon=True).start()
    threading.Thread(target=maintenance, daemon=True).start()

    start_listeners()
    window_monitor()

def shutdown():
    global stop_flag
    stop_flag = True

    try:
        typed.flush("shutdown")
    except:
        pass

    try:
        log_event("System", "System Logout", "OS", "", "User Logged Out")
    except:
        pass

    # Best-effort final sync (won't block long; spool guarantees no loss)
    try:
        force_final_sync(max_seconds=1.8)
    except:
        pass

    time.sleep(0.2)

def sigint(sig, frame):
    shutdown()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)

    ident = load_identity()
    ok_common = (
        ident.get("license_accepted")
        and ident.get("company_username")
        and ident.get("role_key") in ROLE_OPTIONS
        and ident.get("full_name")
    )

    # If already configured: start directly.
    # Else: run wizard. (Your requirement: members sign in; others not mandatory.)
    if ok_common:
        start_runtime()
    else:
        Wizard().mainloop()
