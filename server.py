#!/usr/bin/env python3
"""FTMS - Fleet & Transportation Management System (PoC). Python 3.9+, standard library only.
Run:  python3 server.py   ->  http://127.0.0.1:8000
"""
import os, re, sys, json, time, hmac, hashlib, base64, sqlite3, secrets
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import date, datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("FTMS_DB", os.path.join(BASE, "ftms.db"))
SECRET = (os.environ.get("FTMS_SECRET") or secrets.token_hex(32)).encode()  # set FTMS_SECRET to keep sessions across restarts
TTL = int(os.environ.get("FTMS_TOKEN_TTL", "1800"))        # session length (seconds)
SERVICE_KM = int(os.environ.get("FTMS_SERVICE_KM", "5000"))  # maintenance interval
MAX_FAIL, LOCK_SEC = 5, 300                                 # account lockout policy
ROLES = ("Admin", "Dispatcher", "Driver", "Viewer")
A, D, R, V = ROLES

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Admin','Dispatcher','Driver','Viewer')), active INTEGER DEFAULT 1,
  failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS vehicles(id INTEGER PRIMARY KEY, plate_no TEXT UNIQUE NOT NULL, make TEXT, model TEXT, year INTEGER,
  status TEXT DEFAULT 'Available' CHECK(status IN ('Available','In Use','Maintenance')), odometer INTEGER DEFAULT 0, last_service_odo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS drivers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, license_no TEXT UNIQUE NOT NULL, license_expiry TEXT, contact TEXT, user_id INTEGER);
CREATE TABLE IF NOT EXISTS trips(id INTEGER PRIMARY KEY, vehicle_id INTEGER NOT NULL, driver_id INTEGER NOT NULL, origin TEXT, destination TEXT,
  start_time TEXT, end_time TEXT, start_odo INTEGER, distance INTEGER, status TEXT DEFAULT 'Active');
CREATE TABLE IF NOT EXISTS maintenance(id INTEGER PRIMARY KEY, vehicle_id INTEGER NOT NULL, type TEXT, date TEXT, cost REAL, odometer INTEGER);
CREATE TABLE IF NOT EXISTS fuel_logs(id INTEGER PRIMARY KEY, vehicle_id INTEGER NOT NULL, date TEXT, liters REAL, cost REAL, odometer INTEGER);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT, ip TEXT);
"""

# ---------------------------------------------------------------- database
def _conn(autocommit=False):
    c = sqlite3.connect(DB, isolation_level=None if autocommit else "")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def run(sql, a=()):
    """Parameterised query (no string-built SQL anywhere -> no SQL injection). Rows for SELECT, lastrowid otherwise."""
    c = _conn()
    try:
        cur = c.execute(sql, a)
        out = [dict(r) for r in cur.fetchall()] if cur.description else cur.lastrowid
        c.commit()
        return out
    finally:
        c.close()

def one(sql, a=()):
    r = run(sql, a)
    return r[0] if r else None

def tx(fn):
    """Atomic multi-statement transaction (prevents double-booking races)."""
    c = _conn(autocommit=True)
    try:
        c.execute("BEGIN IMMEDIATE")
        r = fn(c)
        c.execute("COMMIT")
        return r
    except BaseException:
        c.execute("ROLLBACK")
        raise
    finally:
        c.close()

def q1(c, sql, a=()):
    r = c.execute(sql, a).fetchone()
    return dict(r) if r else None

# ---------------------------------------------------------------- security primitives
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    return salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000).hex()

def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salt)).split("$")[1], h)

DUMMY = hash_pw("dummy-password")  # equalises timing for unknown usernames

def sign(payload):
    b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    return (b + b"." + hmac.new(SECRET, b, "sha256").hexdigest().encode()).decode()

def verify(tok):
    try:
        b, sig = tok.encode().split(b".")
        if not hmac.compare_digest(hmac.new(SECRET, b, "sha256").hexdigest().encode(), sig):
            return None
        p = json.loads(base64.urlsafe_b64decode(b + b"=" * (-len(b) % 4)))
        return p if p["exp"] > time.time() else None
    except Exception:
        return None

def strong(pw):
    return isinstance(pw, str) and 10 <= len(pw) <= 128 and re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)

_hits = {}
def rate_ok(ip, limit=20, window=60):
    now = time.time()
    h = [t for t in _hits.get(ip, []) if now - t < window]
    h.append(now)
    _hits[ip] = h
    return len(h) <= limit

def audit(user, action, detail="", ip=""):
    run("INSERT INTO audit_log(ts,user,action,detail,ip) VALUES(?,?,?,?,?)",
        (datetime.utcnow().isoformat(timespec="seconds") + "Z", user, action, str(detail)[:300], ip))

# ---------------------------------------------------------------- validation
class Err(Exception):
    def __init__(self, msg, code=400):
        self.msg, self.code = msg, code

def s(d, k, mx=100):
    v = d.get(k)
    if not isinstance(v, str) or not v.strip() or len(v.strip()) > mx:
        raise Err(f"'{k}' is required (text, max {mx} chars)")
    return v.strip()

def n(d, k, lo=0, hi=10**9, f=False):
    v = d.get(k)
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not (lo <= v <= hi):
        raise Err(f"'{k}' must be a number between {lo} and {hi}")
    return float(v) if f else int(v)

def dt(d, k):
    v = d.get(k)
    try:
        return date.fromisoformat(v).isoformat()
    except Exception:
        raise Err(f"'{k}' must be a date (YYYY-MM-DD)")

def mask(x):
    return "***" + x[-3:]

def due(v):
    return v["odometer"] - v["last_service_odo"] >= SERVICE_KM

# ---------------------------------------------------------------- handlers  (ctx: user, body, ip, ids)
def login(c):
    if not rate_ok(c.ip):
        raise Err("Too many requests", 429)
    name, pw = c.body.get("username"), c.body.get("password")
    if not isinstance(name, str) or not isinstance(pw, str):
        raise Err("Invalid credentials", 401)
    u = one("SELECT * FROM users WHERE username=?", (name,))
    if u and u["locked_until"] > time.time():
        audit(name, "LOGIN_BLOCKED", "account locked", c.ip)
        raise Err("Account temporarily locked. Try again later.", 423)
    ok = check_pw(pw, u["pw_hash"] if u else DUMMY) and u and u["active"]
    if not ok:
        if u:
            f = u["failed"] + 1
            run("UPDATE users SET failed=?, locked_until=? WHERE id=?", (0 if f >= MAX_FAIL else f, time.time() + LOCK_SEC if f >= MAX_FAIL else 0, u["id"]))
        audit(name[:50], "LOGIN_FAIL", "", c.ip)
        raise Err("Invalid credentials", 401)
    run("UPDATE users SET failed=0, locked_until=0 WHERE id=?", (u["id"],))
    audit(name, "LOGIN_OK", "", c.ip)
    return {"token": sign({"uid": u["id"], "exp": time.time() + TTL}), "user": {"username": u["username"], "role": u["role"]}}

def me(c):
    return {"username": c.user["username"], "role": c.user["role"]}

def vehicles(c):
    return run("SELECT * FROM vehicles ORDER BY id")

def vehicle_new(c):
    b = c.body
    i = run("INSERT INTO vehicles(plate_no,make,model,year,odometer,last_service_odo) VALUES(?,?,?,?,?,?)",
            (s(b, "plate_no", 20).upper(), s(b, "make", 40), s(b, "model", 40), n(b, "year", 1980, 2100), n(b, "odometer"), n(b, "odometer")))
    audit(c.user["username"], "VEHICLE_CREATE", i, c.ip)
    return {"id": i}

def vehicle_edit(c):
    b, vid = c.body, c.ids[0]
    v = one("SELECT * FROM vehicles WHERE id=?", (vid,))
    if not v: raise Err("Not found", 404)
    st = b.get("status", v["status"])
    if st not in ("Available", "Maintenance") or (v["status"] == "In Use" and st != "In Use"):
        raise Err("Status can only be Available/Maintenance and an In Use vehicle must finish its trip first")
    odo = n(b, "odometer") if "odometer" in b else v["odometer"]
    if odo < v["odometer"]: raise Err("Odometer cannot decrease")
    run("UPDATE vehicles SET status=?, odometer=? WHERE id=?", (st, odo, vid))
    audit(c.user["username"], "VEHICLE_UPDATE", f"{vid} {st} {odo}", c.ip)
    return {"ok": True}

def vehicle_del(c):
    if one("SELECT 1 x FROM trips WHERE vehicle_id=?", (c.ids[0],)): raise Err("Vehicle has trip history")
    run("DELETE FROM vehicles WHERE id=?", (c.ids[0],))
    audit(c.user["username"], "VEHICLE_DELETE", c.ids[0], c.ip)
    return {"ok": True}

def drivers(c):
    rows = run("SELECT * FROM drivers ORDER BY id")
    if c.user["role"] not in (A, D):  # least privilege: licence numbers & contacts are masked
        for r in rows: r["license_no"], r["contact"] = mask(r["license_no"]), "(hidden)"
    return rows

def driver_new(c):
    b = c.body
    uid = b.get("user_id")
    if uid is not None:
        u = one("SELECT role FROM users WHERE id=?", (uid,))
        if not u or u["role"] != R: raise Err("user_id must be a Driver-role user")
    i = run("INSERT INTO drivers(name,license_no,license_expiry,contact,user_id) VALUES(?,?,?,?,?)",
            (s(b, "name"), s(b, "license_no", 30), dt(b, "license_expiry"), s(b, "contact", 60), uid))
    audit(c.user["username"], "DRIVER_CREATE", i, c.ip)
    return {"id": i}

def trips(c):
    sql = ("SELECT t.*, v.plate_no, d.name driver_name FROM trips t JOIN vehicles v ON v.id=t.vehicle_id "
           "JOIN drivers d ON d.id=t.driver_id")
    if c.user["role"] == R:
        return run(sql + " WHERE d.user_id=? ORDER BY t.id DESC", (c.user["id"],))
    return run(sql + " ORDER BY t.id DESC")

def trip_new(c):
    b = c.body
    vid, did, o, de = n(b, "vehicle_id", 1), n(b, "driver_id", 1), s(b, "origin"), s(b, "destination")
    def go(db):
        v, d = q1(db, "SELECT * FROM vehicles WHERE id=?", (vid,)), q1(db, "SELECT * FROM drivers WHERE id=?", (did,))
        if not v or not d: raise Err("Vehicle or driver not found", 404)
        if v["status"] != "Available": raise Err(f"Vehicle is {v['status']}", 409)
        if d["license_expiry"] < date.today().isoformat(): raise Err("Driver licence is expired", 409)
        if q1(db, "SELECT 1 x FROM trips WHERE driver_id=? AND status='Active'", (did,)): raise Err("Driver already on an active trip", 409)
        cur = db.execute("INSERT INTO trips(vehicle_id,driver_id,origin,destination,start_time,start_odo) VALUES(?,?,?,?,?,?)",
                         (vid, did, o, de, datetime.utcnow().isoformat(timespec="seconds") + "Z", v["odometer"]))
        db.execute("UPDATE vehicles SET status='In Use' WHERE id=?", (vid,))
        return {"id": cur.lastrowid, "maintenance_due": due(v)}
    r = tx(go)
    audit(c.user["username"], "TRIP_CREATE", r["id"], c.ip)
    return r

def trip_done(c):
    end = n(c.body, "end_odometer")
    def go(db):
        t = q1(db, "SELECT t.*, d.user_id FROM trips t JOIN drivers d ON d.id=t.driver_id WHERE t.id=?", (c.ids[0],))
        if not t: raise Err("Not found", 404)
        if c.user["role"] == R and t["user_id"] != c.user["id"]: raise Err("Forbidden: not your trip", 403)
        if t["status"] != "Active": raise Err("Trip already completed", 409)
        if end < t["start_odo"]: raise Err("end_odometer is lower than the start odometer")
        db.execute("UPDATE trips SET status='Completed', end_time=?, distance=? WHERE id=?",
                   (datetime.utcnow().isoformat(timespec="seconds") + "Z", end - t["start_odo"], t["id"]))
        db.execute("UPDATE vehicles SET status='Available', odometer=? WHERE id=?", (end, t["vehicle_id"]))
        return {"distance": end - t["start_odo"], "maintenance_due": due(q1(db, "SELECT * FROM vehicles WHERE id=?", (t["vehicle_id"],)))}
    r = tx(go)
    audit(c.user["username"], "TRIP_COMPLETE", c.ids[0], c.ip)
    return r

def maint(c):
    return run("SELECT m.*, v.plate_no FROM maintenance m JOIN vehicles v ON v.id=m.vehicle_id ORDER BY m.id DESC")

def maint_new(c):
    b = c.body
    v = one("SELECT * FROM vehicles WHERE id=?", (n(b, "vehicle_id", 1),))
    if not v: raise Err("Vehicle not found", 404)
    if v["status"] == "In Use": raise Err("Vehicle is on a trip", 409)
    i = run("INSERT INTO maintenance(vehicle_id,type,date,cost,odometer) VALUES(?,?,?,?,?)", (v["id"], s(b, "type", 60), dt(b, "date"), n(b, "cost", 0, 10**8, True), v["odometer"]))
    run("UPDATE vehicles SET last_service_odo=odometer, status='Available' WHERE id=?", (v["id"],))
    audit(c.user["username"], "MAINTENANCE_LOG", i, c.ip)
    return {"id": i}

def fuel(c):
    return run("SELECT f.*, v.plate_no FROM fuel_logs f JOIN vehicles v ON v.id=f.vehicle_id ORDER BY f.id DESC")

def fuel_new(c):
    b = c.body
    vid = n(b, "vehicle_id", 1)
    if c.user["role"] == R and not one("SELECT 1 x FROM trips t JOIN drivers d ON d.id=t.driver_id WHERE t.vehicle_id=? AND t.status='Active' AND d.user_id=?", (vid, c.user["id"])):
        raise Err("Forbidden: you can only log fuel for your active trip's vehicle", 403)
    if not one("SELECT 1 x FROM vehicles WHERE id=?", (vid,)): raise Err("Vehicle not found", 404)
    i = run("INSERT INTO fuel_logs(vehicle_id,date,liters,cost,odometer) VALUES(?,?,?,?,?)", (vid, dt(b, "date"), n(b, "liters", 0.1, 2000, True), n(b, "cost", 0, 10**7, True), n(b, "odometer")))
    audit(c.user["username"], "FUEL_LOG", i, c.ip)
    return {"id": i}

def alerts(c):
    soon = (date.today() + timedelta(days=30)).isoformat()
    return {"maintenance": [v for v in run("SELECT * FROM vehicles") if due(v)],
            "licenses": run("SELECT id,name,license_expiry FROM drivers WHERE license_expiry<=?", (soon,))}

def dashboard(c):
    st = {r["status"]: r["k"] for r in run("SELECT status, COUNT(*) k FROM vehicles GROUP BY status")}
    return {"vehicles": st, "active_trips": one("SELECT COUNT(*) k FROM trips WHERE status='Active'")["k"],
            "fuel_cost": round(one("SELECT COALESCE(SUM(cost),0) k FROM fuel_logs")["k"], 2),
            "maintenance_cost": round(one("SELECT COALESCE(SUM(cost),0) k FROM maintenance")["k"], 2),
            "alerts": len(alerts(c)["maintenance"]) + len(alerts(c)["licenses"])}

def users(c):
    return run("SELECT id,username,role,active FROM users ORDER BY id")

def user_new(c):
    b = c.body
    if b.get("role") not in ROLES: raise Err("Invalid role")
    if not strong(b.get("password")): raise Err("Password needs 10+ chars with upper, lower and a digit")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", b.get("username") or ""): raise Err("Username: 3-30 letters/digits/._-")
    try:
        i = run("INSERT INTO users(username,pw_hash,role) VALUES(?,?,?)", (b["username"], hash_pw(b["password"]), b["role"]))
    except sqlite3.IntegrityError:
        raise Err("Username taken", 409)
    audit(c.user["username"], "USER_CREATE", f"{b['username']} as {b['role']}", c.ip)
    return {"id": i}

def user_toggle(c):
    if c.ids[0] == c.user["id"]: raise Err("You cannot disable your own account")
    run("UPDATE users SET active=1-active, failed=0, locked_until=0 WHERE id=?", (c.ids[0],))
    audit(c.user["username"], "USER_TOGGLE", c.ids[0], c.ip)
    return {"ok": True}

def audit_list(c):
    return run("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")

ALL = (A, D, R, V)
ROUTES = [  # (method, path, allowed roles or None=public, handler)
    ("POST", r"/api/login", None, login), ("GET", r"/api/me", ALL, me),
    ("GET", r"/api/dashboard", (A, D, V), dashboard), ("GET", r"/api/alerts", (A, D, V), alerts),
    ("GET", r"/api/vehicles", (A, D, V), vehicles), ("POST", r"/api/vehicles", (A, D), vehicle_new),
    ("PUT", r"/api/vehicles/(\d+)", (A, D), vehicle_edit), ("DELETE", r"/api/vehicles/(\d+)", (A,), vehicle_del),
    ("GET", r"/api/drivers", (A, D, V), drivers), ("POST", r"/api/drivers", (A, D), driver_new),
    ("GET", r"/api/trips", ALL, trips), ("POST", r"/api/trips", (A, D), trip_new),
    ("POST", r"/api/trips/(\d+)/complete", (A, D, R), trip_done),
    ("GET", r"/api/maintenance", (A, D, V), maint), ("POST", r"/api/maintenance", (A, D), maint_new),
    ("GET", r"/api/fuel", (A, D, V), fuel), ("POST", r"/api/fuel", (A, D, R), fuel_new),
    ("GET", r"/api/users", (A,), users), ("POST", r"/api/users", (A,), user_new),
    ("POST", r"/api/users/(\d+)/toggle", (A,), user_toggle), ("GET", r"/api/audit", (A,), audit_list),
]
ROUTES = [(m, re.compile(p), r, f) for m, p, r, f in ROUTES]
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8")}

class Ctx:
    def __init__(s_, ip): s_.ip, s_.user, s_.body, s_.ids = ip, None, {}, ()

class H(BaseHTTPRequestHandler):
    server_version = "FTMS"
    sys_version = ""

    def _send(self, code, data, ctype="application/json"):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        for k, v in {"Content-Type": ctype, "Content-Length": str(len(body)), "Cache-Control": "no-store",
                     "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                     "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        path = self.path.split("?")[0]
        if method == "GET" and path in STATIC:
            f, ct = STATIC[path]
            return self._send(200, open(os.path.join(BASE, f), "rb").read(), ct)
        ctx = Ctx(self.client_address[0])
        try:
            for m, rx, roles, fn in ROUTES:
                mt = rx.fullmatch(path)
                if m != method or not mt: continue
                if roles:
                    p = verify(self.headers.get("Authorization", "")[7:])
                    u = p and one("SELECT * FROM users WHERE id=? AND active=1", (p["uid"],))
                    if not u: raise Err("Authentication required", 401)
                    ctx.user = u
                    if u["role"] not in roles:  # role is read from DB, never trusted from the token
                        audit(u["username"], "ACCESS_DENIED", f"{method} {path}", ctx.ip)
                        raise Err("Forbidden: your role cannot do this", 403)
                if method in ("POST", "PUT"):
                    ln = int(self.headers.get("Content-Length") or 0)
                    if ln > 65536: raise Err("Payload too large", 413)
                    try: ctx.body = json.loads(self.rfile.read(ln) or b"{}")
                    except ValueError: raise Err("Invalid JSON")
                    if not isinstance(ctx.body, dict): raise Err("JSON object expected")
                ctx.ids = tuple(int(x) for x in mt.groups())
                return self._send(200, fn(ctx))
            raise Err("Not found", 404)
        except Err as e:
            self._send(e.code, {"error": e.msg})
        except sqlite3.IntegrityError as e:
            self._send(409, {"error": "Duplicate or invalid reference"})
        except Exception as e:  # never leak internals to the client
            print("ERROR", repr(e), file=sys.stderr)
            self._send(500, {"error": "Internal server error"})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self): self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, *a): pass

def init(print_creds=True):
    c = _conn(); c.executescript(SCHEMA); c.commit(); c.close()
    if one("SELECT 1 x FROM users"): return {}
    creds = {}
    for name, role in (("admin", A), ("dispatcher", D), ("driver1", R), ("viewer", V)):
        pw = "Ftms-" + secrets.token_urlsafe(8) + "9"   # random one-time passwords, shown once
        creds[name] = pw
        run("INSERT INTO users(username,pw_hash,role) VALUES(?,?,?)", (name, hash_pw(pw), role))
    for p, mk, md, y, o in (("ABC-1234", "Toyota", "Hiace", 2021, 42000), ("XYZ-5678", "Isuzu", "NLR", 2019, 98000), ("DEF-9012", "Mitsubishi", "L300", 2022, 8000)):
        run("INSERT INTO vehicles(plate_no,make,model,year,odometer,last_service_odo) VALUES(?,?,?,?,?,?)", (p, mk, md, y, o, o - 3000 if p != "XYZ-5678" else o - 5200))
    run("INSERT INTO drivers(name,license_no,license_expiry,contact,user_id) VALUES('Juan Dela Cruz','N01-23-456789','2028-05-01','0917-000-0001',3)")
    run("INSERT INTO drivers(name,license_no,license_expiry,contact) VALUES('Maria Santos','N02-34-567890','2026-10-20','0917-000-0002')")
    if print_creds:
        print("\nFirst run - demo accounts (shown ONCE, change/replace for real use):")
        for k, v in creds.items(): print(f"  {k:<11} {v}")
    return creds

if __name__ == "__main__":
    init()
    host, port = os.environ.get("FTMS_HOST", "127.0.0.1"), int(os.environ.get("FTMS_PORT", "8000"))
    print(f"\nFTMS running at http://{host}:{port}  (use a TLS reverse proxy for anything beyond localhost)")
    ThreadingHTTPServer((host, port), H).serve_forever()
