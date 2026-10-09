#!/usr/bin/env python3
"""Runs the document's test cases (TC-01..TC-05) plus security tests. Usage: python3 test_ftms.py"""
import os, sys, json, tempfile, threading, http.client
os.environ["FTMS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["FTMS_SECRET"] = "test-secret"
import server
from http.server import ThreadingHTTPServer

creds = server.init(print_creds=False)
srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
PORT = srv.server_address[1]
results = []

def call(method, path, body=None, token=None, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT)
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    c.request(method, path, raw if raw is not None else (json.dumps(body) if body is not None else None), h)
    r = c.getresponse(); data = r.read()
    try: data = json.loads(data)
    except Exception: pass
    return r.status, data, r.getheaders()

def login(u):
    s, d, _ = call("POST", "/api/login", {"username": u, "password": creds[u]}); assert s == 200, d
    return d["token"]

def check(name, cond):
    results.append(cond); print(("PASS  " if cond else "FAIL  ") + name)

adm, dis, drv, vwr = (login(u) for u in ("admin", "dispatcher", "driver1", "viewer"))

print("-- Document test cases")
s, d, _ = call("POST", "/api/vehicles", {"plate_no": "new-001", "make": "Ford", "model": "Transit", "year": 2023, "odometer": 1000}, dis)
vid = d.get("id"); s2, l, _ = call("GET", "/api/vehicles", token=dis)
check("TC-01 Add a new vehicle -> saved and listed", s == 200 and any(v["plate_no"] == "NEW-001" for v in l))
s, d, _ = call("POST", "/api/trips", {"vehicle_id": vid, "driver_id": 1, "origin": "Manila", "destination": "Quezon City"}, dis)
tid = d.get("id"); v = [x for x in call("GET", "/api/vehicles", token=dis)[1] if x["id"] == vid][0]
check("TC-02 Assign driver+vehicle -> trip created, vehicle In Use", s == 200 and v["status"] == "In Use")
check("     double-booking the same vehicle is rejected (409)", call("POST", "/api/trips", {"vehicle_id": vid, "driver_id": 2, "origin": "a", "destination": "b"}, dis)[0] == 409)
check("     driver on another active trip is rejected (409)", call("POST", "/api/trips", {"vehicle_id": 1, "driver_id": 1, "origin": "a", "destination": "b"}, dis)[0] == 409)
s, d, _ = call("POST", f"/api/trips/{tid}/complete", {"end_odometer": 1120}, drv)
v = [x for x in call("GET", "/api/vehicles", token=dis)[1] if x["id"] == vid][0]
check("TC-03 Complete trip -> vehicle Available, distance 120", s == 200 and v["status"] == "Available" and d["distance"] == 120)
s, d, _ = call("GET", "/api/alerts", token=dis)
check("TC-04 Mileage past threshold -> maintenance alert (XYZ-5678)", any(x["plate_no"] == "XYZ-5678" for x in d["maintenance"]))
check("TC-05 Unauthorized role on admin page -> denied (403)", call("GET", "/api/users", token=dis)[0] == 403 and call("GET", "/api/audit", token=vwr)[0] == 403)

print("-- Security tests")
check("No token -> 401", call("GET", "/api/vehicles")[0] == 401)
check("Tampered token -> 401", call("GET", "/api/vehicles", token=adm[:-3] + "abc")[0] == 401)
check("Expired token -> 401", call("GET", "/api/vehicles", token=server.sign({"uid": 1, "exp": 1}))[0] == 401)
check("Viewer cannot create vehicles (403)", call("POST", "/api/vehicles", {"plate_no": "X"}, vwr)[0] == 403)
check("Driver cannot list vehicles/fuel (403)", call("GET", "/api/vehicles", token=drv)[0] == 403 and call("GET", "/api/fuel", token=drv)[0] == 403)
check("Driver cannot dispatch trips (403)", call("POST", "/api/trips", {"vehicle_id": 1, "driver_id": 1, "origin": "a", "destination": "b"}, drv)[0] == 403)
s, d, _ = call("GET", "/api/drivers", token=vwr)
check("Viewer sees masked licence numbers", all(x["license_no"].startswith("***") for x in d))
s, d, _ = call("GET", "/api/drivers", token=dis)
check("Dispatcher sees full licence numbers", not d[0]["license_no"].startswith("***"))
s, d, _ = call("POST", "/api/trips", {"vehicle_id": 3, "driver_id": 1, "origin": "a", "destination": "b"}, dis)
other = call("POST", "/api/users", {"username": "driver2", "password": "Str0ngPassword1", "role": "Driver"}, adm)[1]["id"]
check("Driver cannot complete someone else's trip (403)", call("POST", f"/api/trips/{d['id']}/complete", {"end_odometer": 99999}, server.sign({"uid": other, "exp": 9e12}) and call("POST", "/api/login", {"username": "driver2", "password": "Str0ngPassword1"})[1]["token"])[0] == 403)
check("Driver cannot log fuel for a vehicle not on their trip (403)", call("POST", "/api/fuel", {"vehicle_id": 1, "date": "2026-10-09", "liters": 10, "cost": 500, "odometer": 5}, drv)[0] == 403)
s, d, _ = call("POST", "/api/vehicles", {"plate_no": "';DROP TABLE users--", "make": "x", "model": "y", "year": 2020, "odometer": 1}, adm)
check("SQL injection payload stored as plain text, tables intact", s == 200 and call("GET", "/api/users", token=adm)[0] == 200)
check("Bad input (negative odometer / bool / text year) rejected (400)", all(call("POST", "/api/vehicles", b, adm)[0] == 400 for b in (
    {"plate_no": "A", "make": "m", "model": "m", "year": 2020, "odometer": -5}, {"plate_no": "B", "make": "m", "model": "m", "year": True, "odometer": 1}, {"plate_no": "C", "make": "m", "model": "m", "year": "2020", "odometer": 1})))
check("Malformed JSON -> 400, oversized body -> 413", call("POST", "/api/vehicles", token=adm, raw="{bad")[0] == 400 and call("POST", "/api/vehicles", token=adm, raw="x" * 70000)[0] == 413)
check("Weak password rejected on user creation", call("POST", "/api/users", {"username": "weak", "password": "password", "role": "Viewer"}, adm)[0] == 400)
check("Admin cannot disable own account", call("POST", "/api/users/1/toggle", token=adm)[0] == 400)
call("POST", "/api/users/%d/toggle" % other, token=adm)
check("Disabled user cannot log in", call("POST", "/api/login", {"username": "driver2", "password": "Str0ngPassword1"})[0] == 401)
for _ in range(5): call("POST", "/api/login", {"username": "viewer", "password": "wrong"})
check("Account locks after 5 failed logins (423), even with the right password", call("POST", "/api/login", {"username": "viewer", "password": creds["viewer"]})[0] == 423)
s, d, h = call("GET", "/api/me", token=adm); hd = {k.lower(): v for k, v in h}
check("Security headers present (CSP, nosniff, DENY, no-store)", all(k in hd for k in ("content-security-policy", "x-content-type-options", "x-frame-options")) and hd["cache-control"] == "no-store")
s, d, _ = call("GET", "/api/audit", token=adm); acts = {x["action"] for x in d}
check("Audit log recorded logins, failures, denials, changes", {"LOGIN_OK", "LOGIN_FAIL", "ACCESS_DENIED", "TRIP_CREATE", "VEHICLE_CREATE"} <= acts)
check("Password hashes never exposed via API", "pw_hash" not in json.dumps(call("GET", "/api/users", token=adm)[1]))
check("Path traversal / unknown files not served", call("GET", "/../server.py")[0] == 404 and call("GET", "/server.py")[0] == 404)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
