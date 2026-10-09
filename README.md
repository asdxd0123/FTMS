# FTMS - Fleet & Transportation Management System (PoC)

Python 3.9+, no installs needed.

    python3 server.py        # prints one-time demo passwords on first run, then open http://127.0.0.1:8000
    python3 test_ftms.py     # runs TC-01..TC-05 + security tests

Roles: Admin (everything, users, audit) | Dispatcher (vehicles, drivers, trips, maintenance, fuel) |
Driver (own trips, complete own trip, fuel for own active vehicle) | Viewer (read-only, licence numbers masked).

Config (env vars): FTMS_SECRET (keep sessions across restarts), FTMS_TOKEN_TTL, FTMS_SERVICE_KM, FTMS_HOST, FTMS_PORT.
To reset demo data: delete ftms.db.
