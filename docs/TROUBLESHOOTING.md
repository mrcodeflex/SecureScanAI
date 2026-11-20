# Troubleshooting

## Installation
| Problem | Fix |
|---|---|
| "Python was not found" | Install Python 3.11+ from python.org and tick **Add python.exe to PATH**; reopen the folder and run `install_windows.bat` again |
| `pip install` fails / no internet | Check your connection or proxy; run `install_windows.bat` again (it resumes) |
| Antivirus blocks `.bat` files | Allow the folder, or run the commands in README section 7 manually |
| "Password rejected" while creating the admin | Use 12+ characters with letters **and** numbers; do not include the username |

## Server
| Problem | Fix |
|---|---|
| `start_server.bat` says it refuses to listen without TLS | Run `allow_phone_access.bat` (as administrator) or set `SSAI_HOST=127.0.0.1` in `.env` |
| "address already in use" | Another program uses port 8000. Run `stop_server.bat`, or change `SSAI_PORT` in `.env` |
| Forgot the admin password | `.venv\Scripts\python.exe -m app.cli reset-password USERNAME` |
| Everything signs out after a restart | Normal only if `data\` was deleted; sessions are stored in the database |
| Where are the logs? | In the server window. `SSAI_LOG_LEVEL=DEBUG` in `.env` for more detail (never logs passwords or tokens) |

## Phone cannot connect
1. The phone and PC must be on the **same Wi-Fi** (not a guest network with client isolation).
2. Use the PC's **IPv4 address** from `ipconfig` - never `localhost`.
3. Include the port: `http://192.168.1.20:8000`.
4. Run `allow_phone_access.bat` **as administrator**, then restart the server.
5. In Windows *Settings > Network & Internet > Wi-Fi > your network*, set the profile to **Private**. The firewall rule applies to Private networks only.
6. Test from the phone's browser: open `http://<ip>:8000/api/health` - it should show `{"status":"ok",...}`.
7. "Certificate problem" in the app: the address starts with `https://` but the server certificate is not trusted. Use a trusted certificate or the plain LAN address.
8. "Plain HTTP is only allowed on a trusted local network": you typed a non-private address with `http://`. Use `https://`.

## Scanning
| Message | Meaning |
|---|---|
| "...resolves to a private, loopback, link-local or reserved network" | The scanner refuses internal targets (SSRF protection). Scan public sites only |
| "Active checks require the target host to be on the authorization allowlist" | An administrator must add the host in Settings > Authorized targets |
| "Could not reach the target" | DNS/firewall/timeouts; the site may block automated requests |
| "The archive contains an unsafe path..." | The ZIP was rejected for safety (path traversal) |
| "The archive compression ratio is suspiciously high" | Possible ZIP bomb; re-zip the source without huge generated files |
| Engine shows "not installed" | See `docs/ENGINES.md` |

## Android build
See `ANDROID_BUILD_GUIDE.md`, section "If the build fails".
