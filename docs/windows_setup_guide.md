# Windows Setup Guide for NetGuard

## Prerequisites
- **Windows 10/11** (64‑bit)
- **Administrator** rights on the machine.
- **Python 3.11** installed and added to `PATH`.
- **Git** (optional, for source checkout).

## 1. Install Npcap
1. Download the latest stable **Npcap** installer from the official site:
   - URL: https://nmap.org/npcap/
2. Run the installer with default options. Ensure **"Install Npcap in WinPcap API-compatible mode"** is checked – NetGuard uses the `pcapy` wrapper.
3. Re‑boot if prompted.

## 2. Install Wireshark (optional – for manual PCAP inspection)
1. Download Wireshark from https://www.wireshark.org/download.html.
2. Run the installer and keep the default components.
3. Verify installation by opening a sample PCAP (`File → Open`).

## 3. Set up the Python environment
```powershell
# Create a virtual environment inside the project
cd d:\netguard\is_project2\is_project
python -m venv .venv
# Activate it
.\.venv\Scripts\Activate.ps1
# Upgrade pip
python -m pip install --upgrade pip
# Install required packages (offline wheel caches are bundled with the repo)
python -m pip install -r requirements.txt
```
> **Note**: If `pip install` fails with a permission error, re‑run the PowerShell window as Administrator or retry the command (the sandbox may temporarily block file creation).

## 4. Verify NetGuard dependencies
```powershell
python -c "import flask; import scapy; import numpy; import sklearn; print('All imports OK')"
```
You should see `All imports OK` without errors.

## 5. Run the Flask Web UI (`netguard/web/app.py`)
```powershell
# Ensure the virtual env is active
cd d:\netguard\is_project2\is_project
python netguard/web/app.py
```
This runs the **Flask** application (`app = create_app(); app.run(host="127.0.0.1", port=5000, debug=True)`). Open a browser and navigate to `http://127.0.0.1:5000`. You should see the NetGuard dashboard.

## 6. Common troubleshooting
| Symptom | Likely cause | Fix |
|---|---|---|
| `ImportError: DLL load failed` for `pcapy` | Npcap driver not installed or not in compatibility mode | Re‑install Npcap with the WinPcap‑compatible flag. |
| `PermissionError` on model save path | Sandbox blocked file creation | Run the PowerShell session as Administrator or move the model directory to a writable location (e.g., `C:\Temp\netguard_models`). |
| UI not loading | Flask server not started or wrong port | Verify `app.py` is running and check console output for errors. |

---
*All commands assume the project root is `d:\netguard\is_project2\is_project`. Adjust paths accordingly if you use a different location.*