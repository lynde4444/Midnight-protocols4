# 🛡️ Forensic Android APK Triage Platform
**Defensive Mobile Digital Forensics**

A rapid, explainable static triage platform for law-enforcement digital forensics investigators. Upload one or more suspicious Android APK packages and obtain an instant **0–100 risk score with forensic evidence**, extracted IoCs, cross-sample infrastructure mapping, and courtroom-ready printable reports.

---

## 🎯 Key Capabilities
1. **Explainable 0–100 Risk Score**: Every awarded point is directly linked to an evidentiary artifact (permission, bytecode string, exact API descriptor, or hash).
2. **Deterministic Category Caps**:
   - **Permissions (Cap 25)**: SMS manipulation, Accessibility Service, Device Admin, Overlay (`SYSTEM_ALERT_WINDOW`), Contacts, Audio.
   - **Evasion (Cap 30)**: `DexClassLoader`, `InMemoryDexClassLoader`, commercial packers (`libjiagu`, `libsecexe`, etc.), anti-debugging, emulator detection, high-entropy assets (>7.5), class obfuscation (>30%).
   - **Behaviour (Cap 25)**: SMS interception, Accessibility abuse, Device Admin receiver, overlay injection, audio eavesdropping, contacts harvesting, IMEI/Cipher.
   - **Network (Cap 10)**: Telegram/Firebase C2 endpoints, hard-coded public IPv4s, high-abuse TLDs (`.xyz`, `.top`, `.online`), cleartext HTTP.
   - **Integrity (Cap 10)**: Unsigned / tampered package penalty (+6).
3. **Zero Host Execution (Pure Defensive Safety)**: Operates 100% via static memory parsing. Host machine never installs, emulates, or executes untrusted binaries. Memory reads are strictly bounded to prevent ZipSlip and ZipBombs.
4. **Modern Signature Awareness**: Detects APK Signing Block v2/v3 (`APK Sig Block 42` magic bytes) alongside legacy v1 (`META-INF/*.RSA`), preventing false "unsigned" flags on modern apps.
5. **Campaign Infrastructure Graphing**: Identifies shared C2 servers across multi-APK investigations and renders dynamic Graphviz network graphs.

---

## 🚀 Quickstart Options

### Option 1: Standalone Console Runner (Pure Python Stdlib)
Requires **zero external dependencies** and runs on Python 3.6+ in any terminal, air-gapped forensic workstation, or online compiler (Replit, Programiz, etc.):

```bash
# Run with 3 built-in synthetic demo APKs (Banking Trojan ~78, Adware ~61, Benign ~8):
python apk_triage_console.py

# Or triage specific APK files:
python apk_triage_console.py /path/to/suspect1.apk /path/to/suspect2.apk
```

---

### Option 2: Streamlit Interactive Web Application
A self-contained single-file interface ready for **Streamlit Community Cloud** or local analyst deployment:

```bash
# Install dependencies
pip install -r requirements.txt

# Launch interactive UI
streamlit run streamlit_app.py
```
* **Community Cloud Deployment**: Push this repository to GitHub and link `streamlit_app.py` directly. Configured with modern `width="stretch"` layout.
* **In-Memory Demos**: Click **"🚀 Load Demo APKs"** in the sidebar to populate the UI with 3 representative synthetic samples instantly.
* **Upload Clearing**: Click **"🗑️ Clear All"** to reset session state and wipe the file uploader cache via dynamic key rotation.

---

### Option 3: FastAPI REST Service & SQLite Case Vault
For agency-wide API integration and persistent forensic storage:

```bash
# Start backend server
uvicorn api:app --host 0.0.0.0 --port 8000
```

#### REST Endpoints:
- `POST /api/analyze`: Upload APK package; returns structured JSON score, evidence list, extracted IoCs, and case ID.
- `GET /api/reports`: List historic triage cases with risk filtering (`?risk_level=High`).
- `GET /api/reports/{id}`: Retrieve detailed JSON forensic dossier by case ID.
- `GET /report/{id}`: Courtroom-ready printable HTML report with print-to-PDF button.
- `POST /api/compare`: Multi-sample cross-comparison matrix and shared infrastructure.
- `GET /api/health`: Service health and threat intelligence integration status.

#### Optional Threat Intelligence Enrichment:
Supply environment variables to activate external queries without crashing if absent:
```bash
export VT_API_KEY="your_virustotal_key"
export MOBSF_URL="http://localhost:8000"
export MOBSF_API_KEY="your_mobsf_key"
```

---

## 🧪 Automated Test Suite

Run unit and integration tests across engine, UI, and REST API:

```bash
# Run all tests
pytest tests -v

# Verify Python 3.6+ compatibility on the console tool
vermin apk_triage_console.py
```

### Verified Test Coverage:
- Synthetic demo APKs scoring targets: Banking Trojan (78), Adware (61), Benign (8).
- Rejection of non-APK ZIPs missing `AndroidManifest.xml`.
- Memory bounds and resilience against corrupt/truncated archives.
- Name collision disambiguation using `name [sha256[:6]]`.
- Real benign open-source APK (Termux release) scoring Low (<25) and verified as signed.
- Headless Streamlit `AppTest` verifying load, demo execution, and state-clearing.
- FastAPI endpoints, SQLite case persistence, and HTML report rendering.

---

## 📁 Repository Structure

```text
├── apk_triage_console.py   # Self-contained CLI (Python 3.6+ stdlib only)
├── streamlit_app.py        # Self-contained Streamlit UI (Single-file deployable)
├── apk_triage_engine.py    # Modular triage engine
├── api.py                  # FastAPI REST service
├── db.py                   # SQLite case storage
├── enrichment.py           # VirusTotal & MobSF integrations (fail-safe)
├── requirements.txt        # Optional UI and API dependencies
├── LIMITATIONS.md          # Forensic scope, limitations, & safety statement
└── tests/
    ├── test_engine.py      # Core engine unit tests
    ├── test_streamlit.py   # Streamlit AppTest UI tests
    └── test_api.py         # FastAPI REST integration tests
```

---

## 📜 Law Enforcement Disclaimer
This tool is developed strictly for defensive triage, threat identification, and evidence extraction by authorized digital forensics personnel. It adheres to strict read-only static analysis principles to maintain forensic integrity of investigated digital artifacts.
