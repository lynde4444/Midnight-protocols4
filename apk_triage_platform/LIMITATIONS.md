# Platform Limitations & Forensic Boundaries
**Defensive Android APK Triage**

This document provides a realistic and honest appraisal of the technical boundaries, threat coverage, and operational constraints of this defensive static triage platform.

---

### 1. Dynamic Analysis & Runtime Evasion Not Covered
* **Static Inspection Only**: The platform operates strictly via in-memory static extraction (ZIP directory traversal, binary manifest parsing, DEX bytecode string scanning, and file entropy). It does **not** emulate, execute, or dynamically inspect runtime code execution.
* **Runtime Decryption**: Advanced malware families employing multi-stage stagers, custom native runtime decryptors (e.g., packers that decrypt secondary DEX files in memory via custom JNI calls), or dynamic reflection without hardcoded class names cannot be deeply inspected by static string analysis alone.
* **Anti-Emulation and Environment Probes**: While detection rules look for strings indicating emulator or sandbox checks (`tracerpid`, `goldfish`, etc.), the actual behavior when executing on real Android devices or emulators cannot be verified without sandboxed dynamic instrumentation (e.g., Frida or Cuckoo-Droid).

### 2. Real-World Malware Accuracy & False Positives / Negatives
* **Rule-Based Heuristics**: The scoring engine relies on deterministic point allocations across Permissions, Evasion, Behaviour, Network, and Integrity. While designed to reliably surface banking trojans, spyware, and stalkerware, heuristics can yield false positives on heavily packed commercial applications (e.g., legitimate games or banking apps using commercial protectors like Qihoo 360 or SecNeo).
* **Novel Evasion Techniques**: Novel obfuscation methods (such as control-flow flattening, string encryption via XOR/AES without plaintext literals, or steganography inside images) may score lower than their true threat level if they do not declare excessive dangerous permissions.
* **Triage vs. Deep Forensics**: This platform is designed for **rapid initial field triage** (0–100 risk prioritization in seconds) to guide investigators on whether to impound a device or perform deep decompilation, rather than serving as a replacement for manual reverse-engineering tools (e.g., JADX, Ghidra).

### 3. Public-Hosting Safety & Infrastructure Hardening
* **Local / Air-Gapped Orientation**: The system is designed for air-gapped forensic lab workstations and secure internal law-enforcement networks.
* **Public-Facing Multi-Tenancy**: If hosted on a public server, running arbitrary untrusted file parsing requires OS-level virtualization or disposable microVM sandboxing (e.g., gVisor, Firecracker). While this engine enforces strict bounded memory reads (`z.open().read(limit)`) and never extracts files to disk by archive path to thwart ZipSlip/ZipBombs, public deployments must enforce strict reverse-proxy rate limiting, authentication, and worker container timeouts.
* **Third-Party API Secrets**: External enrichment lookups (VirusTotal, MobSF) are strictly optional and depend on investigator-provided API keys. Public-facing instances should never expose these keys to client-side browsers.
