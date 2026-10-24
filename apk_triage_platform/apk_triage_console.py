#!/usr/bin/env python3
"""
Defensive Android APK Triage Platform - Standalone Console CLI Version
Pure Python standard library only (strictly Python 3.6+ compatible).
Self-contained single file: runs in any terminal, air-gapped forensic lab, or online compiler.
Default behavior: When run with no CLI arguments, automatically executes triage on 3 built-in demo APKs.
"""

import hashlib
import io
import math
import os
import re
import struct
import sys
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Bounded memory limits to prevent zip bombs / memory exhaustion
MAX_MEMBER_SIZE = 15 * 1024 * 1024       # 15 MB max per member
MAX_TOTAL_DEX_BYTES = 50 * 1024 * 1024   # 50 MB total dex scan cap

# Android APK Signing Block Magic (v2 / v3)
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Known noise domains and prefixes to discard from IoC list
NOISE_DOMAINS = {
    "schemas.android.com", "w3.org", "www.w3.org", "apache.org", "www.apache.org",
    "example.com", "android.com", "developer.android.com", "google.com", "www.google.com",
    "gstatic.com", "xmlpull.org", "schema.org", "java.sun.com", "json.org",
    "github.com", "raw.githubusercontent.com", "maven.org", "repo1.maven.org",
}

# High abuse TLDs frequently seen in mobile C2 / phishing
HIGH_ABUSE_TLDS = {
    ".top", ".xyz", ".club", ".buzz", ".online", ".bid",
    ".loan", ".work", ".icu", ".tk", ".ml", ".ga", ".cf", ".gq"
}

# Known packer native libraries and signatures
KNOWN_PACKER_PATTERNS = [
    (r"libjiagu.*\.so", "Qihoo 360 Packer (libjiagu)"),
    (r"libsecexe.*\.so|libsecmain.*\.so", "Bangcle Packer (libsecexe)"),
    (r"libDexHelper.*\.so", "SecNeo Packer (libDexHelper)"),
    (r"libshell.*\.so", "Tencent Legu Packer (libshell)"),
    (r"libnqshield.*\.so", "NetQin Shield (libnqshield)"),
    (r"libprotectClass.*\.so", "Baidu Packer (libprotectClass)"),
    (r"libapktoolplus.*\.so", "ApktoolPlus Packer"),
    (r"libexec.*\.so|libnsa.*\.so", "AliSafe Packer"),
]

# Known third-party library prefixes
LIBRARY_PREFIXES = [
    ("androidx.", "AndroidX"),
    ("android.support.", "Android Support"),
    ("kotlin.", "Kotlin Stdlib"),
    ("kotlinx.", "Kotlin Coroutines/Extensions"),
    ("com.google.android.gms", "Google Play Services"),
    ("com.google.firebase", "Google Firebase SDK"),
    ("com.google.gson", "Google Gson"),
    ("okhttp3", "Square OkHttp"),
    ("retrofit2", "Square Retrofit"),
    ("io.reactivex", "RxJava"),
    ("com.facebook", "Facebook SDK"),
    ("com.squareup", "Square Libraries"),
    ("org.apache.commons", "Apache Commons"),
]


def compute_hashes(data: bytes) -> Dict[str, Any]:
    """Compute MD5, SHA1, and SHA256 hashes of input bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}  # type: Dict[int, int]
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def check_signature(data: bytes, namelist: List[str]) -> Dict[str, Any]:
    """
    Check APK signing info.
    Detects v1 (META-INF/*.RSA, DSA, EC) and v2/v3 ('APK Sig Block 42' magic).
    Handles Pitfall 1: Modern APKs use v2/v3 signing without .RSA files.
    """
    has_v1 = any(
        n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
        for n in namelist
    )
    has_v2_v3 = APK_SIG_BLOCK_MAGIC in data

    if has_v1 and has_v2_v3:
        status = "signed (v1 + v2/v3)"
        is_signed = True
    elif has_v2_v3:
        status = "signed (v2/v3)"
        is_signed = True
    elif has_v1:
        status = "signed (v1)"
        is_signed = True
    else:
        status = "unsigned"
        is_signed = False

    return {
        "status": status,
        "is_signed": is_signed,
        "has_v1": has_v1,
        "has_v2_v3": has_v2_v3,
    }


def parse_manifest_permissions(manifest_bytes: bytes) -> List[str]:
    """
    Extract Android permissions by parsing manifest bytes as latin-1 AND
    UTF-16LE at byte offsets 0 and 1 using regex android.permission.[A-Z0-9_]+
    """
    extracted = set()
    pattern = re.compile(r"android\.permission\.([A-Z0-9_]+)")

    try:
        text_latin = manifest_bytes.decode("latin-1", errors="ignore")
        extracted.update(pattern.findall(text_latin))
    except Exception:
        pass

    try:
        text_utf16_0 = manifest_bytes.decode("utf-16le", errors="ignore")
        extracted.update(pattern.findall(text_utf16_0))
    except Exception:
        pass

    try:
        if len(manifest_bytes) > 1:
            text_utf16_1 = manifest_bytes[1:].decode("utf-16le", errors="ignore")
            extracted.update(pattern.findall(text_utf16_1))
    except Exception:
        pass

    return sorted(list(extracted))


def extract_dex_strings(z: zipfile.ZipFile, dex_members: List[str]) -> Tuple[Set[str], Dict[str, Any]]:
    """
    Extract strings and indicators from classes*.dex files with bounded memory reads.
    Handles Pitfall 2: Match precise descriptors like
    'Landroid/accessibilityservice/AccessibilityService;' and
    'Landroid/app/admin/DeviceAdminReceiver;'.
    """
    all_strings = set()
    total_dex_read = 0
    dex_stats = {
        "dex_files_count": len(dex_members),
        "total_dex_bytes": 0,
        "classes_count": 0,
        "obfuscated_classes_count": 0,
    }

    obfuscated_pattern = re.compile(r"^L([a-z]{1,2}(?:/[a-z]{1,2})*);$")

    for member_name in dex_members:
        if total_dex_read >= MAX_TOTAL_DEX_BYTES:
            break
        try:
            with z.open(member_name) as f:
                content = f.read(MAX_MEMBER_SIZE)
                total_dex_read += len(content)
                dex_stats["total_dex_bytes"] += len(content)

                raw_matches = re.findall(b"[\x20-\x7e]{4,}", content)
                for rm in raw_matches[:50000]:
                    try:
                        s = rm.decode("ascii", errors="ignore").strip()
                        if s:
                            all_strings.add(s)
                            if s.startswith("L") and s.endswith(";"):
                                dex_stats["classes_count"] += 1
                                if obfuscated_pattern.match(s):
                                    dex_stats["obfuscated_classes_count"] += 1
                    except Exception:
                        pass
        except Exception:
            continue

    return all_strings, dex_stats


def extract_iocs_and_urls(all_strings: Set[str]) -> Dict[str, Any]:
    """Extract URLs, domains, IPs, and C2 indicators, filtering out noise."""
    urls = set()
    domains = set()
    ips = set()
    telegram_c2 = []
    firebase_c2 = []
    high_abuse_domains = []
    cleartext_http = []

    url_pattern = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>]*)?")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_extract = re.compile(r"https?://([a-zA-Z0-9.\-_]+)")

    for s in all_strings:
        if len(s) > 300:
            continue

        found_urls = url_pattern.findall(s)
        for u in found_urls:
            dm_match = domain_extract.match(u)
            if dm_match:
                dom = dm_match.group(1).lower()
                if any(dom == nd or dom.endswith("." + nd) for nd in NOISE_DOMAINS):
                    continue
                domains.add(dom)
                urls.add(u)

                if u.startswith("http://"):
                    cleartext_http.append(u)

                if "api.telegram.org" in dom or dom == "t.me" or dom.endswith(".t.me"):
                    telegram_c2.append(u)
                if "firebaseio.com" in dom or "firebasestorage.googleapis.com" in u:
                    firebase_c2.append(u)
                if any(dom.endswith(tld) for tld in HIGH_ABUSE_TLDS):
                    high_abuse_domains.append(dom)

        found_ips = ip_pattern.findall(s)
        for ip in found_ips:
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    nums = [int(p) for p in parts]
                    if all(0 <= n <= 255 for n in nums):
                        if nums[0] in (0, 10, 127, 255):
                            continue
                        if nums[0] == 192 and nums[1] == 168:
                            continue
                        if nums[0] == 172 and 16 <= nums[1] <= 31:
                            continue
                        ips.add(ip)
                except ValueError:
                    pass

    return {
        "urls": sorted(list(urls))[:100],
        "domains": sorted(list(domains))[:100],
        "ips": sorted(list(ips))[:100],
        "telegram_c2": sorted(list(set(telegram_c2))),
        "firebase_c2": sorted(list(set(firebase_c2))),
        "high_abuse_domains": sorted(list(set(high_abuse_domains))),
        "cleartext_http": sorted(list(set(cleartext_http)))[:50],
    }


def scan_assets_and_payloads(z: zipfile.ZipFile, namelist: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Inspect assets, res, and res/raw for high entropy and hidden executable payloads."""
    high_entropy_assets = []
    hidden_payloads = []
    media_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp3", ".ogg", ".wav", ".aac", ".ttf"}

    for name in namelist:
        is_asset_or_raw = name.startswith("assets/") or name.startswith("res/raw/")

        if is_asset_or_raw or name.startswith("res/"):
            try:
                with z.open(name) as f:
                    header = f.read(16)
                    if header:
                        if header.startswith(b"dex\n"):
                            hidden_payloads.append({
                                "file": name,
                                "type": "Hidden DEX executable",
                                "magic": header[:8].hex()
                            })
                        elif header.startswith(b"PK\x03\x04") and not name.endswith(".zip") and not name.endswith(".apk"):
                            hidden_payloads.append({
                                "file": name,
                                "type": "Hidden ZIP/APK archive",
                                "magic": header[:4].hex()
                            })
                        elif header.startswith(b"\x7fELF") and not name.startswith("lib/"):
                            hidden_payloads.append({
                                "file": name,
                                "type": "Hidden native ELF binary",
                                "magic": header[:4].hex()
                            })
            except Exception:
                pass

        if is_asset_or_raw:
            _, ext = os.path.splitext(name.lower())
            if ext not in media_extensions:
                try:
                    info = z.getinfo(name)
                    if info.file_size > 512:
                        with z.open(name) as f:
                            sample_bytes = f.read(256 * 1024)
                            entropy = calculate_entropy(sample_bytes)
                            if entropy > 7.5:
                                high_entropy_assets.append({
                                    "file": name,
                                    "size": info.file_size,
                                    "entropy": entropy
                                })
                except Exception:
                    pass

    return high_entropy_assets, hidden_payloads


def detect_packers(namelist: List[str], all_strings: Set[str]) -> List[str]:
    """Detect presence of packer / protector native libraries or identifiers."""
    detected = set()
    for item in namelist:
        base = os.path.basename(item)
        for pattern, label in KNOWN_PACKER_PATTERNS:
            if re.search(pattern, base, re.IGNORECASE):
                detected.add(label)

    for s in all_strings:
        for pattern, label in KNOWN_PACKER_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                detected.add(label)

    return sorted(list(detected))


def detect_libraries(all_strings: Set[str], namelist: List[str]) -> List[str]:
    """Identify third-party libraries present in APK."""
    detected = set()
    for prefix, lib_name in LIBRARY_PREFIXES:
        slash_prefix = prefix.replace(".", "/")
        for s in all_strings:
            if s.startswith(prefix) or s.startswith(slash_prefix) or s.startswith("L" + slash_prefix):
                detected.add(lib_name)
                break
    return sorted(list(detected))


def score_apk(f: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score = sum of capped categories, every point linked to evidence.
    Categories:
      - Permissions (cap 25)
      - Evasion (cap 30)
      - Behaviour (cap 25)
      - Network (cap 10)
      - Integrity (cap 10)
    Total: 0-100. Levels: High >= 50, Medium >= 25, else Low.
    """
    if not f.get("valid", False):
        return {
            "total_score": 0,
            "risk_level": "Invalid",
            "categories": {},
            "evidence": [],
        }

    permissions = set(f.get("permissions", []))
    dex_strings = f.get("dex_strings", set())
    iocs = f.get("iocs", {})
    high_entropy_assets = f.get("high_entropy_assets", [])
    hidden_payloads = f.get("hidden_payloads", [])
    packers = f.get("packers", [])
    obf_ratio = f.get("obfuscation_ratio", 0.0)
    signing = f.get("signing", {})

    evidence_list = []  # type: List[Dict[str, Any]]

    # 1. Permissions (Cap 25)
    perm_score = 0
    perm_evidence = []  # type: List[Dict[str, Any]]
    perm_weights = {
        "READ_SMS": 5, "RECEIVE_SMS": 5, "SEND_SMS": 5,
        "BIND_ACCESSIBILITY_SERVICE": 6, "BIND_DEVICE_ADMIN": 5,
        "SYSTEM_ALERT_WINDOW": 4, "REQUEST_INSTALL_PACKAGES": 4,
        "READ_CONTACTS": 3, "RECORD_AUDIO": 3, "READ_CALL_LOG": 3,
        "CAMERA": 2, "CALL_PHONE": 2, "PROCESS_OUTGOING_CALLS": 2,
        "ACCESS_FINE_LOCATION": 2, "INSTALL_PACKAGES": 2, "MANAGE_EXTERNAL_STORAGE": 2,
        "ACCESS_COARSE_LOCATION": 1, "WRITE_EXTERNAL_STORAGE": 1,
        "READ_EXTERNAL_STORAGE": 1, "RECEIVE_BOOT_COMPLETED": 1,
        "READ_PHONE_STATE": 1, "GET_ACCOUNTS": 1,
    }

    for p in permissions:
        pts = perm_weights.get(p, 0)
        if pts > 0:
            perm_score += pts
            perm_evidence.append({
                "category": "Permissions",
                "points": pts,
                "rule": f"Permission: android.permission.{p}",
                "evidence": f"android.permission.{p}",
            })

    capped_perm_score = min(25, perm_score)
    evidence_list.extend(perm_evidence)

    # 2. Evasion (Cap 30)
    evasion_score = 0
    evasion_evidence = []  # type: List[Dict[str, Any]]

    if any("DexClassLoader" in s for s in dex_strings):
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Dynamic code loading via DexClassLoader",
            "evidence": "dalvik.system.DexClassLoader reference in DEX strings",
        })

    if any("InMemoryDexClassLoader" in s for s in dex_strings):
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "In-memory dynamic DEX execution",
            "evidence": "dalvik.system.InMemoryDexClassLoader reference in DEX strings",
        })

    if packers:
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Commercial/Malicious APK Packer detected",
            "evidence": f"Packer indicators: {', '.join(packers)}",
        })

    if hidden_payloads:
        pts = 10
        evasion_score += pts
        items_desc = ", ".join(f"{h['file']} ({h['type']})" for h in hidden_payloads[:3])
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Hidden executable payload inside assets/resources",
            "evidence": f"Embedded binaries: {items_desc}",
        })

    anti_debug_indicators = ["isDebuggerConnected", "tracerpid", "Ptrace", "/proc/self/status", "p_traced"]
    matched_anti_debug = [i for i in anti_debug_indicators if any(i.lower() in s.lower() for s in dex_strings)]
    if matched_anti_debug:
        pts = 8
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Anti-debugging check detected",
            "evidence": f"Debugger detection strings: {', '.join(matched_anti_debug)}",
        })

    emulator_indicators = ["goldfish", "ranchu", "generic_x86", "vbox86", "nox", "Genymotion", "ro.kernel.qemu"]
    matched_emu = [e for e in emulator_indicators if any(e.lower() in s.lower() for s in dex_strings)]
    if matched_emu:
        pts = 8
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Sandbox / Emulator detection check",
            "evidence": f"Emulator artifacts: {', '.join(matched_emu)}",
        })

    if high_entropy_assets:
        pts = 8
        evasion_score += pts
        top_asset = high_entropy_assets[0]
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Encrypted or packed payload in assets (Entropy > 7.5)",
            "evidence": f"Asset {top_asset['file']} has entropy {top_asset['entropy']}",
        })

    if obf_ratio > 0.30:
        pts = 6
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "High class-name identifier obfuscation (> 30%)",
            "evidence": f"Obfuscated class ratio: {round(obf_ratio * 100, 1)}%",
        })

    capped_evasion_score = min(30, evasion_score)
    evidence_list.extend(evasion_evidence)

    # 3. Behaviour (Cap 25)
    behaviour_score = 0
    behaviour_evidence = []  # type: List[Dict[str, Any]]

    sms_apis = ["sendTextMessage", "sendMultipartTextMessage", "getAllMessagesFromPdu", "content://sms/"]
    matched_sms = [a for a in sms_apis if any(a in s for s in dex_strings)]
    if matched_sms or ("SEND_SMS" in permissions and "RECEIVE_SMS" in permissions):
        pts = 7
        behaviour_score += pts
        ev = f"SMS manipulation strings/permissions: {', '.join(matched_sms) if matched_sms else 'SEND/RECEIVE SMS permissions'}"
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "SMS interception or background transmission capability",
            "evidence": ev,
        })

    if "Landroid/accessibilityservice/AccessibilityService;" in dex_strings or "BIND_ACCESSIBILITY_SERVICE" in permissions:
        pts = 9
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Accessibility Service abuse (keylogging/UI injection)",
            "evidence": "Descriptor: Landroid/accessibilityservice/AccessibilityService; or BIND_ACCESSIBILITY_SERVICE",
        })

    if "Landroid/app/admin/DeviceAdminReceiver;" in dex_strings or "BIND_DEVICE_ADMIN" in permissions:
        pts = 6
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Device Administrator privileges capability",
            "evidence": "Descriptor: Landroid/app/admin/DeviceAdminReceiver; or BIND_DEVICE_ADMIN",
        })

    overlay_apis = ["TYPE_APPLICATION_OVERLAY", "Settings.canDrawOverlays"]
    if any(a in s for a in overlay_apis for s in dex_strings) or "SYSTEM_ALERT_WINDOW" in permissions:
        pts = 6
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Screen Overlay / Phishing Window injection",
            "evidence": "SYSTEM_ALERT_WINDOW permission or overlay window API",
        })

    audio_apis = ["AudioRecord", "MediaRecorder"]
    if any(a in s for a in audio_apis for s in dex_strings) or "RECORD_AUDIO" in permissions:
        pts = 5
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Surreptitious microphone / audio recording capability",
            "evidence": "RECORD_AUDIO permission or AudioRecord API call",
        })

    if any("ContactsContract" in s for s in dex_strings) or "READ_CONTACTS" in permissions:
        pts = 4
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Address book / contacts harvesting capability",
            "evidence": "READ_CONTACTS permission or ContactsContract API call",
        })

    crypto_imei_apis = ["Cipher.getInstance", "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber"]
    matched_crypto = [c for c in crypto_imei_apis if any(c in s for s in dex_strings)]
    if matched_crypto:
        pts = 3
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Device IMEI / Hardware identifier harvesting or custom cipher",
            "evidence": f"Identifier APIs: {', '.join(matched_crypto)}",
        })

    capped_behaviour_score = min(25, behaviour_score)
    evidence_list.extend(behaviour_evidence)

    # 4. Network (Cap 10)
    network_score = 0
    network_evidence = []  # type: List[Dict[str, Any]]

    if iocs.get("telegram_c2") or iocs.get("firebase_c2"):
        pts = 8
        network_score += pts
        c2_samples = (iocs.get("telegram_c2", []) + iocs.get("firebase_c2", []))[:2]
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Telegram or Firebase Command & Control infrastructure",
            "evidence": f"C2 Endpoint: {', '.join(c2_samples)}",
        })

    if iocs.get("ips"):
        pts = 3
        network_score += pts
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Hard-coded public IPv4 address in binary",
            "evidence": f"IP addresses: {', '.join(iocs['ips'][:3])}",
        })

    if iocs.get("high_abuse_domains"):
        pts = 4
        network_score += pts
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Suspicious / High-abuse Top-Level Domain (TLD)",
            "evidence": f"Domains: {', '.join(iocs['high_abuse_domains'][:3])}",
        })

    if iocs.get("cleartext_http"):
        pts = 1
        network_score += pts
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Unencrypted cleartext HTTP communication",
            "evidence": f"Cleartext URL: {iocs['cleartext_http'][0]}",
        })

    capped_network_score = min(10, network_score)
    evidence_list.extend(network_evidence)

    # 5. Integrity (Cap 10)
    integrity_score = 0
    integrity_evidence = []  # type: List[Dict[str, Any]]

    if not signing.get("is_signed", True):
        pts = 6
        integrity_score += pts
        integrity_evidence.append({
            "category": "Integrity",
            "points": pts,
            "rule": "Unsigned APK (Tampered or unverified developer certificate)",
            "evidence": "No v1 (META-INF/*.RSA) or v2/v3 (APK Sig Block 42) signature found",
        })

    capped_integrity_score = min(10, integrity_score)
    evidence_list.extend(integrity_evidence)

    # Total Score
    total_score = (
        capped_perm_score +
        capped_evasion_score +
        capped_behaviour_score +
        capped_network_score +
        capped_integrity_score
    )

    if total_score >= 50:
        risk_level = "High"
    elif total_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "categories": {
            "permissions": {"score": capped_perm_score, "raw": perm_score, "cap": 25},
            "evasion": {"score": capped_evasion_score, "raw": evasion_score, "cap": 30},
            "behaviour": {"score": capped_behaviour_score, "raw": behaviour_score, "cap": 25},
            "network": {"score": capped_network_score, "raw": network_score, "cap": 10},
            "integrity": {"score": capped_integrity_score, "raw": integrity_score, "cap": 10},
        },
        "evidence": evidence_list,
    }


def analyze_apk(data: bytes, name: str = "sample.apk") -> Dict[str, Any]:
    """Main triage analysis function with safe bounded reads and clear error handling."""
    hashes = compute_hashes(data)

    if not data.startswith(b"PK\x03\x04"):
        return {
            "valid": False,
            "error": "File is not a valid ZIP/APK archive (missing PK zip magic)",
            "name": name,
            "hashes": hashes,
            "scoring": {"total_score": 0, "risk_level": "Invalid", "categories": {}, "evidence": []},
        }

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, Exception) as e:
        return {
            "valid": False,
            "error": f"Corrupt or invalid ZIP archive: {str(e)}",
            "name": name,
            "hashes": hashes,
            "scoring": {"total_score": 0, "risk_level": "Invalid", "categories": {}, "evidence": []},
        }

    namelist = zf.namelist()

    if "AndroidManifest.xml" not in namelist:
        return {
            "valid": False,
            "error": "Rejected: Archive does not contain AndroidManifest.xml (not an Android APK)",
            "name": name,
            "hashes": hashes,
            "scoring": {"total_score": 0, "risk_level": "Invalid", "categories": {}, "evidence": []},
        }

    try:
        with zf.open("AndroidManifest.xml") as mf:
            manifest_bytes = mf.read(MAX_MEMBER_SIZE)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Could not read AndroidManifest.xml: {str(e)}",
            "name": name,
            "hashes": hashes,
            "scoring": {"total_score": 0, "risk_level": "Invalid", "categories": {}, "evidence": []},
        }

    permissions = parse_manifest_permissions(manifest_bytes)
    signing = check_signature(data, namelist)
    dex_members = [n for n in namelist if n.endswith(".dex")]
    dex_strings, dex_stats = extract_dex_strings(zf, dex_members)
    iocs = extract_iocs_and_urls(dex_strings)
    high_entropy_assets, hidden_payloads = scan_assets_and_payloads(zf, namelist)
    packers = detect_packers(namelist, dex_strings)
    total_classes = dex_stats.get("classes_count", 0)
    obf_classes = dex_stats.get("obfuscated_classes_count", 0)
    obf_ratio = (obf_classes / total_classes) if total_classes > 0 else 0.0
    libraries = detect_libraries(dex_strings, namelist)

    extracted = {
        "valid": True,
        "name": name,
        "hashes": hashes,
        "signing": signing,
        "permissions": permissions,
        "dex_stats": dex_stats,
        "dex_strings": dex_strings,
        "iocs": iocs,
        "high_entropy_assets": high_entropy_assets,
        "hidden_payloads": hidden_payloads,
        "packers": packers,
        "obfuscation_ratio": round(obf_ratio, 3),
        "libraries": libraries,
        "file_count": len(namelist),
    }

    score_result = score_apk(extracted)
    extracted["scoring"] = score_result
    return extracted


def _build_synthetic_apk(
    permissions: List[str],
    dex_strings: List[str],
    assets: Optional[Dict[str, bytes]] = None,
    sign_v1: bool = True,
    sign_v2: bool = True,
) -> bytes:
    """Helper to assemble a valid zip-based APK with AndroidManifest and classes.dex in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest_text = '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="org.cyberpolice.triage">\n'
        for p in permissions:
            manifest_text += f'  <uses-permission android:name="android.permission.{p}" />\n'
        manifest_text += '</manifest>\n'

        manifest_bytes = manifest_text.encode("latin-1") + b"\x00\x00" + manifest_text.encode("utf-16le")
        z.writestr("AndroidManifest.xml", manifest_bytes)

        dex_buf = io.BytesIO()
        dex_buf.write(b"dex\n035\x00")
        dex_buf.write(b"\x00" * 32)
        for s in dex_strings:
            dex_buf.write(s.encode("utf-8") + b"\x00")
        z.writestr("classes.dex", dex_buf.getvalue())

        if assets:
            for path, data in assets.items():
                z.writestr(path, data)

        if sign_v1:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: 1.0\n")
            z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
            z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x0a" + b"\xaa" * 128)

    apk_bytes = buf.getvalue()

    if sign_v2:
        sig_block = b"APK-SIG-BLOCK-DATA" + b"\x00" * 16 + struct.pack("<Q", 32) + APK_SIG_BLOCK_MAGIC
        apk_bytes = apk_bytes + sig_block

    return apk_bytes


def generate_demo_apks() -> Dict[str, bytes]:
    """Generate 3 harmless synthetic demo APKs matching hackathon triage profiles (78 / 61 / 8)."""
    # 1. Demo 1: High-Risk Banking Trojan / Spyware (Target Score: 78)
    demo1_perms = [
        "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES"
    ]
    demo1_strings = [
        "Landroid/accessibilityservice/AccessibilityService;",
        "dalvik.system.DexClassLoader",
        "android.os.Debug.isDebuggerConnected", "tracerpid",
        "goldfish", "generic_x86",
        "sendTextMessage", "getDeviceId", "Cipher.getInstance",
        "https://api.telegram.org/bot123456/sendMessage",
    ]
    demo1_apk = _build_synthetic_apk(demo1_perms, demo1_strings, sign_v1=False, sign_v2=True)

    # 2. Demo 2: Suspicious Adware / Harvester (Target Score: 61)
    demo2_perms = [
        "READ_CONTACTS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "CAMERA"
    ]
    high_entropy_bytes = bytes([i % 256 for i in range(2048)])
    demo2_assets = {"assets/payload.dat": high_entropy_bytes}
    obf_classes = [f"La/{chr(97 + i)};" for i in range(15)]
    normal_classes = [f"Lcom/example/feature/Service{i};" for i in range(15)]
    demo2_strings = obf_classes + normal_classes + [
        "TYPE_APPLICATION_OVERLAY", "AudioRecord", "ContactsContract", "getImei",
        "https://tracker.suspicious-domain.xyz/ping", "198.51.100.42",
    ]
    demo2_apk = _build_synthetic_apk(demo2_perms, demo2_strings, assets=demo2_assets, sign_v1=False, sign_v2=False)

    # 3. Demo 3: Clean Benign Utility (Target Score: 8)
    demo3_perms = [
        "CAMERA", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED", "READ_EXTERNAL_STORAGE"
    ]
    demo3_strings = [
        "Lcom/example/calculator/MainActivity;",
        "Lcom/example/calculator/Utils;",
        "http://insecure-cdn.calculatorapp.org/help",
    ]
    demo3_apk = _build_synthetic_apk(demo3_perms, demo3_strings, sign_v1=True, sign_v2=False)

    return {
        "banking_trojan_demo.apk": demo1_apk,
        "suspicious_adware_demo.apk": demo2_apk,
        "benign_calculator_demo.apk": demo3_apk,
    }


def compare_apks(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare multiple analyzed APKs with collision-safe labels 'name [sha256[:6]]'."""
    labeled_results = []
    matrix = []
    shared_domains = {}  # type: Dict[str, List[str]]

    for r in results:
        name = r.get("name", "unknown.apk")
        sha = r.get("hashes", {}).get("sha256", "000000")[:6]
        label = f"{name} [{sha}]"
        labeled_results.append((label, r))

    for label, r in labeled_results:
        sc = r.get("scoring", {})
        iocs = r.get("iocs", {})
        doms = set(iocs.get("domains", []))
        for d in doms:
            shared_domains.setdefault(d, []).append(label)

        matrix.append({
            "label": label,
            "risk_level": sc.get("risk_level", "Unknown"),
            "score": sc.get("total_score", 0),
            "permissions_count": len(r.get("permissions", [])),
            "urls_count": len(iocs.get("urls", [])),
            "ips_count": len(iocs.get("ips", [])),
            "is_signed": r.get("signing", {}).get("is_signed", False),
            "signing_status": r.get("signing", {}).get("status", "Unknown"),
            "packers": ", ".join(r.get("packers", [])) or "None",
        })

    shared_infrastructure = {d: apks for d, apks in shared_domains.items() if len(apks) > 1}

    return {
        "matrix": matrix,
        "shared_infrastructure": shared_infrastructure,
    }


def print_banner() -> None:
    """Print digital forensics triage banner."""
    print("=" * 78)
    print("  BIHAR POLICE CYBER DEFENSIVE FORENSICS - APK TRIAGE PLATFORM")
    print("  Static Analysis & Risk Scoring Engine (Pure Python Stdlib)")
    print("=" * 78)


def format_category_bar(score: int, cap: int) -> str:
    """Render a text-based progress bar for score category."""
    pct = score / cap if cap > 0 else 0
    filled = int(round(pct * 15))
    bar = "[" + "#" * filled + "-" * (15 - filled) + "]"
    return f"{bar} {score:2d}/{cap:2d}"


def display_triage_summary(result: Dict[str, Any]) -> None:
    """Display forensic summary for a single analyzed APK."""
    name = result.get("name", "Unknown")
    valid = result.get("valid", False)

    if not valid:
        print("\n" + "-" * 78)
        print(f"[-] FILE: {name}")
        print(f"[!] STATUS: REJECTED / INVALID")
        print(f"[!] REASON: {result.get('error', 'Unknown parsing error')}")
        print("-" * 78)
        return

    hashes = result.get("hashes", {})
    signing = result.get("signing", {})
    sc = result.get("scoring", {})
    score_val = sc.get("total_score", 0)
    risk = sc.get("risk_level", "Unknown")
    cats = sc.get("categories", {})
    iocs = result.get("iocs", {})
    evidence = sc.get("evidence", [])

    print("\n" + "=" * 78)
    print(f"[*] SAMPLE: {name}  [{hashes.get('size', 0):,} bytes]")
    print(f"[*] SHA256: {hashes.get('sha256')}")
    print(f"[*] SIGNING: {signing.get('status')}")
    print(f"[*] OVERALL RISK: {score_val}/100 [{risk.upper()}]")
    print("-" * 78)

    print("RISK SCORE BREAKDOWN:")
    p = cats.get("permissions", {})
    e = cats.get("evasion", {})
    b = cats.get("behaviour", {})
    n = cats.get("network", {})
    i = cats.get("integrity", {})

    print(f"  Permissions (cap 25): {format_category_bar(p.get('score', 0), p.get('cap', 25))}")
    print(f"  Evasion     (cap 30): {format_category_bar(e.get('score', 0), e.get('cap', 30))}")
    print(f"  Behaviour   (cap 25): {format_category_bar(b.get('score', 0), b.get('cap', 25))}")
    print(f"  Network     (cap 10): {format_category_bar(n.get('score', 0), n.get('cap', 10))}")
    print(f"  Integrity   (cap 10): {format_category_bar(i.get('score', 0), i.get('cap', 10))}")

    print("\nTOP EVIDENCE LINKED TO SCORE:")
    for ev in evidence[:10]:
        print(f"  [+{ev.get('points')} pts] [{ev.get('category')}] {ev.get('rule')}")
        print(f"          Evidence: {ev.get('evidence')}")

    print("\nEXTRACTED IOCs & TELEMETRY:")
    if iocs.get("telegram_c2"):
        print(f"  [!] Telegram C2 Endpoints : {', '.join(iocs['telegram_c2'])}")
    if iocs.get("firebase_c2"):
        print(f"  [!] Firebase C2 Endpoints : {', '.join(iocs['firebase_c2'])}")
    if iocs.get("high_abuse_domains"):
        print(f"  [!] High-Abuse Domains    : {', '.join(iocs['high_abuse_domains'])}")
    if iocs.get("ips"):
        print(f"  [*] Hard-coded IPv4s      : {', '.join(iocs['ips'][:5])}")
    if iocs.get("urls"):
        print(f"  [*] Extracted URLs ({len(iocs['urls'])})   : {', '.join(iocs['urls'][:3])} ...")

    packers = result.get("packers", [])
    if packers:
        print(f"  [!] Native Packer Identified: {', '.join(packers)}")

    hidden = result.get("hidden_payloads", [])
    if hidden:
        for h in hidden:
            print(f"  [!] Hidden Executable Payload: {h.get('file')} ({h.get('type')})")

    high_ent = result.get("high_entropy_assets", [])
    if high_ent:
        for he in high_ent:
            print(f"  [!] High Entropy Asset       : {he.get('file')} (Entropy: {he.get('entropy')})")

    print("=" * 78)


def display_comparison_table(results: List[Dict[str, Any]]) -> None:
    """Print cross-sample comparison table for multi-file analysis."""
    valid_results = [r for r in results if r.get("valid", False)]
    if len(valid_results) < 2:
        return

    comp = compare_apks(valid_results)
    matrix = comp.get("matrix", [])

    print("\n" + "=" * 78)
    print("  MULTI-APK COMPARISON MATRIX")
    print("=" * 78)
    header = f"{'Sample Label':<35} | {'Score':<6} | {'Risk':<7} | {'Perms':<5} | {'URLs':<5} | {'Signed'}"
    print(header)
    print("-" * 78)
    for m in matrix:
        signed_txt = "Yes" if m.get("is_signed") else "NO"
        line = f"{m.get('label', '')[:35]:<35} | {m.get('score', 0):<6} | {m.get('risk_level', ''):<7} | {m.get('permissions_count', 0):<5} | {m.get('urls_count', 0):<5} | {signed_txt}"
        print(line)

    shared_infra = comp.get("shared_infrastructure", {})
    if shared_infra:
        print("\n[!] SHARED INFRASTRUCTURE / COMMON C2 DETECTED:")
        for dom, apks in shared_infra.items():
            print(f"  - Domain '{dom}' shared by: {', '.join(apks)}")
    print("=" * 78)


def main() -> None:
    """Main CLI entrypoint."""
    print_banner()
    args = sys.argv[1:]

    if not args:
        print("\n[i] No input files provided. Running triage on built-in synthetic demo APKs...\n")
        demos = generate_demo_apks()
        results = []
        for name, data in demos.items():
            res = analyze_apk(data, name)
            results.append(res)
            display_triage_summary(res)

        display_comparison_table(results)
        return

    results = []
    for filepath in args:
        if not os.path.isfile(filepath):
            print(f"[!] Warning: File not found '{filepath}'. Skipping.")
            continue
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            filename = os.path.basename(filepath)
            res = analyze_apk(data, filename)
            results.append(res)
            display_triage_summary(res)
        except Exception as e:
            print(f"[-] Error reading file '{filepath}': {str(e)}")

    if len(results) > 1:
        display_comparison_table(results)


if __name__ == "__main__":
    main()
