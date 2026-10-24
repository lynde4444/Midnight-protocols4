"""
Defensive Android APK Triage Platform - Core Analysis Engine
Pure Python standard library implementation (3.6+ compatible).
Static analysis only: never executes, emulates, or installs hostile code.
"""

import hashlib
import io
import math
import os
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

# Bounded memory limits to prevent zip bombs / memory exhaustion
MAX_MEMBER_SIZE = 15 * 1024 * 1024  # 15 MB max per decompressed member
MAX_TOTAL_DEX_BYTES = 50 * 1024 * 1024  # 50 MB total dex scan cap
MAX_STRING_SCAN_BYTES = 5 * 1024 * 1024  # 5 MB per individual string search

# Android APK Signing Block Magic (v2 / v3)
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

# Known noise domains and prefixes to discard from IoC list
NOISE_DOMAINS = {
    "schemas.android.com",
    "w3.org",
    "www.w3.org",
    "apache.org",
    "www.apache.org",
    "example.com",
    "android.com",
    "developer.android.com",
    "google.com",
    "www.google.com",
    "gstatic.com",
    "xmlpull.org",
    "schema.org",
    "java.sun.com",
    "json.org",
    "github.com",
    "raw.githubusercontent.com",
    "maven.org",
    "repo1.maven.org",
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


class ApkParseError(Exception):
    """Raised when an APK file is malformed, corrupt, or not an Android package."""
    pass


def compute_hashes(data: bytes) -> Dict[str, str]:
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
    counts = {}
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
    Addresses Known Pitfall 1: Modern APKs use v2/v3 signing without .RSA files.
    """
    has_v1 = any(
        n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
        for n in namelist
    )
    # Scan for APK Signing Block 42 magic bytes in raw bytes
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

    # 1. Latin-1 / ASCII stream
    try:
        text_latin = manifest_bytes.decode("latin-1", errors="ignore")
        extracted.update(pattern.findall(text_latin))
    except Exception:
        pass

    # 2. UTF-16LE at offset 0
    try:
        text_utf16_0 = manifest_bytes.decode("utf-16le", errors="ignore")
        extracted.update(pattern.findall(text_utf16_0))
    except Exception:
        pass

    # 3. UTF-16LE at offset 1 (odd alignment in binary XML string pool)
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
    Addresses Known Pitfall 2: Match precise descriptors like
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

    class_pattern = re.compile(r"L([a-zA-Z0-9_$]+(?:/[a-zA-Z0-9_$]+)*);")
    obfuscated_pattern = re.compile(r"^L([a-z]{1,2}(?:/[a-z]{1,2})*);$")

    for member_name in dex_members:
        if total_dex_read >= MAX_TOTAL_DEX_BYTES:
            break
        try:
            with z.open(member_name) as f:
                content = f.read(MAX_MEMBER_SIZE)
                total_dex_read += len(content)
                dex_stats["total_dex_bytes"] += len(content)

                # Search printable ASCII substrings (length >= 4)
                raw_matches = re.findall(b"[\x20-\x7e]{4,}", content)
                for rm in raw_matches[:50000]:  # Cap to prevent unbounded memory
                    try:
                        s = rm.decode("ascii", errors="ignore").strip()
                        if s:
                            all_strings.add(s)
                            # Check class descriptor
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

    # Regex patterns
    url_pattern = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s\"'<>]*)?")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_extract = re.compile(r"https?://([a-zA-Z0-9.\-_]+)")

    for s in all_strings:
        if len(s) > 300:
            continue  # Discard giant strings

        # URL matching
        found_urls = url_pattern.findall(s)
        for u in found_urls:
            # Check noise
            dm_match = domain_extract.match(u)
            if dm_match:
                dom = dm_match.group(1).lower()
                if any(dom == nd or dom.endswith("." + nd) for nd in NOISE_DOMAINS):
                    continue
                domains.add(dom)
                urls.add(u)

                if u.startswith("http://"):
                    cleartext_http.append(u)

                # Check C2
                if "api.telegram.org" in dom or dom == "t.me" or dom.endswith(".t.me"):
                    telegram_c2.append(u)
                if "firebaseio.com" in dom or "firebasestorage.googleapis.com" in u:
                    firebase_c2.append(u)
                if any(dom.endswith(tld) for tld in HIGH_ABUSE_TLDS):
                    high_abuse_domains.append(dom)

        # IP matching
        found_ips = ip_pattern.findall(s)
        for ip in found_ips:
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    nums = [int(p) for p in parts]
                    if all(0 <= n <= 255 for n in nums):
                        # Filter out internal/private/loopback/zeros
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
    """
    Inspect assets, res, and res/raw for high entropy and hidden executable payloads (DEX, ZIP, ELF).
    Reads bounded bytes with z.open(n).read(limit).
    Excludes standard compressed image/media assets from entropy checks.
    """
    high_entropy_assets = []
    hidden_payloads = []
    media_extensions = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp3", ".ogg", ".wav", ".aac", ".ttf"}

    for name in namelist:
        is_asset_or_raw = name.startswith("assets/") or name.startswith("res/raw/")

        # Hidden executable payload checks across assets and resources
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

        # High entropy asset check (strictly in assets/ or res/raw/, ignoring standard media)
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

    # Check dex strings
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


def analyze_apk(data: bytes, name: str = "sample.apk") -> Dict[str, Any]:
    """
    Main triage analysis function: parses APK data in memory and extracts forensics.
    Handles Known Pitfalls 3 & 4: Catch corrupt/unsupported/encrypted files and
    reject ZIPs missing AndroidManifest.xml.
    """
    hashes = compute_hashes(data)

    # Validate ZIP header before opening
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

    # Reject ZIPs that lack AndroidManifest.xml (Known Pitfall 3)
    if "AndroidManifest.xml" not in namelist:
        return {
            "valid": False,
            "error": "Rejected: Archive does not contain AndroidManifest.xml (not an Android APK)",
            "name": name,
            "hashes": hashes,
            "scoring": {"total_score": 0, "risk_level": "Invalid", "categories": {}, "evidence": []},
        }

    # Extract manifest safely
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

    # 1. Permissions
    permissions = parse_manifest_permissions(manifest_bytes)

    # 2. Signing info (Known Pitfall 1)
    signing = check_signature(data, namelist)

    # 3. DEX analysis
    dex_members = [n for n in namelist if n.endswith(".dex")]
    dex_strings, dex_stats = extract_dex_strings(zf, dex_members)

    # 4. IoCs, URLs, Domains, IPs
    iocs = extract_iocs_and_urls(dex_strings)

    # 5. High entropy assets & hidden payloads
    high_entropy_assets, hidden_payloads = scan_assets_and_payloads(zf, namelist)

    # 6. Packers and Obfuscation
    packers = detect_packers(namelist, dex_strings)
    total_classes = dex_stats.get("classes_count", 0)
    obf_classes = dex_stats.get("obfuscated_classes_count", 0)
    obf_ratio = (obf_classes / total_classes) if total_classes > 0 else 0.0

    # 7. Third-party libraries
    libraries = detect_libraries(dex_strings, namelist)

    # Compile raw extraction dict
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

    # Score APK
    score_result = score_apk(extracted)
    extracted["scoring"] = score_result
    return extracted


def score_apk(f: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score = sum of capped categories, every point linked to evidence.
    Categories:
      - Permissions (cap 25)
      - Evasion (cap 30)
      - Behaviour (cap 25)
      - Network (cap 10)
      - Integrity (cap 10)
    Total: 0-100.
    Levels: High >= 50, Medium >= 25, else Low.
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

    evidence_list: List[Dict[str, Any]] = []

    # ----------------------------------------------------
    # Category 1: Permissions (Cap: 25)
    # ----------------------------------------------------
    perm_score = 0
    perm_evidence: List[Dict[str, Any]] = []

    perm_weights = {
        "READ_SMS": 5,
        "RECEIVE_SMS": 5,
        "SEND_SMS": 5,
        "BIND_ACCESSIBILITY_SERVICE": 6,
        "BIND_DEVICE_ADMIN": 5,
        "SYSTEM_ALERT_WINDOW": 4,
        "REQUEST_INSTALL_PACKAGES": 4,
        "READ_CONTACTS": 3,
        "RECORD_AUDIO": 3,
        "READ_CALL_LOG": 3,
        "CAMERA": 2,
        "CALL_PHONE": 2,
        "PROCESS_OUTGOING_CALLS": 2,
        "ACCESS_FINE_LOCATION": 2,
        "INSTALL_PACKAGES": 2,
        "MANAGE_EXTERNAL_STORAGE": 2,
        "ACCESS_COARSE_LOCATION": 1,
        "WRITE_EXTERNAL_STORAGE": 1,
        "READ_EXTERNAL_STORAGE": 1,
        "RECEIVE_BOOT_COMPLETED": 1,
        "READ_PHONE_STATE": 1,
        "GET_ACCOUNTS": 1,
    }

    for p in permissions:
        pts = perm_weights.get(p, 0)  # Only sensitive permissions contribute risk points
        if pts > 0:
            perm_score += pts
            item = {
                "category": "Permissions",
                "points": pts,
                "rule": f"Permission: android.permission.{p}",
                "evidence": f"android.permission.{p}",
            }
            perm_evidence.append(item)

    capped_perm_score = min(25, perm_score)
    evidence_list.extend(perm_evidence)

    # ----------------------------------------------------
    # Category 2: Evasion (Cap: 30)
    # ----------------------------------------------------
    evasion_score = 0
    evasion_evidence: List[Dict[str, Any]] = []

    # DexClassLoader (10)
    if any("DexClassLoader" in s for s in dex_strings):
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Dynamic code loading via DexClassLoader",
            "evidence": "dalvik.system.DexClassLoader reference in DEX strings",
        })

    # InMemoryDexClassLoader (10)
    if any("InMemoryDexClassLoader" in s for s in dex_strings):
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "In-memory dynamic DEX execution",
            "evidence": "dalvik.system.InMemoryDexClassLoader reference in DEX strings",
        })

    # Packer detected (10)
    if packers:
        pts = 10
        evasion_score += pts
        evasion_evidence.append({
            "category": "Evasion",
            "points": pts,
            "rule": "Commercial/Malicious APK Packer detected",
            "evidence": f"Packer indicators: {', '.join(packers)}",
        })

    # Hidden executable payload in assets/res (10)
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

    # Anti-debug checks (8)
    anti_debug_indicators = [
        "isDebuggerConnected", "tracerpid", "Ptrace", "/proc/self/status", "p_traced"
    ]
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

    # Emulator checks (8)
    emulator_indicators = [
        "goldfish", "ranchu", "generic_x86", "vbox86", "nox", "Genymotion", "ro.kernel.qemu"
    ]
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

    # High entropy asset (> 7.5) (8)
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

    # Obfuscation > 30% (6)
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

    # ----------------------------------------------------
    # Category 3: Behaviour (Cap: 25)
    # ----------------------------------------------------
    behaviour_score = 0
    behaviour_evidence: List[Dict[str, Any]] = []

    # Sends/reads SMS (7)
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

    # Accessibility Service descriptor (9) - Pitfall 2: exact descriptor!
    if "Landroid/accessibilityservice/AccessibilityService;" in dex_strings or "BIND_ACCESSIBILITY_SERVICE" in permissions:
        pts = 9
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Accessibility Service abuse (keylogging/UI injection)",
            "evidence": "Descriptor: Landroid/accessibilityservice/AccessibilityService; or BIND_ACCESSIBILITY_SERVICE",
        })

    # Device Admin Receiver descriptor (6) - Pitfall 2: exact descriptor!
    if "Landroid/app/admin/DeviceAdminReceiver;" in dex_strings or "BIND_DEVICE_ADMIN" in permissions:
        pts = 6
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Device Administrator privileges capability",
            "evidence": "Descriptor: Landroid/app/admin/DeviceAdminReceiver; or BIND_DEVICE_ADMIN",
        })

    # Overlay (6)
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

    # Audio recording (5)
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

    # Contacts access (4)
    if any("ContactsContract" in s for s in dex_strings) or "READ_CONTACTS" in permissions:
        pts = 4
        behaviour_score += pts
        behaviour_evidence.append({
            "category": "Behaviour",
            "points": pts,
            "rule": "Address book / contacts harvesting capability",
            "evidence": "READ_CONTACTS permission or ContactsContract API call",
        })

    # Crypto / IMEI / Device ID (3)
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

    # ----------------------------------------------------
    # Category 4: Network (Cap: 10)
    # ----------------------------------------------------
    network_score = 0
    network_evidence: List[Dict[str, Any]] = []

    # Telegram / Firebase C2 (8)
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

    # Hard-coded IP (3)
    if iocs.get("ips"):
        pts = 3
        network_score += pts
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Hard-coded public IPv4 address in binary",
            "evidence": f"IP addresses: {', '.join(iocs['ips'][:3])}",
        })

    # High-abuse TLD (4)
    if iocs.get("high_abuse_domains"):
        pts = 4
        network_score += pts
        network_evidence.append({
            "category": "Network",
            "points": pts,
            "rule": "Suspicious / High-abuse Top-Level Domain (TLD)",
            "evidence": f"Domains: {', '.join(iocs['high_abuse_domains'][:3])}",
        })

    # Cleartext HTTP (1)
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

    # ----------------------------------------------------
    # Category 5: Integrity (Cap: 10)
    # ----------------------------------------------------
    integrity_score = 0
    integrity_evidence: List[Dict[str, Any]] = []

    # Unsigned APK (6) - Pitfall 1: only if neither v1 nor v2/v3 is present
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


def score(f: Dict[str, Any]) -> Dict[str, Any]:
    """Alias for score_apk."""
    return score_apk(f)


# ---------------------------------------------------------------------------
# Demo APK Generator: 3 synthetic in-memory APKs (harmless, no real malware)
# Target Scores: Demo 1 ~78, Demo 2 ~61, Demo 3 ~8
# ---------------------------------------------------------------------------

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
        # Create AndroidManifest.xml (contains permissions in UTF-16LE and Latin-1)
        manifest_text = '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="org.cyberpolice.triage">\n'
        for p in permissions:
            manifest_text += f'  <uses-permission android:name="android.permission.{p}" />\n'
        manifest_text += '</manifest>\n'
        
        # Write both UTF-16LE and Latin-1 representations to simulate Android binary XML string pool
        manifest_bytes = manifest_text.encode("latin-1") + b"\x00\x00" + manifest_text.encode("utf-16le")
        z.writestr("AndroidManifest.xml", manifest_bytes)

        # Create classes.dex containing targeted DEX strings
        dex_buf = io.BytesIO()
        dex_buf.write(b"dex\n035\x00")  # DEX magic header
        dex_buf.write(b"\x00" * 32)
        for s in dex_strings:
            dex_buf.write(s.encode("utf-8") + b"\x00")
        z.writestr("classes.dex", dex_buf.getvalue())

        # Write assets if provided
        if assets:
            for path, data in assets.items():
                z.writestr(path, data)

        # Write v1 signature files if requested
        if sign_v1:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: 1.0\n")
            z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
            z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x0a" + b"\xaa" * 128)

    apk_bytes = buf.getvalue()

    # Append APK Sig Block 42 magic if v2/v3 requested
    if sign_v2:
        # Construct valid v2/v3 block structure containing magic
        sig_block = b"APK-SIG-BLOCK-DATA" + b"\x00" * 16 + struct.pack("<Q", 32) + APK_SIG_BLOCK_MAGIC
        apk_bytes = apk_bytes + sig_block

    return apk_bytes


def generate_demo_apks() -> Dict[str, bytes]:
    """
    Generate 3 harmless synthetic demo APKs matching hackathon triage profiles:
      - Demo 1 (Banking Trojan / Spyware): Scores ~78 (High)
      - Demo 2 (Suspicious Adware / Harvester): Scores ~61 (High/Medium)
      - Demo 3 (Benign Calculator Utility): Scores ~8 (Low)
    """
    # 1. Demo 1: High-Risk Banking Trojan / Spyware (Target Score: 78)
    # Perms: SEND_SMS(5) + RECEIVE_SMS(5) + READ_SMS(5) + BIND_ACCESSIBILITY_SERVICE(6) + REQUEST_INSTALL_PACKAGES(4) = 25 (capped 25)
    # Evasion: DexClassLoader(10) + anti-debug(8) + emulator checks(8) = 26 (capped 30)
    # Behaviour: AccessibilityService(9) + sends/reads SMS(7) + crypto/IMEI(3) = 19 (capped 25)
    # Network: Telegram C2(8) = 8 (capped 10)
    # Integrity: Signed v2/v3 = 0
    # Total = 25 + 26 + 19 + 8 + 0 = 78!
    demo1_perms = [
        "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "REQUEST_INSTALL_PACKAGES"
    ]
    demo1_strings = [
        # Precise class descriptors
        "Landroid/accessibilityservice/AccessibilityService;",
        # Evasion
        "dalvik.system.DexClassLoader",
        "android.os.Debug.isDebuggerConnected", "tracerpid",
        "goldfish", "generic_x86",
        # Behaviour
        "sendTextMessage", "getDeviceId", "Cipher.getInstance",
        # Network C2
        "https://api.telegram.org/bot123456/sendMessage",
    ]
    demo1_apk = _build_synthetic_apk(
        demo1_perms, demo1_strings, sign_v1=False, sign_v2=True
    )

    # 2. Demo 2: Suspicious Adware / Harvester (Target Score: 61)
    # Perms: READ_CONTACTS(3) + RECORD_AUDIO(3) + SYSTEM_ALERT_WINDOW(4) + REQUEST_INSTALL_PACKAGES(4) + CAMERA(2) = 16 (capped 25)
    # Evasion: High entropy asset(8) + Obfuscation > 30%(6) = 14 (capped 30)
    # Behaviour: Overlay(6) + Audio(5) + Contacts(4) + Crypto/IMEI(3) = 18 (capped 25)
    # Network: Hard-coded IP(3) + High-abuse TLD(4) = 7 (capped 10)
    # Integrity: Unsigned(6) = 6 (capped 10)
    # Total = 16 + 14 + 18 + 7 + 6 = 61!
    demo2_perms = [
        "READ_CONTACTS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "CAMERA"
    ]
    # Create high-entropy uniform byte distribution (>7.5 entropy, >512 bytes)
    high_entropy_bytes = bytes([i % 256 for i in range(2048)])
    demo2_assets = {
        "assets/payload.dat": high_entropy_bytes
    }
    # Obfuscated class names to reach > 30% obfuscation ratio
    obf_classes = [f"La/{chr(97 + i)};" for i in range(15)]
    normal_classes = [f"Lcom/example/feature/Service{i};" for i in range(15)]
    demo2_strings = obf_classes + normal_classes + [
        # Behaviour
        "TYPE_APPLICATION_OVERLAY",
        "AudioRecord",
        "ContactsContract",
        "getImei",
        # Network: IP (3) + High abuse TLD (4) = 7
        "https://tracker.suspicious-domain.xyz/ping",
        "198.51.100.42",
    ]
    demo2_apk = _build_synthetic_apk(
        demo2_perms, demo2_strings, assets=demo2_assets, sign_v1=False, sign_v2=False
    )

    # 3. Demo 3: Clean Benign Utility (Target Score: 8)
    # Perms: CAMERA(2) + WRITE_EXTERNAL_STORAGE(1) + ACCESS_FINE_LOCATION(2) + RECEIVE_BOOT_COMPLETED(1) + READ_EXTERNAL_STORAGE(1) = 7
    # Evasion: 0
    # Behaviour: 0
    # Network: Cleartext HTTP(1) = 1
    # Integrity: Signed v1 = 0
    # Total = 7 + 0 + 0 + 1 + 0 = 8!
    demo3_perms = [
        "CAMERA", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "RECEIVE_BOOT_COMPLETED", "READ_EXTERNAL_STORAGE"
    ]
    demo3_strings = [
        "Lcom/example/calculator/MainActivity;",
        "Lcom/example/calculator/Utils;",
        "http://insecure-cdn.calculatorapp.org/help",
    ]
    demo3_apk = _build_synthetic_apk(
        demo3_perms, demo3_strings, sign_v1=True, sign_v2=False
    )

    return {
        "banking_trojan_demo.apk": demo1_apk,
        "suspicious_adware_demo.apk": demo2_apk,
        "benign_calculator_demo.apk": demo3_apk,
    }


# ---------------------------------------------------------------------------
# Cross-APK Comparison & Forensics Report Helpers
# ---------------------------------------------------------------------------

def compare_apks(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compare multiple analyzed APKs.
    Handles Known Pitfall 5: Disambiguate duplicate names as 'name [sha256[:6]]'.
    """
    labeled_results = []
    matrix = []
    all_domains = set()
    shared_domains = {}

    for r in results:
        name = r.get("name", "unknown.apk")
        sha = r.get("hashes", {}).get("sha256", "000000")[:6]
        label = f"{name} [{sha}]"
        labeled_results.append((label, r))

    for label, r in labeled_results:
        sc = r.get("scoring", {})
        iocs = r.get("iocs", {})
        doms = set(iocs.get("domains", []))
        all_domains.update(doms)
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

    # Filter domains shared across 2 or more APKs
    shared_infrastructure = {d: apks for d, apks in shared_domains.items() if len(apks) > 1}

    return {
        "matrix": matrix,
        "shared_infrastructure": shared_infrastructure,
    }


def generate_graphviz_dot(results: List[Dict[str, Any]]) -> str:
    """
    Generate Graphviz DOT source visualizing shared domains/IPs between APKs.
    Handles Known Pitfall 7: Graphviz labels must be properly escaped.
    """
    dot_lines = [
        "graph APK_Triage_Graph {",
        "  rankdir=LR;",
        '  node [fontname="Helvetica", fontsize=10];',
        '  edge [color="#666666", penwidth=1.2];',
    ]

    def escape_label(txt: str) -> str:
        return txt.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

    for r in results:
        name = r.get("name", "unknown.apk")
        sha = r.get("hashes", {}).get("sha256", "000000")[:6]
        apk_label = escape_label(f"{name} [{sha}]")
        score_val = r.get("scoring", {}).get("total_score", 0)
        
        # Color nodes by score
        if score_val >= 50:
            color = "#FF4B4B"
            fillcolor = "#FFD2D2"
        elif score_val >= 25:
            color = "#FFA500"
            fillcolor = "#FFE8CC"
        else:
            color = "#28A745"
            fillcolor = "#D4EDDA"

        dot_lines.append(
            f'  "{apk_label}" [shape=box, style="filled,rounded", color="{color}", fillcolor="{fillcolor}", penwidth=2];'
        )

        # Connect domains
        iocs = r.get("iocs", {})
        for dom in iocs.get("domains", [])[:10]:
            dom_label = escape_label(dom)
            dot_lines.append(f'  "{dom_label}" [shape=ellipse, style=filled, fillcolor="#E8F4F8", color="#17A2B8"];')
            dot_lines.append(f'  "{apk_label}" -- "{dom_label}";')

        # Connect IPs
        for ip in iocs.get("ips", [])[:10]:
            ip_label = escape_label(ip)
            dot_lines.append(f'  "{ip_label}" [shape=diamond, style=filled, fillcolor="#FFF3CD", color="#FFC107"];')
            dot_lines.append(f'  "{apk_label}" -- "{ip_label}";')

    dot_lines.append("}")
    return "\n".join(dot_lines)


def generate_html_report(result: Dict[str, Any]) -> str:
    """Generate self-contained, printable forensic HTML report for law enforcement investigators."""
    name = result.get("name", "APK")
    hashes = result.get("hashes", {})
    sc = result.get("scoring", {})
    signing = result.get("signing", {})
    perms = result.get("permissions", [])
    iocs = result.get("iocs", {})
    ev = sc.get("evidence", [])
    score_val = sc.get("total_score", 0)
    risk = sc.get("risk_level", "Unknown")

    badge_color = "#d9534f" if score_val >= 50 else ("#f0ad4e" if score_val >= 25 else "#5cb85c")

    evidence_rows = "".join(
        f"<tr><td><b>{e.get('category')}</b></td><td>+{e.get('points')}</td><td>{e.get('rule')}</td><td><code>{e.get('evidence')}</code></td></tr>"
        for e in ev
    )

    perm_badges = " ".join(f'<span class="badge">{p}</span>' for p in perms) or "None detected"
    url_items = "".join(f"<li><code>{u}</code></li>" for u in iocs.get("urls", [])[:20]) or "None extracted"
    ip_items = "".join(f"<li><code>{ip}</code></li>" for ip in iocs.get("ips", [])[:20]) or "None extracted"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Forensic APK Triage Report - {name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #222; background: #fff; }}
  h1, h2, h3 {{ color: #0f172a; margin-bottom: 8px; }}
  .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 12px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
  .score-box {{ background: {badge_color}; color: #fff; padding: 12px 24px; border-radius: 8px; text-align: center; }}
  .score-val {{ font-size: 32px; font-weight: bold; }}
  .meta-table, .evidence-table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
  .meta-table td, .meta-table th, .evidence-table td, .evidence-table th {{ border: 1px solid #e2e8f0; padding: 8px 12px; font-size: 14px; text-align: left; }}
  .evidence-table th {{ background: #f8fafc; font-weight: 600; }}
  .badge {{ display: inline-block; background: #f1f5f9; color: #334155; padding: 3px 8px; border-radius: 4px; font-size: 12px; margin: 2px; font-family: monospace; }}
  code {{ font-family: monospace; background: #f8fafc; padding: 2px 4px; border-radius: 3px; font-size: 13px; }}
  @media print {{
    body {{ margin: 10mm; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Forensic Digital Triage Report</h1>
    <p>Defensive APK Static Triage</p>
  </div>
  <div class="score-box">
    <div class="score-val">{score_val} / 100</div>
    <div>Risk: {risk.upper()}</div>
  </div>
</div>

<h2>File Identifiers</h2>
<table class="meta-table">
  <tr><th>File Name</th><td>{name}</td><th>File Size</th><td>{hashes.get('size', 0):,} bytes</td></tr>
  <tr><th>MD5</th><td colspan="3"><code>{hashes.get('md5')}</code></td></tr>
  <tr><th>SHA1</th><td colspan="3"><code>{hashes.get('sha1')}</code></td></tr>
  <tr><th>SHA256</th><td colspan="3"><code>{hashes.get('sha256')}</code></td></tr>
  <tr><th>Signing Status</th><td colspan="3"><b>{signing.get('status')}</b></td></tr>
</table>

<h2>Risk Score Breakdown & Evidence</h2>
<table class="evidence-table">
  <thead>
    <tr><th>Category</th><th>Points</th><th>Detection Rule</th><th>Evidence Extracted</th></tr>
  </thead>
  <tbody>
    {evidence_rows}
  </tbody>
</table>

<h2>Extracted Indicators of Compromise (IoCs)</h2>
<h3>Network URLs ({len(iocs.get('urls', []))})</h3>
<ul>{url_items}</ul>

<h3>Extracted Public IPs ({len(iocs.get('ips', []))})</h3>
<ul>{ip_items}</ul>

<h2>Declared Permissions ({len(perms)})</h2>
<div>{perm_badges}</div>

<div class="no-print" style="margin-top: 40px; text-align: center;">
  <button onclick="window.print()" style="padding: 10px 20px; font-size: 16px; cursor: pointer; background: #0f172a; color: #fff; border: none; border-radius: 6px;">Print / Save as PDF</button>
</div>
</body>
</html>
"""
    return html
