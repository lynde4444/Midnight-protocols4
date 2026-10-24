"""
Defensive Android APK Triage Platform - Threat Intelligence Enrichment
Optional integrations for VirusTotal and MobSF REST APIs.
Never crashes or blocks execution if API keys or remote endpoints are absent or unreachable.
"""

import os
import urllib.error
import urllib.parse
import urllib.request
import json
from typing import Any, Dict, Optional


def query_virustotal(sha256: str, timeout: int = 4) -> Dict[str, Any]:
    """
    Query VirusTotal v3 files API for a given SHA256 hash.
    Safe and resilient: returns structured status, never throws an unhandled exception.
    """
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY environment variable not configured",
            "positives": None,
            "total": None,
        }

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "BiharPoliceForensics-APKTriage/1.0",
    }

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            return {
                "status": "found",
                "positives": positives,
                "total": total,
                "stats": stats,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found", "reason": "Hash not observed on VirusTotal", "positives": 0, "total": 0}
        return {"status": "error", "reason": f"VirusTotal HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "reason": f"VirusTotal connection error: {str(e)}"}


def query_mobsf_report(sha256: str, timeout: int = 4) -> Dict[str, Any]:
    """
    Query a local or remote MobSF REST instance for an existing static scan report.
    Never throws or halts execution if MobSF is absent or unreachable.
    """
    mobsf_url = os.environ.get("MOBSF_URL", "").strip()
    mobsf_api_key = os.environ.get("MOBSF_API_KEY", "").strip()

    if not mobsf_url or not mobsf_api_key:
        return {
            "status": "skipped",
            "reason": "MOBSF_URL or MOBSF_API_KEY not configured",
        }

    target_url = f"{mobsf_url.rstrip('/')}/api/v1/report_json"
    headers = {
        "Authorization": mobsf_api_key,
        "User-Agent": "BiharPoliceForensics-APKTriage/1.0",
    }
    payload = urllib.parse.urlencode({"hash": sha256}).encode("utf-8")
    req = urllib.request.Request(target_url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "status": "found",
                "app_name": data.get("app_name", "Unknown"),
                "security_score": data.get("security_score"),
                "cvss": data.get("average_cvss"),
            }
    except urllib.error.HTTPError as e:
        return {"status": "error", "reason": f"MobSF HTTP {e.code}"}
    except Exception as e:
        return {"status": "error", "reason": f"MobSF unreachable: {str(e)}"}


def enrich_analysis(sha256: str) -> Dict[str, Any]:
    """Execute all configured threat intelligence enrichments without crashing."""
    return {
        "virustotal": query_virustotal(sha256),
        "mobsf": query_mobsf_report(sha256),
    }
