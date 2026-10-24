"""
Defensive Android APK Triage Platform - FastAPI Forensic REST Service
Provides RESTful analysis, case persistence, comparison, and printable reports.
"""

import os
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from apk_triage_engine import (
    analyze_apk,
    compare_apks,
    generate_html_report,
)
from db import get_html_report, get_report, init_db, list_reports, save_report
from enrichment import enrich_analysis

app = FastAPI(
    title="Defensive APK Triage Forensics API",
    description="Automated digital static triage and risk assessment for Android packages.",
    version="1.0.0",
)

# Initialize database
DB_PATH = os.environ.get("DB_PATH", "forensics.db")
db_conn = init_db(DB_PATH)


class CompareRequest(BaseModel):
    ids: List[int]


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    """Health and threat intelligence status."""
    return {
        "status": "healthy",
        "engine": "pure-stdlib-static",
        "integrations": {
            "virustotal": bool(os.environ.get("VT_API_KEY")),
            "mobsf": bool(os.environ.get("MOBSF_URL") and os.environ.get("MOBSF_API_KEY")),
        },
    }


@app.post("/api/analyze")
async def analyze_endpoint(
    file: UploadFile = File(...),
    enrich: bool = Query(True, description="Run optional external threat enrichment if configured"),
) -> Dict[str, Any]:
    """
    Triage an uploaded APK package.
    Parses manifest, DEX bytecode strings, packers, and computes explainable 0-100 risk score.
    """
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    name = file.filename or "sample.apk"
    result = analyze_apk(content, name)

    if not result.get("valid", False):
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Invalid or malformed Android APK archive"),
        )

    # Optional threat intelligence enrichment (VT / MobSF)
    sha256 = result.get("hashes", {}).get("sha256", "")
    enrichment_data = enrich_analysis(sha256) if enrich else {}
    result["enrichment"] = enrichment_data

    # Generate printable HTML report
    html_rep = generate_html_report(result)

    # Save to SQLite
    record_id = save_report(db_conn, result, html_rep)
    result["id"] = record_id

    # Exclude raw in-memory sets/large byte collections from JSON response
    clean_result = {k: v for k, v in result.items() if k not in ("dex_strings",)}
    return clean_result


@app.get("/api/reports")
def get_reports_endpoint(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (High, Medium, Low)"),
    limit: int = Query(50, ge=1, le=200),
) -> List[Dict[str, Any]]:
    """Retrieve list of historic investigated APK triage cases."""
    return list_reports(db_conn, risk_level=risk_level, limit=limit)


@app.get("/api/reports/{report_id}")
def get_report_json_endpoint(report_id: int) -> Dict[str, Any]:
    """Retrieve detailed forensic JSON report for a specific case ID."""
    rep = get_report(db_conn, report_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found")
    return rep


@app.get("/report/{report_id}", response_class=HTMLResponse)
def get_report_html_endpoint(report_id: int) -> HTMLResponse:
    """Retrieve printable, courtroom-ready HTML forensic triage report."""
    html_content = get_html_report(db_conn, report_id)
    if not html_content:
        raise HTTPException(status_code=404, detail=f"Report #{report_id} not found")
    return HTMLResponse(content=html_content)


@app.post("/api/compare")
def compare_endpoint(req: CompareRequest) -> Dict[str, Any]:
    """
    Compare multiple analyzed APK reports by IDs.
    Returns comparison matrix and identified shared infrastructure (domains/IPs).
    """
    if len(req.ids) < 2:
        raise HTTPException(status_code=400, detail="Provide at least 2 report IDs to compare")

    reports = []
    for rid in req.ids:
        rep = get_report(db_conn, rid)
        if rep:
            reports.append(rep)

    if len(reports) < 2:
        raise HTTPException(
            status_code=404,
            detail="Fewer than 2 valid reports found matching requested IDs",
        )

    return compare_apks(reports)
