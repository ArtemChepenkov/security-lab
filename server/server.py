import os
import json
import time
import uuid
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.parse
import urllib.request
from typing import List, Optional, Any, Dict

from fastapi import (
    FastAPI, UploadFile, File, Form, HTTPException,
    BackgroundTasks, Depends, Security, Query,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import APIKeyHeader

import yaml
from pydantic import BaseModel

# =========================================================
# AUTH
# =========================================================

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: str = Security(_api_key_header)):
    configured = os.environ.get("API_KEY", "")
    if configured and key != configured:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# =========================================================
# APP
# =========================================================

DB_PATH = "./data/scans.db"
os.makedirs("./data", exist_ok=True)

app = FastAPI(title="Security Scan API", dependencies=[Depends(verify_api_key)])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DB
# =========================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id TEXT PRIMARY KEY,
        ts INTEGER,
        namespace TEXT,
        release TEXT,
        status TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_images(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        image TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        scanner TEXT,
        severity TEXT,
        target TEXT,
        title TEXT,
        cve_id TEXT,
        pkg_name TEXT,
        installed_version TEXT,
        fixed_version TEXT,
        cvss_score REAL,
        description TEXT,
        references_json TEXT
    )
    """)

    # Migration for existing DBs created by older server versions.
    cur.execute("PRAGMA table_info(scan_findings)")
    existing_columns = {row[1] for row in cur.fetchall()}
    migrations = {
        "cve_id": "TEXT",
        "pkg_name": "TEXT",
        "installed_version": "TEXT",
        "fixed_version": "TEXT",
        "cvss_score": "REAL",
        "description": "TEXT",
        "references_json": "TEXT",
        # "vuln" | "misconfig" — misconfig используется для trivy k8s
        "finding_type": "TEXT DEFAULT 'vuln'",
    }
    for column, column_type in migrations.items():
        if column not in existing_columns:
            cur.execute(f"ALTER TABLE scan_findings ADD COLUMN {column} {column_type}")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities(
        cve_id TEXT PRIMARY KEY,
        severity TEXT,
        cvss_score REAL,
        title TEXT,
        description TEXT,
        published_at TEXT,
        modified_at TEXT,
        source TEXT,
        references_json TEXT,
        raw_json TEXT,
        updated_at INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_sbom(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        image TEXT NOT NULL,
        format TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON scan_findings(scan_id, severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON scan_findings(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sbom_scan ON scan_sbom(scan_id)")

    conn.commit()
    conn.close()


init_db()


# =========================================================
# UTIL
# =========================================================

def run_cmd(cmd: List[str], timeout: int = 300):
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "code": 124,
            "stdout": exc.stdout or "",
            "stderr": f"Command timed out after {timeout}s: {' '.join(cmd)}",
        }

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    v = value.upper()
    return v if v in SEVERITY_ORDER else "UNKNOWN"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row):
    return dict(row) if row else None


def parse_json_list(value):
    if not value:
        return []
    try:
        return json.loads(value)
    except Exception:
        return []


def build_pagination(page: int, page_size: int):
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    offset = (page - 1) * page_size
    return page, page_size, offset


def extract_cvss_from_trivy(vuln: Dict[str, Any]) -> Optional[float]:
    cvss = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        item = cvss.get(source)
        if item and item.get("V3Score") is not None:
            return float(item["V3Score"])
    for item in cvss.values():
        if isinstance(item, dict) and item.get("V3Score") is not None:
            return float(item["V3Score"])
    return None


def extract_cvss_from_grype(vuln: Dict[str, Any]) -> Optional[float]:
    for entry in vuln.get("cvss") or []:
        score = entry.get("metrics", {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


def _update_scan_status(scan_id: str, status: str):
    conn = get_conn()
    conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
    conn.commit()
    conn.close()


# =========================================================
# PERSISTENCE
# =========================================================
def sync_nvd_for_scan(scan_id: str) -> Dict[str, Any]:
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT DISTINCT cve_id
        FROM scan_findings
        WHERE scan_id=? AND cve_id IS NOT NULL AND cve_id != ''
        """,
        (scan_id,),
    ).fetchall()
    conn.close()

    api_key = os.environ.get("NVD_API_KEY") or None

    synced, skipped, failed = 0, 0, 0
    for row in rows:
        cve_id = row["cve_id"]

        # NVD не знает DLA-*, GHSA-* и прочие форматы — пропускаем
        if not cve_id.upper().startswith("CVE-"):
            skipped += 1
            continue

        try:
            data = fetch_nvd_cve(cve_id, api_key=api_key)
            items = data.get("vulnerabilities") or []

            if not items:
                skipped += 1
                continue

            parsed = parse_nvd_item(items[0])
            upsert_vulnerability(**parsed)
            synced += 1

            # NVD rate limit: 5 req/30s без ключа, 50 req/30s с ключом
            time.sleep(0.7 if api_key else 6)
        except Exception as exc:
            failed += 1
            print(f"NVD sync failed for {cve_id}: {exc}", flush=True)

    return {"synced": synced, "skipped": skipped, "failed": failed}


def upsert_vulnerability(
    cve_id: str,
    severity: str = "UNKNOWN",
    cvss_score: Optional[float] = None,
    title: Optional[str] = None,
    description: Optional[str] = None,
    published_at: Optional[str] = None,
    modified_at: Optional[str] = None,
    source: str = "local",
    references: Optional[List[str]] = None,
    raw: Optional[Dict[str, Any]] = None,
):
    if not cve_id:
        return
    conn = get_conn()
    conn.execute("""
        INSERT INTO vulnerabilities(
            cve_id, severity, cvss_score, title, description,
            published_at, modified_at, source, references_json, raw_json, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(cve_id) DO UPDATE SET
            severity=excluded.severity,
            cvss_score=COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
            title=COALESCE(excluded.title, vulnerabilities.title),
            description=COALESCE(excluded.description, vulnerabilities.description),
            published_at=COALESCE(excluded.published_at, vulnerabilities.published_at),
            modified_at=COALESCE(excluded.modified_at, vulnerabilities.modified_at),
            source=excluded.source,
            references_json=COALESCE(excluded.references_json, vulnerabilities.references_json),
            raw_json=COALESCE(excluded.raw_json, vulnerabilities.raw_json),
            updated_at=excluded.updated_at
    """, (
        cve_id,
        normalize_severity(severity),
        cvss_score,
        title,
        description,
        published_at,
        modified_at,
        source,
        json.dumps(references or []),
        json.dumps(raw or {}, ensure_ascii=False),
        int(time.time() * 1000),
    ))
    conn.commit()
    conn.close()


def fetch_nvd_cve(cve_id: str, api_key: Optional[str] = None):
    query = urllib.parse.urlencode({"cveId": cve_id})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
    headers = {"User-Agent": "security-scan-api/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_nvd_item(item: Dict[str, Any]):
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    severity = "UNKNOWN"
    cvss_score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric = (metrics.get(key) or [None])[0]
        if metric:
            cvss_data = metric.get("cvssData", {})
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or severity
            cvss_score = cvss_data.get("baseScore")
            break
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    references = [r.get("url") for r in (cve.get("references") or []) if r.get("url")]
    return {
        "cve_id": cve.get("id"),
        "severity": severity,
        "cvss_score": cvss_score,
        "title": cve.get("id"),
        "description": description,
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
        "source": "nvd",
        "references": references,
        "raw": item,
    }


def create_scan(release: str, namespace_override: Optional[str] = None) -> tuple:
    scan_id = uuid.uuid4().hex[:8]
    namespace = namespace_override or f"scan-{scan_id}"
    run_cmd(["kubectl", "create", "namespace", namespace], timeout=30)
    conn = get_conn()
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?)",
        (scan_id, int(time.time() * 1000), namespace, release, "created"),
    )
    conn.commit()
    conn.close()
    return scan_id, namespace


def save_images(scan_id: str, images: List[str]):
    conn = get_conn()
    for img in images:
        conn.execute("INSERT INTO scan_images(scan_id, image) VALUES (?,?)", (scan_id, img))
    conn.commit()
    conn.close()


def save_finding(
    scan_id: str,
    scanner: str,
    severity: str,
    target: str,
    title: str,
    cve_id: Optional[str] = None,
    pkg_name: Optional[str] = None,
    installed_version: Optional[str] = None,
    fixed_version: Optional[str] = None,
    cvss_score: Optional[float] = None,
    description: Optional[str] = None,
    references: Optional[List[str]] = None,
    finding_type: str = "vuln",
):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO scan_findings(
            scan_id, scanner, severity, target, title, cve_id, pkg_name,
            installed_version, fixed_version, cvss_score, description, references_json,
            finding_type
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            scan_id, scanner, normalize_severity(severity), target, title,
            cve_id, pkg_name, installed_version, fixed_version,
            cvss_score, description, json.dumps(references or []),
            finding_type,
        ),
    )
    conn.commit()
    conn.close()


def save_sbom(scan_id: str, image: str, fmt: str, content: str):
    conn = get_conn()
    conn.execute(
        "INSERT INTO scan_sbom(scan_id, image, format, content, created_at) VALUES (?,?,?,?,?)",
        (scan_id, image, fmt, content, int(time.time() * 1000)),
    )
    conn.commit()
    conn.close()


# =========================================================
# TRIVY SCANNER
# =========================================================

def parse_trivy_findings(scan_id: str, image: str, data: Dict[str, Any]):
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            cve_id = v.get("VulnerabilityID")
            cvss = extract_cvss_from_trivy(v)
            refs = v.get("References") or []

            save_finding(
                scan_id=scan_id,
                scanner="trivy",
                severity=v.get("Severity", "UNKNOWN"),
                target=image,
                title=v.get("Title") or cve_id or "",
                cve_id=cve_id,
                pkg_name=v.get("PkgName"),
                installed_version=v.get("InstalledVersion"),
                fixed_version=v.get("FixedVersion"),
                cvss_score=cvss,
                description=v.get("Description"),
                references=refs,
            )

            if cve_id:
                upsert_vulnerability(
                    cve_id=cve_id,
                    severity=v.get("Severity"),
                    cvss_score=cvss,
                    title=v.get("Title"),
                    description=v.get("Description"),
                    references=refs,
                    source="trivy",
                )


def run_trivy_image(scan_id: str, image: str):
    res = run_cmd(["trivy", "image", "-f", "json", "--quiet", image], timeout=300)
    if res["code"] != 0:
        print(f"trivy failed for {image}: {res['stderr']}", flush=True)
        return
    try:
        data = json.loads(res["stdout"])
    except json.JSONDecodeError as exc:
        print(f"trivy JSON parse error for {image}: {exc}", flush=True)
        return
    parse_trivy_findings(scan_id, image, data)


# =========================================================
# TRIVY K8S SCANNER
# =========================================================

def parse_trivy_k8s_report(scan_id: str, data: Dict[str, Any]):
    """Парсит вывод `trivy k8s -f json`: уязвимости образов + мисконфиги ресурсов."""
    for resource in data.get("Resources") or []:
        kind = resource.get("Kind", "")
        ns = resource.get("Namespace", "")
        name = resource.get("Name", "")
        # target: Deployment/default/juice-shop
        k8s_target = "/".join(filter(None, [kind, ns, name])) or "cluster"

        for result in resource.get("Results") or []:
            # --- CVE в образах ---
            for v in result.get("Vulnerabilities") or []:
                cve_id = v.get("VulnerabilityID")
                cvss = extract_cvss_from_trivy(v)
                refs = v.get("References") or []
                save_finding(
                    scan_id=scan_id,
                    scanner="trivy-k8s",
                    severity=v.get("Severity", "UNKNOWN"),
                    target=k8s_target,
                    title=v.get("Title") or cve_id or "",
                    cve_id=cve_id,
                    pkg_name=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    cvss_score=cvss,
                    description=v.get("Description"),
                    references=refs,
                    finding_type="vuln",
                )
                if cve_id:
                    upsert_vulnerability(
                        cve_id=cve_id,
                        severity=v.get("Severity"),
                        cvss_score=cvss,
                        title=v.get("Title"),
                        description=v.get("Description"),
                        references=refs,
                        source="trivy-k8s",
                    )

            # --- Мисконфиги k8s ресурсов ---
            for m in result.get("Misconfigurations") or []:
                status = m.get("Status", "")
                if status == "PASS":
                    continue
                save_finding(
                    scan_id=scan_id,
                    scanner="trivy-k8s",
                    severity=m.get("Severity", "UNKNOWN"),
                    target=k8s_target,
                    title=m.get("Title") or m.get("ID") or "",
                    cve_id=None,
                    description=m.get("Description"),
                    references=[m.get("PrimaryURL")] if m.get("PrimaryURL") else [],
                    finding_type="misconfig",
                )


def _run_k8s_scan_background(scan_id: str, namespace: Optional[str]):
    try:
        cmd = ["trivy", "k8s", "-f", "json", "--quiet"]
        if namespace:
            cmd += ["--include-namespaces", namespace]
        else:
            cmd += ["--all-namespaces"]

        res = run_cmd(cmd, timeout=600)
        if res["code"] != 0:
            print(f"trivy k8s failed: {res['stderr']}", flush=True)
            _update_scan_status(scan_id, "failed")
            return

        data = json.loads(res["stdout"])
        parse_trivy_k8s_report(scan_id, data)
        _update_scan_status(scan_id, "done")
    except Exception as exc:
        print(f"trivy k8s scan {scan_id} error: {exc}", flush=True)
        _update_scan_status(scan_id, "failed")


# =========================================================
# GRYPE SCANNER
# =========================================================

def parse_grype_findings(scan_id: str, image: str, data: Dict[str, Any]):
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related = match.get("relatedVulnerabilities") or []

        # Grype часто отдаёт GHSA/DLA как основной ID, а CVE прячет в relatedVulnerabilities.
        # Ищем первый CVE-* среди related, иначе берём основной ID.
        raw_id = vuln.get("id") or ""
        cve_id = raw_id
        for rv in related:
            rv_id = rv.get("id") or ""
            if rv_id.upper().startswith("CVE-"):
                cve_id = rv_id
                break

        severity = normalize_severity(vuln.get("severity", "UNKNOWN"))

        # CVSS: сначала из основной записи, потом из related
        cvss = extract_cvss_from_grype(vuln)
        if cvss is None:
            for rv in related:
                cvss = extract_cvss_from_grype(rv)
                if cvss is not None:
                    break

        fix_versions = vuln.get("fix", {}).get("versions") or []
        refs = vuln.get("urls") or []
        description = vuln.get("description")

        # title = короткий ID (CVE или GHSA), description — отдельно
        title = cve_id or raw_id or ""

        save_finding(
            scan_id=scan_id,
            scanner="grype",
            severity=severity,
            target=image,
            title=title,
            cve_id=cve_id if cve_id.upper().startswith("CVE-") else None,
            pkg_name=artifact.get("name"),
            installed_version=artifact.get("version"),
            fixed_version=", ".join(fix_versions) if fix_versions else None,
            cvss_score=cvss,
            description=description,
            references=refs,
        )

        if cve_id.upper().startswith("CVE-"):
            upsert_vulnerability(
                cve_id=cve_id,
                severity=severity,
                cvss_score=cvss,
                title=cve_id,
                description=description,
                references=refs,
                source="grype",
            )


def run_grype_image(scan_id: str, image: str):
    # Prefer syft → grype (SBOM-based) for richer results; fall back to direct scan.
    # Не используем --quiet у syft: в некоторых версиях он подавляет и stdout.
    syft_res = run_cmd(["syft", image, "-o", "cyclonedx-json"], timeout=120)
    sbom_path: Optional[str] = None

    if syft_res["code"] == 0 and syft_res["stdout"].strip():
        save_sbom(scan_id, image, "cyclonedx-json", syft_res["stdout"])
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        tmp.write(syft_res["stdout"])
        tmp.close()
        sbom_path = tmp.name
        grype_target = f"sbom:{sbom_path}"
    else:
        grype_target = image

    try:
        res = run_cmd(["grype", grype_target, "-o", "json"], timeout=300)
    finally:
        if sbom_path:
            os.unlink(sbom_path)

    if res["code"] != 0:
        print(f"grype failed for {image}: {res['stderr']}", flush=True)
        return
    try:
        data = json.loads(res["stdout"])
    except json.JSONDecodeError as exc:
        print(f"grype JSON parse error for {image}: {exc}", flush=True)
        return
    parse_grype_findings(scan_id, image, data)


# =========================================================
# KUBE-BENCH
# =========================================================

def _parse_kube_bench_json(scan_id: str, data: Dict[str, Any]):
    for control in data.get("Controls") or []:
        # kube-bench >= 0.7 uses groups → checks; older uses tests → results
        groups = control.get("groups") or control.get("tests") or []
        for group in groups:
            checks = group.get("checks") or group.get("results") or []
            for check in checks:
                state = check.get("state") or check.get("status")
                if state in (None, "PASS"):
                    continue
                severity = {"FAIL": "HIGH", "WARN": "MEDIUM", "INFO": "LOW"}.get(state, "LOW")
                check_id = check.get("id") or check.get("test_number") or "cluster"
                text = check.get("text") or check.get("test_desc") or ""
                save_finding(scan_id, "kube-bench", severity, "cluster", f"{check_id}: {text}")


def _run_kube_bench_background(scan_id: str):
    try:
        res = run_cmd(["sudo", "kube-bench", "run", "--json"], timeout=300)
        if res["code"] != 0:
            print(f"kube-bench failed: {res['stderr']}", flush=True)
            _update_scan_status(scan_id, "failed")
            return
        data = json.loads(res["stdout"])
        _parse_kube_bench_json(scan_id, data)
        _update_scan_status(scan_id, "done")
    except Exception as exc:
        print(f"kube-bench {scan_id} error: {exc}", flush=True)
        _update_scan_status(scan_id, "failed")


# =========================================================
# HELM / IMAGE SCAN BACKGROUND TASK
# =========================================================

def _run_helm_scan_background(
    scan_id: str,
    namespace: str,
    release: str,
    chart_path: str,
    tmp_dir: str,
):
    try:
        _update_scan_status(scan_id, "running")

        res = run_cmd(["helm", "upgrade", "--install", release, chart_path, "-n", namespace], timeout=120)
        if res["code"] != 0:
            print(f"helm failed for scan {scan_id}: {res['stderr']}", flush=True)
            _update_scan_status(scan_id, "failed")
            return

        # Poll until pods are running (max 60 s).
        images: List[str] = []
        for _ in range(12):
            time.sleep(5)
            images = get_images(namespace)
            if images:
                break

        if not images:
            print(f"scan {scan_id}: no images found in namespace {namespace}", flush=True)
            _update_scan_status(scan_id, "failed")
            return

        save_images(scan_id, images)

        for img in images:
            run_trivy_image(scan_id, img)
            run_grype_image(scan_id, img)

        _update_scan_status(scan_id, "done")
        print(f"scan {scan_id}: done ({len(images)} images)", flush=True)
    except Exception as exc:
        print(f"scan {scan_id} error: {exc}", flush=True)
        _update_scan_status(scan_id, "failed")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =========================================================
# GET IMAGES FROM PODS
# =========================================================

def get_images(namespace: str) -> List[str]:
    res = run_cmd(["kubectl", "get", "pods", "-n", namespace, "-o", "json"], timeout=30)
    try:
        data = json.loads(res["stdout"])
    except json.JSONDecodeError:
        return []
    images = []
    for pod in data.get("items", []):
        for c in pod.get("spec", {}).get("containers", []):
            if c.get("image"):
                images.append(c["image"])
    return list(set(images))


# =========================================================
# SCAN ENDPOINTS
# =========================================================

@app.post("/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    release: str = Form(...),
    chart: UploadFile = File(...),
):
    if not chart.filename.endswith(".tgz"):
        raise HTTPException(400, "chart must be .tgz")

    scan_id, namespace = create_scan(release)

    tmp = tempfile.mkdtemp()
    chart_path = os.path.join(tmp, chart.filename)
    contents = await chart.read()
    with open(chart_path, "wb") as f:
        f.write(contents)

    background_tasks.add_task(
        _run_helm_scan_background, scan_id, namespace, release, chart_path, tmp
    )

    return {"scan_id": scan_id, "namespace": namespace, "status": "running"}


@app.post("/scan/kube-bench")
def run_kube_bench(background_tasks: BackgroundTasks):
    scan_id = uuid.uuid4().hex[:8]
    conn = get_conn()
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?)",
        (scan_id, int(time.time() * 1000), "cluster-wide", "kube-bench", "running"),
    )
    conn.commit()
    conn.close()

    background_tasks.add_task(_run_kube_bench_background, scan_id)

    return {"scan_id": scan_id, "status": "running"}


@app.post("/scan/k8s")
def start_k8s_scan(
    background_tasks: BackgroundTasks,
    namespace: Optional[str] = Query(None, description="Конкретный namespace; если не указан — сканируется весь кластер"),
):
    """
    Запускает `trivy k8s` — сканирует Deployments, DaemonSets, StatefulSets,
    Jobs, Pods, Secrets, RBAC и прочие ресурсы.
    Находки двух типов: vuln (CVE в образах) и misconfig (нарушения k8s best practices).
    """
    scan_id = uuid.uuid4().hex[:8]
    label = namespace or "all-namespaces"
    conn = get_conn()
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?)",
        (scan_id, int(time.time() * 1000), label, "trivy-k8s", "running"),
    )
    conn.commit()
    conn.close()

    background_tasks.add_task(_run_k8s_scan_background, scan_id, namespace)

    return {"scan_id": scan_id, "namespace": label, "status": "running"}


@app.get("/kube-bench/list")
def list_kube_bench_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()

    total = cur.execute(
        "SELECT COUNT(*) AS c FROM scans WHERE release=?",
        ("kube-bench",),
    ).fetchone()["c"]

    rows = cur.execute(
        """
        SELECT
            s.id,
            s.ts,
            s.namespace,
            s.release,
            s.status,
            COUNT(f.id) AS findings_total,
            SUM(CASE WHEN f.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN f.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN f.severity = 'LOW' THEN 1 ELSE 0 END) AS low_count
        FROM scans s
        LEFT JOIN scan_findings f ON f.scan_id = s.id AND f.scanner = 'kube-bench'
        WHERE s.release = ?
        GROUP BY s.id, s.ts, s.namespace, s.release, s.status
        ORDER BY s.ts DESC
        LIMIT ? OFFSET ?
        """,
        ("kube-bench", page_size, offset),
    ).fetchall()
    conn.close()

    return {
        "items": [row_to_dict(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@app.get("/kube-bench/{scan_id}")
def kube_bench_details(
    scan_id: str,
    severity: Optional[List[str]] = Query(None),
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()

    scan = cur.execute(
        """
        SELECT id, ts, namespace, release, status
        FROM scans
        WHERE id=? AND release='kube-bench'
        """,
        (scan_id,),
    ).fetchone()

    if not scan:
        conn.close()
        raise HTTPException(404, "kube-bench scan not found")

    where = ["scan_id = ?", "scanner = 'kube-bench'"]
    params: List[Any] = [scan_id]

    if severity:
        normalized = [normalize_severity(s) for s in severity]
        placeholders = ",".join("?" for _ in normalized)
        where.append(f"severity IN ({placeholders})")
        params.extend(normalized)

    if q:
        where.append("(title LIKE ? OR target LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like])

    where_sql = " AND ".join(where)

    total = cur.execute(
        f"SELECT COUNT(*) AS c FROM scan_findings WHERE {where_sql}",
        params,
    ).fetchone()["c"]

    rows = cur.execute(
        f"""
        SELECT id, scanner, severity, target, title, cve_id,
               pkg_name, installed_version, fixed_version,
               cvss_score, description, references_json
        FROM scan_findings
        WHERE {where_sql}
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            id DESC
        LIMIT ? OFFSET ?
        """,
        params + [page_size, offset],
    ).fetchall()

    summary = cur.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low,
            SUM(CASE WHEN severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown
        FROM scan_findings
        WHERE scan_id=? AND scanner='kube-bench'
        """,
        (scan_id,),
    ).fetchone()

    conn.close()

    items = []
    for row in rows:
        item = row_to_dict(row)
        item["references"] = parse_json_list(item.pop("references_json", None))
        items.append(item)

    return {
        "scan": row_to_dict(scan),
        "summary": row_to_dict(summary),
        "findings": {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
        },
    }


@app.get("/scan/list")
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    rows = cur.execute(
        "SELECT id, ts, namespace, release, status FROM scans ORDER BY ts DESC LIMIT ? OFFSET ?",
        (page_size, offset),
    ).fetchall()
    conn.close()
    return {"items": [row_to_dict(r) for r in rows], "page": page, "page_size": page_size, "total": total}


@app.get("/scan/{scan_id}/sbom")
def get_scan_sbom(scan_id: str, image: Optional[str] = None):
    conn = get_conn()
    cur = conn.cursor()

    if not cur.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "scan not found")

    query = "SELECT id, image, format, created_at FROM scan_sbom WHERE scan_id=?"
    params: List[Any] = [scan_id]
    if image:
        query += " AND image=?"
        params.append(image)

    rows = cur.execute(query, params).fetchall()
    conn.close()
    return {"items": [row_to_dict(r) for r in rows]}


@app.get("/scan/{scan_id}/sbom/{sbom_id}/download")
def download_sbom(scan_id: str, sbom_id: int):
    conn = get_conn()
    row = conn.execute(
        "SELECT format, content FROM scan_sbom WHERE id=? AND scan_id=?",
        (sbom_id, scan_id),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "SBOM not found")
    return Response(
        content=row["content"],
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sbom-{sbom_id}.json"'},
    )


@app.get("/scan/diff/{scan1}/{scan2}")
def diff(scan1: str, scan2: str):
    conn = get_conn()
    cur = conn.cursor()

    def _cves(scan_id: str):
        rows = cur.execute(
            "SELECT COALESCE(cve_id, title) AS key FROM scan_findings WHERE scan_id=?",
            (scan_id,),
        ).fetchall()
        return {r["key"] for r in rows if r["key"]}

    f1, f2 = _cves(scan1), _cves(scan2)
    conn.close()
    return {"fixed": list(f1 - f2), "new": list(f2 - f1)}


@app.get("/scan/{scan_id}")
def scan_details(
    scan_id: str,
    severity: Optional[List[str]] = Query(None),
    scanner: Optional[str] = None,
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()

    scan = cur.execute(
        "SELECT id, ts, namespace, release, status FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(404, "scan not found")

    images = cur.execute(
        "SELECT image FROM scan_images WHERE scan_id=? ORDER BY image", (scan_id,)
    ).fetchall()

    where = ["f.scan_id = ?"]
    params: List[Any] = [scan_id]

    if severity:
        normalized = [normalize_severity(s) for s in severity]
        placeholders = ",".join("?" for _ in normalized)
        where.append(f"f.severity IN ({placeholders})")
        params.extend(normalized)

    if scanner:
        where.append("f.scanner = ?")
        params.append(scanner)

    if q:
        where.append("(f.title LIKE ? OR f.target LIKE ? OR f.cve_id LIKE ? OR f.pkg_name LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like])

    where_sql = " AND ".join(where)

    total = cur.execute(
        f"SELECT COUNT(*) AS c FROM scan_findings f WHERE {where_sql}", params
    ).fetchone()["c"]

    findings = cur.execute(f"""
        SELECT
            f.id, f.scanner, f.severity, f.target, f.title, f.cve_id,
            f.pkg_name, f.installed_version, f.fixed_version,
            COALESCE(f.cvss_score, v.cvss_score) AS cvss_score,
            COALESCE(f.description, v.description) AS description,
            COALESCE(f.references_json, v.references_json) AS references_json
        FROM scan_findings f
        LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id
        WHERE {where_sql}
        ORDER BY
            CASE f.severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
                ELSE 5
            END,
            f.id DESC
        LIMIT ? OFFSET ?
    """, params + [page_size, offset]).fetchall()

    conn.close()

    items = []
    for row in findings:
        item = row_to_dict(row)
        item["references"] = parse_json_list(item.pop("references_json", None))
        items.append(item)

    return {
        "scan": row_to_dict(scan),
        "images": [r["image"] for r in images],
        "findings": {"items": items, "page": page, "page_size": page_size, "total": total},
    }


@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: str):
    conn = get_conn()
    cur = conn.cursor()
    row = cur.execute("SELECT namespace FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "scan not found")
    namespace = row["namespace"]
    conn.close()

    run_cmd(["kubectl", "delete", "namespace", namespace], timeout=30)

    conn = get_conn()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.execute("DELETE FROM scan_images WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))
    conn.execute("DELETE FROM scan_sbom WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()

    return {"deleted": scan_id}


# =========================================================
# VULNERABILITY ENDPOINTS
# =========================================================

@app.get("/vulnerabilities")
def list_vulnerabilities(
    severity: Optional[List[str]] = Query(None),
    q: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()

    where = ["1=1"]
    params: List[Any] = []

    if severity:
        normalized = [normalize_severity(s) for s in severity]
        placeholders = ",".join("?" for _ in normalized)
        where.append(f"severity IN ({placeholders})")
        params.extend(normalized)

    if q:
        where.append("(cve_id LIKE ? OR title LIKE ? OR description LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    where_sql = " AND ".join(where)
    total = cur.execute(f"SELECT COUNT(*) AS c FROM vulnerabilities WHERE {where_sql}", params).fetchone()["c"]
    rows = cur.execute(f"""
        SELECT cve_id, severity, cvss_score, title, description,
               published_at, modified_at, source, references_json, updated_at
        FROM vulnerabilities
        WHERE {where_sql}
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
                ELSE 5
            END,
            modified_at DESC
        LIMIT ? OFFSET ?
    """, params + [page_size, offset]).fetchall()
    conn.close()

    items = []
    for row in rows:
        item = row_to_dict(row)
        item["references"] = parse_json_list(item.pop("references_json", None))
        items.append(item)

    return {"items": items, "page": page, "page_size": page_size, "total": total}


@app.get("/vulnerabilities/{cve_id}")
def vulnerability_details(cve_id: str):
    conn = get_conn()
    row = conn.execute("""
        SELECT cve_id, severity, cvss_score, title, description,
               published_at, modified_at, source, references_json, raw_json, updated_at
        FROM vulnerabilities WHERE cve_id=?
    """, (cve_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "vulnerability not found")
    item = row_to_dict(row)
    item["references"] = parse_json_list(item.pop("references_json", None))
    item["raw"] = json.loads(item.pop("raw_json") or "{}")
    return item


class DescriptionUpdate(BaseModel):
    description: str


@app.patch("/vulnerabilities/{cve_id}/description")
def update_vulnerability_description(cve_id: str, body: DescriptionUpdate):
    """Позволяет фронтенду переопределить описание уязвимости."""
    conn = get_conn()
    cur = conn.cursor()
    row = cur.execute("SELECT cve_id FROM vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "vulnerability not found")
    conn.execute(
        "UPDATE vulnerabilities SET description=?, updated_at=? WHERE cve_id=?",
        (body.description, int(time.time() * 1000), cve_id),
    )
    conn.commit()
    conn.close()
    return {"cve_id": cve_id, "updated": True}


@app.post("/scan/{scan_id}/sync-nvd")
def sync_nvd_scan(scan_id: str, background_tasks: BackgroundTasks):
    """
    Обогащает все CVE данного скана данными из NVD (описание, CVSS, ссылки).
    Запускается ВРУЧНУЮ по запросу. Идёт в фоне — может занять минуты из-за rate limit.
    Прогресс смотри в логах; результат — в GET /scan/{scan_id} (поля description/cvss_score).
    Ключ NVD берётся из env NVD_API_KEY (с ключом лимит выше).
    """
    conn = get_conn()
    exists = conn.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
    cve_count = conn.execute(
        """
        SELECT COUNT(DISTINCT cve_id) AS c FROM scan_findings
        WHERE scan_id=? AND cve_id LIKE 'CVE-%'
        """,
        (scan_id,),
    ).fetchone()["c"]
    conn.close()

    if not exists:
        raise HTTPException(404, "scan not found")

    background_tasks.add_task(sync_nvd_for_scan, scan_id)

    return {
        "scan_id": scan_id,
        "status": "syncing",
        "cve_to_sync": cve_count,
        "note": "NVD sync запущен в фоне; результат появится в деталях скана",
    }


@app.post("/vulnerabilities/sync/nvd/{cve_id}")
def sync_nvd_cve(cve_id: str, api_key: Optional[str] = None):
    # NVD содержит только CVE-* идентификаторы.
    # DLA (Debian), GHSA (GitHub) и другие форматы NVD не знает.
    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(400, f"NVD поддерживает только CVE-* идентификаторы, получен: {cve_id}")
    try:
        data = fetch_nvd_cve(cve_id, api_key=api_key)
    except Exception as exc:
        raise HTTPException(502, f"NVD sync failed: {exc}")
    items = data.get("vulnerabilities") or []
    if not items:
        raise HTTPException(404, "CVE not found in NVD")
    parsed = parse_nvd_item(items[0])
    upsert_vulnerability(**parsed)
    return {"synced": parsed["cve_id"], "source": "nvd"}