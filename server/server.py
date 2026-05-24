import os
import json
import time
import uuid
import sqlite3
import subprocess
import tempfile
import urllib.parse
import urllib.request
import shutil
from typing import List, Optional, Any, Dict
from fastapi.middleware.cors import CORSMiddleware

import yaml
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import JSONResponse

DB_PATH = "./data/scans.db"
os.makedirs("./data", exist_ok=True)

app = FastAPI(title="Security Scan API")
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

    # Миграция для уже существующей локальной БД, где таблица scan_findings
    # была создана старой версией сервера.
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

    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_severity ON scan_findings(scan_id, severity)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_findings_cve ON scan_findings(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)")

    conn.commit()
    conn.close()

init_db()


# =========================================================
# UTIL
# =========================================================

def run_cmd(cmd: List[str]):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr
    }

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

def normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    value = value.upper()
    return value if value in SEVERITY_ORDER else "UNKNOWN"

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


def extract_cvss_from_trivy(vuln: Dict[str, Any]):
    # Trivy может отдавать CVSS по разным источникам: nvd, redhat, ghsa и т.д.
    cvss = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        item = cvss.get(source)
        if item and item.get("V3Score") is not None:
            return float(item["V3Score"])
    for item in cvss.values():
        if isinstance(item, dict) and item.get("V3Score") is not None:
            return float(item["V3Score"])
    return None


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
    cur = conn.cursor()
    cur.execute("""
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
    references = [r.get("url") for r in cve.get("references", {}).get("referenceData", []) if r.get("url")]

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


def create_scan(release):

    scan_id = uuid.uuid4().hex[:8]
    namespace = f"scan-{scan_id}"

    run_cmd(["kubectl", "create", "namespace", namespace])

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?)",
        (scan_id, int(time.time()*1000), namespace, release, "created")
    )
    print(release, flush=True)
    conn.commit()
    conn.close()

    return scan_id, namespace


def save_images(scan_id, images):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for img in images:
        cur.execute(
            "INSERT INTO scan_images(scan_id,image) VALUES (?,?)",
            (scan_id, img)
        )

    conn.commit()
    conn.close()


def save_finding(
    scan_id,
    scanner,
    severity,
    target,
    title,
    cve_id=None,
    pkg_name=None,
    installed_version=None,
    fixed_version=None,
    cvss_score=None,
    description=None,
    references=None,
):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO scan_findings(
            scan_id, scanner, severity, target, title, cve_id, pkg_name,
            installed_version, fixed_version, cvss_score, description, references_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            scan_id,
            scanner,
            normalize_severity(severity),
            target,
            title,
            cve_id,
            pkg_name,
            installed_version,
            fixed_version,
            cvss_score,
            description,
            json.dumps(references or []),
        )
    )

    conn.commit()
    conn.close()


def run_kube_bench_local(scan_id):
    report_file = tempfile.mkstemp(suffix=".json")
    print(report_file)
    cmd = [
        "sudo",
        "kube-bench",
        "run",
        "--benchmark", "cis-1.9",
        "--targets", "node,master,etcd,controlplane",
        "--json"
    ]

    env = os.environ.copy()
    env["KUBECONFIG"] = env.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))

    with open(report_file[1], "w") as f:
        proc = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, env=env)

    if proc.returncode != 0:
        print("kube-bench failed:", proc.stderr)
        return

    try:
        with open(report_file[1]) as f:
            data = json.load(f)
    except Exception as e:
        print("parse error:", e)
        return

    parse_kube_bench(scan_id, data)

def parse_kube_bench(scan_id, data):

    for control in data.get("Controls", []):
        for test in control.get("tests", []):
            for result in test.get("results", []):
                status = result.get("status", "UNKNOWN")
                desc = result.get("test_desc", "")
                test_id = result.get("test_number", "")

                if status == "PASS":
                    continue

                severity_map = {
                    "FAIL": "HIGH",
                    "WARN": "MEDIUM",
                    "INFO": "LOW"
                }

                severity = severity_map.get(status, "LOW")

                save_finding(
                    scan_id,
                    "kube-bench",
                    severity,
                    "cluster",
                    f"{test_id}: {desc}"
                )

# =========================================================
# GET IMAGES FROM PODS
# =========================================================

def get_images(namespace):

    res = run_cmd([
        "kubectl",
        "get",
        "pods",
        "-n",
        namespace,
        "-o",
        "json"
    ])

    data = json.loads(res["stdout"])

    images = []

    for pod in data["items"]:
        for c in pod["spec"]["containers"]:
            images.append(c["image"])

    return list(set(images))


# =========================================================
# FAKE SCANNER (пример)
# =========================================================

def fake_scan(scan_id, images):

    for img in images:

        res = run_cmd([
            "trivy",
            "image",
            "-f",
            "json",
            "--quiet",
            img
        ])

        if res["code"] != 0:
            print("Trivy failed:", res["stderr"])
            continue

        data = json.loads(res["stdout"])

        results = data.get("Results", [])

        for r in results:

            vulns = r.get("Vulnerabilities", [])

            for v in vulns:

                save_finding(
                    scan_id=scan_id,
                    scanner="trivy",
                    severity=v.get("Severity", "UNKNOWN"),
                    target=img,
                    title=v.get("Title") or v.get("VulnerabilityID"),

                    cve_id=v.get("VulnerabilityID"),
                    pkg_name=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),

                    cvss_score=extract_cvss_from_trivy(v),

                    description=v.get("Description"),

                    references=v.get("References", [])
            )

# =========================================================
# START SCAN
# =========================================================

@app.post("/scan/start")
async def start_scan(
        release: str = Form(...),
        chart: UploadFile = File(...)
):

    if not chart.filename.endswith(".tgz"):
        raise HTTPException(400, "chart must be tgz")

    scan_id, namespace = create_scan(release)

    tmp = tempfile.mkdtemp()
    chart_path = os.path.join(tmp, chart.filename)

    with open(chart_path, "wb") as f:
        shutil.copyfileobj(chart.file, f)

    run_cmd([
        "helm",
        "upgrade",
        "--install",
        release,
        chart_path,
        "-n",
        namespace
    ])

    time.sleep(5)

    images = get_images(namespace)

    save_images(scan_id, images)

    fake_scan(scan_id, images)

    return {
        "scan_id": scan_id,
        "namespace": namespace,
        "images": images
    }


@app.post("/scan/kube-bench")
def run_kube_bench():

    scan_id = uuid.uuid4().hex[:8]

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?)",
        (
            scan_id, 
            int(time.time()*1000), 
            "cluster-wide",
            "kube-bench", 
            "running")
    )

    conn.commit()
    conn.close()

    # запускаем kube-bench
    res = run_cmd([
        "kube-bench",
        "run",
        "--json"
    ])

    if res["code"] != 0:
        return {
            "scan_id": scan_id,
            "error": res["stderr"]
        }

    data = json.loads(res["stdout"])

    findings_count = 0

    for control in data.get("Controls", []):
        for group in control.get("groups", []):
            for check in group.get("checks", []):

                state = check.get("state")

                if state not in ["FAIL", "WARN"]:
                    continue

                severity = "LOW"
                if state == "FAIL":
                    severity = "HIGH"
                elif state == "WARN":
                    severity = "MEDIUM"

                save_finding(
                    scan_id,
                    "kube-bench",
                    severity,
                    check.get("id"),
                    check.get("text")
                )

                findings_count += 1

    # обновляем статус
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "UPDATE scans SET status=? WHERE id=?",
        ("done", scan_id)
    )

    conn.commit()
    conn.close()

    return {
        "scan_id": scan_id,
        "findings": findings_count,
        "status": "done"
    }


# =========================================================
# LIST SCANS
# =========================================================

@app.get("/scan/list")
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    page, page_size, offset = build_pagination(page, page_size)
    conn = get_conn()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    rows = cur.execute("""
        SELECT id, ts, namespace, release, status
        FROM scans
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
    """, (page_size, offset)).fetchall()

    conn.close()

    return {
        "items": [row_to_dict(r) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
    }

# =========================================================
# SCAN DETAILS
# =========================================================

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

    scan = cur.execute("SELECT id, ts, namespace, release, status FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(404, "scan not found")

    images = cur.execute("SELECT image FROM scan_images WHERE scan_id=? ORDER BY image", (scan_id,)).fetchall()

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

    total = cur.execute(f"""
        SELECT COUNT(*) AS c
        FROM scan_findings f
        WHERE {where_sql}
    """, params).fetchone()["c"]

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
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
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
        "findings": {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
        }
    }

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
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
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
    cur = conn.cursor()
    row = cur.execute("""
        SELECT cve_id, severity, cvss_score, title, description,
               published_at, modified_at, source, references_json, raw_json, updated_at
        FROM vulnerabilities
        WHERE cve_id=?
    """, (cve_id,)).fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "vulnerability not found")

    item = row_to_dict(row)
    item["references"] = parse_json_list(item.pop("references_json", None))
    item["raw"] = json.loads(item.pop("raw_json") or "{}")
    return item


@app.post("/vulnerabilities/sync/nvd/{cve_id}")
def sync_nvd_cve(cve_id: str, api_key: Optional[str] = None):
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



# =========================================================
# DIFF SCANS
# =========================================================

@app.get("/scan/diff/{scan1}/{scan2}")
def diff(scan1, scan2):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    SELECT title FROM scan_findings
    WHERE scan_id=?
    """, (scan1,))

    f1 = set(r[0] for r in cur.fetchall())

    cur.execute("""
    SELECT title FROM scan_findings
    WHERE scan_id=?
    """, (scan2,))

    f2 = set(r[0] for r in cur.fetchall())

    conn.close()

    fixed = list(f1 - f2)
    new = list(f2 - f1)

    return {
        "fixed": fixed,
        "new": new
    }


# =========================================================
# DELETE SCAN
# =========================================================

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT namespace FROM scans WHERE id=?", (scan_id,))
    ns = cur.fetchone()

    if not ns:
        raise HTTPException(404)

    namespace = ns[0]

    run_cmd(["kubectl", "delete", "namespace", namespace])

    cur.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    cur.execute("DELETE FROM scan_images WHERE scan_id=?", (scan_id,))
    cur.execute("DELETE FROM scan_findings WHERE scan_id=?", (scan_id,))

    conn.commit()
    conn.close()

    return {"deleted": scan_id}
