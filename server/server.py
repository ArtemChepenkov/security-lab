import os
import json
import time
import uuid
import sqlite3
import subprocess
import tempfile
import shutil
from typing import List, Optional

from fastapi.middleware.cors import CORSMiddleware

import yaml
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
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
        title TEXT
    )
    """)

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


def save_finding(scan_id, scanner, severity, target, title):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO scan_findings(scan_id,scanner,severity,target,title) VALUES (?,?,?,?,?)",
        (scan_id, scanner, severity, target, title)
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
                    scan_id,
                    "trivy",
                    v.get("Severity", "UNKNOWN"),
                    img,
                    v.get("Title", v.get("VulnerabilityID"))
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
def list_scans():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT * FROM scans")

    rows = cur.fetchall()

    conn.close()

    return rows


# =========================================================
# SCAN DETAILS
# =========================================================

@app.get("/scan/{scan_id}")
def scan_details(scan_id):

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    scan = cur.fetchone()

    cur.execute("SELECT image FROM scan_images WHERE scan_id=?", (scan_id,))
    images = cur.fetchall()

    cur.execute("""
        SELECT scanner,severity,target,title
        FROM scan_findings
        WHERE scan_id=?
    """, (scan_id,))

    findings = cur.fetchall()

    conn.close()

    return {
        "scan": scan,
        "images": images,
        "findings": findings
    }


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
