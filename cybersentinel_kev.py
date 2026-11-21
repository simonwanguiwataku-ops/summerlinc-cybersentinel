import json
import sqlite3
import urllib.request
import urllib.error
import csv
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timezone
from pathlib import Path

APP_DIR = Path.home() / "CyberSentinel"
DB_PATH = APP_DIR / "cybersentinel_kev.sqlite3"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "Summerlinc-CyberSentinel-KEV/0.3 (local desktop client)"

APP_DIR.mkdir(parents=True, exist_ok=True)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS kev (
            cve_id TEXT PRIMARY KEY,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware TEXT,
            notes TEXT,
            catalog_version TEXT,
            synced_at TEXT
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL DEFAULT '',
            asset_name TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '',
            environment TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            synced_at TEXT NOT NULL,
            catalog_version TEXT,
            count INTEGER,
            status TEXT NOT NULL,
            message TEXT NOT NULL
        )""")
        con.execute("""
        CREATE TABLE IF NOT EXISTS nvd_details (
            cve_id TEXT PRIMARY KEY,
            fetched_at TEXT NOT NULL,
            status TEXT NOT NULL,
            raw_json TEXT NOT NULL
        )""")

def sync_kev(status_callback):
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=45) as response:
            if response.status != 200:
                raise RuntimeError(f"CISA feed returned HTTP {response.status}")
            raw = response.read()
        payload = json.loads(raw.decode("utf-8"))
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise RuntimeError("Unexpected CISA feed format")
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for item in vulnerabilities:
            rows.append((
                item.get("cveID", ""),
                item.get("vendorProject", ""),
                item.get("product", ""),
                item.get("vulnerabilityName", ""),
                item.get("dateAdded", ""),
                item.get("shortDescription", ""),
                item.get("requiredAction", ""),
                item.get("dueDate", ""),
                item.get("knownRansomwareCampaignUse", ""),
                item.get("notes", ""),
                payload.get("catalogVersion", ""),
                now
            ))
        with db() as con:
            con.executemany("""
            INSERT INTO kev VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
              vendor_project=excluded.vendor_project,
              product=excluded.product,
              vulnerability_name=excluded.vulnerability_name,
              date_added=excluded.date_added,
              short_description=excluded.short_description,
              required_action=excluded.required_action,
              due_date=excluded.due_date,
              known_ransomware=excluded.known_ransomware,
              notes=excluded.notes,
              catalog_version=excluded.catalog_version,
              synced_at=excluded.synced_at
            """, rows)
            con.execute("INSERT INTO sync_log(synced_at,catalog_version,count,status,message) VALUES(?,?,?,?,?)",
                        (now, payload.get("catalogVersion", ""), len(rows), "success", "CISA KEV catalog synchronized"))
        status_callback(f"Sync complete: {len(rows):,} KEV records. Catalog version {payload.get('catalogVersion','unknown')}.")
    except Exception as exc:
        now = datetime.now(timezone.utc).isoformat()
        with db() as con:
            con.execute("INSERT INTO sync_log(synced_at,status,message) VALUES(?,?,?)",
                        (now, "failed", str(exc)))
        status_callback(f"Sync failed: {exc}")

def norm(s):
    return " ".join((s or "").lower().replace("-", " ").replace("_", " ").split())


def version_tokens(value):
    """Conservative tokenization for common dotted software versions."""
    import re
    parts = re.findall(r"\d+|[A-Za-z]+", (value or "").lower())
    return [(0, int(x)) if x.isdigit() else (1, x) for x in parts]

def compare_versions(a, b):
    """Return -1, 0, 1 for common numeric/alphanumeric versions; None if unknown."""
    if not a or not b or a in ("*", "-") or b in ("*", "-"):
        return None
    aa, bb = version_tokens(a), version_tokens(b)
    if not aa or not bb:
        return None
    n = max(len(aa), len(bb))
    aa += [(0, 0)] * (n - len(aa))
    bb += [(0, 0)] * (n - len(bb))
    return (aa > bb) - (aa < bb)

def cpe_vendor_product(criteria):
    parts = (criteria or "").split(":")
    # CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return norm(parts[3].replace("\\\\:", ":")), norm(parts[4].replace("\\\\:", ":")), parts[5]
    return "", "", ""

def extract_cpe_matches(node):
    found = []
    for match in node.get("cpeMatch", []) or []:
        if match.get("vulnerable") is True:
            found.append(match)
    for child in node.get("children", []) or []:
        found.extend(extract_cpe_matches(child))
    return found

def nvd_affected_ranges(raw):
    result = []
    for item in raw.get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        for config in cve.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                result.extend(extract_cpe_matches(node))
    return result

def evaluate_version(version, cpe_match):
    criteria = cpe_match.get("criteria", "")
    _, _, cpe_ver = cpe_vendor_product(criteria)
    start_i = cpe_match.get("versionStartIncluding")
    start_e = cpe_match.get("versionStartExcluding")
    end_i = cpe_match.get("versionEndIncluding")
    end_e = cpe_match.get("versionEndExcluding")
    if not version:
        return "Version unknown"
    if cpe_ver not in ("*", "-") and not any((start_i, start_e, end_i, end_e)):
        cmp = compare_versions(version, cpe_ver)
        return "Affected" if cmp == 0 else ("Not in exact affected version" if cmp is not None else "Needs review")
    checks = []
    for bound, relation in ((start_i, "ge"), (start_e, "gt"), (end_i, "le"), (end_e, "lt")):
        if bound:
            cmp = compare_versions(version, bound)
            if cmp is None:
                return "Needs review"
            checks.append(cmp >= 0 if relation == "ge" else cmp > 0 if relation == "gt" else cmp <= 0 if relation == "le" else cmp < 0)
    if not checks:
        return "Version scope unspecified"
    return "Affected" if all(checks) else "Outside affected range"

def fetch_nvd_cve(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as response:
        if response.status != 200:
            raise RuntimeError(f"NVD returned HTTP {response.status}")
        return json.loads(response.read().decode("utf-8"))


def nvd_cvss_summary(raw):
    """Return the highest available NVD CVSS score/severity and vector."""
    candidates = []
    for item in raw.get("vulnerabilities", []) or []:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []) or []:
                data = metric.get("cvssData", {}) or {}
                score = data.get("baseScore")
                if isinstance(score, (int, float)):
                    candidates.append((float(score), str(data.get("baseSeverity") or metric.get("baseSeverity") or "Unknown").upper(), str(data.get("vectorString") or ""), key))
    if not candidates:
        return None, "Not available", "", ""
    # Prefer the highest numeric score; keep the source metric for traceability.
    score, severity, vector, metric = max(candidates, key=lambda x: x[0])
    return score, severity, vector, metric


def risk_priority_score(kev_record, match_status, cvss_score=None):
    """Transparent triage heuristic (0-100), not a probability of compromise."""
    score = 35  # CISA KEV inclusion means exploitation has been observed in the wild.
    if str(kev_record["known_ransomware"]).strip().lower() in ("known", "yes", "true"):
        score += 20
    if cvss_score is not None:
        score += round(min(max(float(cvss_score), 0), 10) * 3)
    status = (match_status or "").lower()
    if "affected version range" in status:
        score += 20
    elif "version unknown" in status or "manual review" in status:
        score += 10
    elif "outside listed" in status or "not confirmed" in status:
        score -= 15
    due = str(kev_record["due_date"] or "")
    if due:
        try:
            days = (datetime.strptime(due, "%Y-%m-%d").date() - datetime.now(timezone.utc).date()).days
            if days < 0: score += 10
            elif days <= 7: score += 7
            elif days <= 30: score += 3
        except ValueError:
            pass
    return max(0, min(100, int(score)))


def priority_label(score):
    return "Critical" if score >= 85 else "High" if score >= 70 else "Elevated" if score >= 50 else "Monitor"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Summerlinc CyberSentinel AI — Live KEV Intelligence v0.3.1")
        self.geometry("1180x760")
        self.minsize(920, 600)
        self.status = tk.StringVar(value=f"Local database: {DB_PATH}")
        self.ui_messages = queue.Queue()
        self.build_ui()
        self.after(150, self.process_ui_messages)
        self.refresh_kev()
        self.refresh_assets()

    def process_ui_messages(self):
        """Apply worker-thread results only on Tk's main thread."""
        try:
            while True:
                message, refresh_dashboard = self.ui_messages.get_nowait()
                self.status.set(message)
                if message.startswith("Sync complete:"):
                    self.sync_button.configure(state="normal", text="Sync CISA KEV now")
                    messagebox.showinfo("CISA KEV synchronization", message)
                elif message.startswith("Sync failed:") or message.startswith("SYNC ERROR:"):
                    self.sync_button.configure(state="normal", text="Retry CISA KEV sync")
                    messagebox.showerror("CISA KEV synchronization failed", message)
                elif "NVD enrichment" in message:
                    pass
                if refresh_dashboard:
                    self.refresh_kev()
                    self.refresh_assets()
                    self.refresh_dashboard()
        except queue.Empty:
            pass
        self.after(150, self.process_ui_messages)

    def build_ui(self):
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")
        ttk.Label(top, text="SUMMERLINC CYBERSENTINEL AI", font=("Segoe UI", 16, "bold")).pack(side="left")
        self.sync_button = ttk.Button(top, text="Sync CISA KEV now", command=self.sync)
        self.sync_button.pack(side="right")
        ttk.Label(self, text="Discover. Test. Protect. Verify.", padding=(12,0)).pack(anchor="w")
        # Prominent feedback: the former bottom-only status was easy to miss.
        status_bar = ttk.Frame(self, padding=(12, 5))
        status_bar.pack(fill="x")
        ttk.Label(status_bar, text="LIVE STATUS:", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(status_bar, textvariable=self.status, wraplength=900).pack(side="left", padx=(8, 0))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=10)
        self.dashboard_tab = ttk.Frame(self.tabs, padding=10)
        self.kev_tab = ttk.Frame(self.tabs, padding=10)
        self.asset_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.dashboard_tab, text="Risk Dashboard")
        self.tabs.add(self.kev_tab, text="KEV Intelligence")
        self.tabs.add(self.asset_tab, text="Authorized Asset Inventory")
        self.build_dashboard_tab()
        self.build_kev_tab()
        self.build_asset_tab()
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=6).pack(fill="x", side="bottom")

    def build_dashboard_tab(self):
        summary = ttk.Frame(self.dashboard_tab)
        summary.pack(fill="x", pady=(0, 10))
        self.metric_vars = {name: tk.StringVar(value="—") for name in ("kev", "assets", "affected", "review", "ransomware")}
        metric_labels = [("kev", "KEV vulnerabilities"), ("assets", "Tracked assets"), ("affected", "Affected-range leads"), ("review", "Needs review"), ("ransomware", "Ransomware-linked KEVs")]
        for key, label in metric_labels:
            card = ttk.LabelFrame(summary, text=label, padding=10)
            card.pack(side="left", fill="x", expand=True, padx=4)
            ttk.Label(card, textvariable=self.metric_vars[key], font=("Segoe UI", 18, "bold")).pack()
        ttk.Label(self.dashboard_tab, text="Priority queue — heuristic triage score, not a probability of compromise. Confirm findings before remediation.", wraplength=1000).pack(anchor="w", pady=(0, 6))
        cols = ("score", "priority", "asset", "product", "cve", "cvss", "status")
        self.priority_tree = ttk.Treeview(self.dashboard_tab, columns=cols, show="headings", height=18)
        labels = {"score":"Score", "priority":"Priority", "asset":"Asset", "product":"Product", "cve":"CVE", "cvss":"CVSS", "status":"Assessment"}
        widths = {"score":65, "priority":90, "asset":170, "product":160, "cve":135, "cvss":75, "status":230}
        for col in cols:
            self.priority_tree.heading(col, text=labels[col])
            self.priority_tree.column(col, width=widths[col], anchor="w")
        self.priority_tree.pack(fill="both", expand=True)
        ttk.Button(self.dashboard_tab, text="Refresh risk dashboard", command=self.refresh_dashboard).pack(anchor="e", pady=8)

    def build_kev_tab(self):
        bar = ttk.Frame(self.kev_tab)
        bar.pack(fill="x", pady=(0,8))
        self.search_var = tk.StringVar()
        ttk.Label(bar, text="Search CVE / vendor / product:").pack(side="left")
        ent = ttk.Entry(bar, textvariable=self.search_var, width=42)
        ent.pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: self.refresh_kev())
        ttk.Button(bar, text="Search", command=self.refresh_kev).pack(side="left")
        ttk.Button(bar, text="Enrich selected CVE from NVD", command=self.enrich_selected).pack(side="right", padx=6)
        ttk.Button(bar, text="Export results CSV", command=self.export_kev).pack(side="right")

        cols = ("cve_id","vendor_project","product","date_added","known_ransomware","due_date")
        self.kev_tree = ttk.Treeview(self.kev_tab, columns=cols, show="headings", height=18)
        labels = {"cve_id":"CVE","vendor_project":"Vendor","product":"Product","date_added":"Date added","known_ransomware":"Ransomware use","due_date":"Due date"}
        widths = {"cve_id":145,"vendor_project":170,"product":200,"date_added":100,"known_ransomware":125,"due_date":100}
        for c in cols:
            self.kev_tree.heading(c, text=labels[c])
            self.kev_tree.column(c, width=widths[c], anchor="w")
        self.kev_tree.pack(fill="both", expand=True)
        self.kev_tree.bind("<<TreeviewSelect>>", self.show_kev_detail)
        self.detail = tk.Text(self.kev_tab, height=8, wrap="word")
        self.detail.pack(fill="x", pady=(8,0))
        self.detail.insert("end", "Select a vulnerability to view its description, required action and notes.")
        self.detail.configure(state="disabled")

    def build_asset_tab(self):
        bar = ttk.Frame(self.asset_tab)
        bar.pack(fill="x", pady=(0,8))
        ttk.Button(bar, text="Add asset", command=self.add_asset).pack(side="left")
        ttk.Button(bar, text="Import assets CSV", command=self.import_assets).pack(side="left", padx=6)
        ttk.Button(bar, text="Export matched findings CSV", command=self.export_matches).pack(side="left")
        ttk.Button(bar, text="Refresh matches", command=self.refresh_assets).pack(side="right")
        cols = ("asset_name","vendor","product","version","environment","matches")
        self.asset_tree = ttk.Treeview(self.asset_tab, columns=cols, show="headings", height=19)
        labels = {"asset_name":"Asset","vendor":"Vendor","product":"Product","version":"Version","environment":"Environment","matches":"KEV matches"}
        widths = {"asset_name":190,"vendor":150,"product":190,"version":100,"environment":130,"matches":100}
        for c in cols:
            self.asset_tree.heading(c, text=labels[c])
            self.asset_tree.column(c, width=widths[c], anchor="w")
        self.asset_tree.pack(fill="both", expand=True)
        ttk.Label(self.asset_tab, text="Matches are preliminary. NVD CPE enrichment is required before version-aware conclusions; a match is not proof of exploitability.", foreground="#9a5b00", wraplength=1000).pack(anchor="w", pady=8)

    def sync(self):
        self.status.set("SYNC STARTED — contacting the official CISA KEV feed. Please wait…")
        self.sync_button.configure(state="disabled", text="Syncing…")
        def callback(msg):
            # Worker threads communicate through a queue; Tkinter is touched only
            # by process_ui_messages() on the main application thread.
            self.ui_messages.put((msg, True))
        def run_sync():
            try:
                sync_kev(callback)
            except Exception as exc:
                callback(f"SYNC ERROR: {type(exc).__name__}: {exc}")
        threading.Thread(target=run_sync, daemon=True, name="CISA-KEV-sync").start()

    def refresh_kev(self):
        q = norm(self.search_var.get())
        with db() as con:
            if q:
                like = f"%{q}%"
                rows = con.execute("""SELECT * FROM kev WHERE lower(cve_id) LIKE ? OR lower(vendor_project) LIKE ? OR lower(product) LIKE ? OR lower(vulnerability_name) LIKE ? ORDER BY date_added DESC""",
                                   (like,like,like,like)).fetchall()
            else:
                rows = con.execute("SELECT * FROM kev ORDER BY date_added DESC LIMIT 1000").fetchall()
        self.kev_rows = rows
        self.kev_tree.delete(*self.kev_tree.get_children())
        for r in rows:
            self.kev_tree.insert("", "end", iid=r["cve_id"], values=(r["cve_id"],r["vendor_project"],r["product"],r["date_added"],r["known_ransomware"],r["due_date"]))

    def show_kev_detail(self, _event=None):
        sel = self.kev_tree.selection()
        if not sel: return
        with db() as con:
            r = con.execute("SELECT * FROM kev WHERE cve_id=?", (sel[0],)).fetchone()
        if not r: return
        with db() as con:
            cached = con.execute("SELECT raw_json FROM nvd_details WHERE cve_id=?", (r["cve_id"],)).fetchone()
        cvss_line = "CVSS: Not enriched"
        if cached:
            try:
                score, severity, vector, metric = nvd_cvss_summary(json.loads(cached["raw_json"]))
                cvss_line = f"CVSS: {score if score is not None else 'Not available'} | {severity} | {metric or 'NVD metric unavailable'}\nVector: {vector}"
            except Exception:
                cvss_line = "CVSS: Cached NVD data could not be parsed"
        text = (f"{r['cve_id']} — {r['vulnerability_name']}\n\n{cvss_line}\n\n"
                f"Vendor: {r['vendor_project']} | Product: {r['product']}\n"
                f"Date added: {r['date_added']} | Due date: {r['due_date']}\n"
                f"Known ransomware campaign use: {r['known_ransomware']}\n\n"
                f"Description:\n{r['short_description']}\n\n"
                f"Required action:\n{r['required_action']}\n\nNotes:\n{r['notes']}")
        self.detail.configure(state="normal")
        self.detail.delete("1.0","end")
        self.detail.insert("end",text)
        self.detail.configure(state="disabled")

    def enrich_selected(self):
        sel = self.kev_tree.selection()
        if not sel:
            messagebox.showinfo("Select a CVE", "Select one CVE in the table first.")
            return
        cve_id = sel[0]
        self.status.set(f"Retrieving NVD data for {cve_id}…")
        def worker():
            try:
                raw = fetch_nvd_cve(cve_id)
                status = "found" if raw.get("vulnerabilities") else "not_found"
                with db() as con:
                    con.execute("INSERT INTO nvd_details(cve_id,fetched_at,status,raw_json) VALUES(?,?,?,?) "
                                "ON CONFLICT(cve_id) DO UPDATE SET fetched_at=excluded.fetched_at,status=excluded.status,raw_json=excluded.raw_json",
                                (cve_id, datetime.now(timezone.utc).isoformat(), status, json.dumps(raw)))
                msg = f"NVD enrichment saved for {cve_id}." if status == "found" else f"NVD returned no CVE record for {cve_id}."
            except Exception as exc:
                msg = f"NVD enrichment failed for {cve_id}: {exc}"
            self.ui_messages.put((msg, True))
        threading.Thread(target=worker, daemon=True, name="NVD-enrichment").start()

    def export_kev(self):
        if not self.kev_rows:
            messagebox.showinfo("Export","No KEV records to export."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], initialfile="cybersentinel_kev.csv")
        if not path: return
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(self.kev_rows[0].keys())
            for r in self.kev_rows: w.writerow([r[k] for k in r.keys()])
        self.status.set(f"Exported {len(self.kev_rows)} KEV records to {path}")

    def add_asset(self):
        win = tk.Toplevel(self); win.title("Add authorized asset"); win.resizable(False,False)
        fields = ["organization","asset_name","vendor","product","version","environment","owner","notes"]
        vars = {}
        for i, name in enumerate(fields):
            ttk.Label(win,text=name.replace("_"," ").title()).grid(row=i,column=0,sticky="w",padx=10,pady=4)
            vars[name]=tk.StringVar()
            ttk.Entry(win,textvariable=vars[name],width=42).grid(row=i,column=1,padx=10,pady=4)
        def save():
            if not vars["asset_name"].get().strip() or not vars["vendor"].get().strip() or not vars["product"].get().strip():
                messagebox.showerror("Missing fields","Asset name, vendor and product are required."); return
            with db() as con:
                con.execute("""INSERT INTO assets(organization,asset_name,vendor,product,version,environment,owner,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                            tuple(vars[k].get().strip() for k in fields)+(datetime.now(timezone.utc).isoformat(),))
            win.destroy(); self.refresh_assets()
        ttk.Button(win,text="Save asset",command=save).grid(row=len(fields),column=1,sticky="e",padx=10,pady=10)

    def import_assets(self):
        path=filedialog.askopenfilename(filetypes=[("CSV","*.csv")])
        if not path:return
        required={"asset_name","vendor","product"}
        try:
            with open(path,newline="",encoding="utf-8-sig") as f:
                reader=csv.DictReader(f)
                if not required.issubset(set(reader.fieldnames or [])):
                    raise ValueError("CSV must include asset_name, vendor and product columns.")
                count=0
                with db() as con:
                    for row in reader:
                        con.execute("""INSERT INTO assets(organization,asset_name,vendor,product,version,environment,owner,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (row.get("organization",""),row.get("asset_name",""),row.get("vendor",""),row.get("product",""),row.get("version",""),row.get("environment",""),row.get("owner",""),row.get("notes",""),datetime.now(timezone.utc).isoformat()))
                        count+=1
            self.refresh_assets(); self.status.set(f"Imported {count} assets.")
        except Exception as exc: messagebox.showerror("Import failed",str(exc))

    def get_matches(self):
        with db() as con:
            assets = con.execute("SELECT * FROM assets ORDER BY asset_name").fetchall()
            kevs = con.execute("SELECT * FROM kev").fetchall()
            nvd_rows = con.execute("SELECT cve_id,raw_json,status FROM nvd_details").fetchall()
        nvd = {}
        for row in nvd_rows:
            try:
                nvd[row["cve_id"]] = (row["status"], json.loads(row["raw_json"]))
            except Exception:
                nvd[row["cve_id"]] = ("invalid", {})
        result = []
        for a in assets:
            av, ap = norm(a["vendor"]), norm(a["product"])
            matches = []
            for k in kevs:
                kv, kp = norm(k["vendor_project"]), norm(k["product"])
                if not (av and ap and (av in kv or kv in av) and (ap in kp or kp in ap)):
                    continue
                state = "Needs NVD enrichment"
                nvd_entry = nvd.get(k["cve_id"])
                if nvd_entry and nvd_entry[0] == "found":
                    cpe_matches = nvd_affected_ranges(nvd_entry[1])
                    relevant = []
                    for cm in cpe_matches:
                        cv, cp, _ = cpe_vendor_product(cm.get("criteria", ""))
                        if cv and cp and (av in cv or cv in av) and (ap in cp or cp in ap):
                            relevant.append(cm)
                    if relevant:
                        evaluations = [evaluate_version(a["version"], cm) for cm in relevant]
                        if "Affected" in evaluations:
                            state = "Affected version range"
                        elif "Version unknown" in evaluations:
                            state = "Version unknown"
                        elif "Needs review" in evaluations:
                            state = "Needs manual review"
                        elif "Version scope unspecified" in evaluations:
                            state = "Version scope unspecified"
                        else:
                            state = "Outside listed affected range"
                    else:
                        state = "Product match not confirmed by NVD CPE"
                matches.append((k, state))
            result.append((a, matches))
        return result

    def refresh_assets(self):
        if not hasattr(self,"asset_tree"): return
        self.asset_tree.delete(*self.asset_tree.get_children())
        for a, matches in self.get_matches():
            iid=str(a["id"])
            self.asset_tree.insert("", "end", iid=iid, values=(a["asset_name"],a["vendor"],a["product"],a["version"],a["environment"],len(matches)))
        self.refresh_dashboard()

    def refresh_dashboard(self):
        if not hasattr(self, "priority_tree"):
            return
        with db() as con:
            kev_count = con.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
            asset_count = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            ransomware_count = con.execute("SELECT COUNT(*) FROM kev WHERE lower(known_ransomware) IN ('known','yes','true')").fetchone()[0]
        self.metric_vars["kev"].set(f"{kev_count:,}")
        self.metric_vars["assets"].set(f"{asset_count:,}")
        self.metric_vars["ransomware"].set(f"{ransomware_count:,}")
        rows = []
        affected = review = 0
        for asset, matches in self.get_matches():
            for kev, state in matches:
                if "Affected version range" in state:
                    affected += 1
                if "review" in state.lower() or "unknown" in state.lower() or "enrichment" in state.lower():
                    review += 1
                cvss = None
                with db() as con:
                    cached = con.execute("SELECT raw_json FROM nvd_details WHERE cve_id=?", (kev["cve_id"],)).fetchone()
                if cached:
                    try: cvss = nvd_cvss_summary(json.loads(cached["raw_json"]))[0]
                    except Exception: pass
                score = risk_priority_score(kev, state, cvss)
                rows.append((score, priority_label(score), asset["asset_name"], asset["product"], kev["cve_id"], f"{cvss:.1f}" if cvss is not None else "—", state))
        self.metric_vars["affected"].set(f"{affected:,}")
        self.metric_vars["review"].set(f"{review:,}")
        self.priority_tree.delete(*self.priority_tree.get_children())
        rows.sort(key=lambda item: item[0], reverse=True)
        for index, row in enumerate(rows[:250]):
            self.priority_tree.insert("", "end", iid=f"risk-{index}", values=row)

    def export_matches(self):
        matches=self.get_matches()
        path=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile="cybersentinel_asset_kev_matches.csv")
        if not path:return
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f); w.writerow(["asset_name","vendor","product","version","cve_id","date_added","description","required_action","match_type"])
            for a, ks in matches:
                for k, match_status in ks:
                    w.writerow([a["asset_name"],a["vendor"],a["product"],a["version"],k["cve_id"],k["date_added"],k["short_description"],k["required_action"],match_status])
        self.status.set(f"Exported matched findings to {path}")

if __name__ == "__main__":
    init_db()
    App().mainloop()
