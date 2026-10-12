#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdminHunter v1.0.0 -- Admin portal discovery & admin-user exposure assessment.
Built for Kali Linux; runs anywhere with Python 3.8+ and `requests`.

  1. Target recon          - DNS resolution, rDNS, CDN/WAF header detection
  2. CMS fingerprinting    - maps detected stack to its known admin paths
  3. Admin subdomain sweep - admin.* cpanel.* portal.* dashboard.* ...
  4. Control-panel ports   - cPanel/WHM, Plesk, Webmin, DirectAdmin, Tomcat...
  5. Admin portal finder   - robots.txt hints + wordlist scan with soft-404
                             filtering and login-form confirmation
  6. Admin-user exposure   - "who uses the admin portal and from which IP":
                             Apache mod_status, world-readable access logs,
                             WordPress user enumeration, .env/.git leaks.

  NOTE: admin-user IPs exist only in server-side state (logs, status pages).
  This tool detects the real leak channels and reports them as findings.

LEGAL: use only on systems you own or have written authorization to test.
"""
import argparse, concurrent.futures as cf, hashlib, json, os, random, re, socket
import string, sys, threading, time
from collections import defaultdict
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlparse

try:
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] Missing dependency 'requests'. Install: pip install requests")

__version__ = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
TTY = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))

def c(code, s): return "\033[%sm%s\033[0m" % (code, s) if TTY else str(s)
def info(m): print(c("36", "[*] ") + str(m))
def ok(m):   print(c("32", "[+] ") + str(m))
def warn(m): print(c("33", "[!] ") + str(m))
def crit(m): print(c("31", "[!!] ") + str(m))
def dim(m):  print(c("90", "    " + str(m)))
def section(t): print("\n" + c("1;36", "=== %s %s" % (t, "=" * max(0, 68 - len(t)))))

SEVC = {"critical": "31", "high": "31", "medium": "33", "low": "33", "info": "36"}

class Findings:
    def __init__(self): self.items = []
    def add(self, sev, title, detail, extra=None):
        self.items.append({"severity": sev, "title": title, "detail": detail,
                           "extra": extra or {}})
        print(c(SEVC.get(sev, "0"), "[%s] %s" % (sev.upper(), title)))
        for ln in str(detail).splitlines(): dim(ln)
    def count(self, sev): return sum(1 for i in self.items if i["severity"] == sev)

def normalize_target(raw):
    raw = raw.strip()
    if "://" not in raw: raw = "http://" + raw
    p = urlparse(raw)
    host, scheme, port = p.hostname, (p.scheme or "http").lower(), p.port
    if not host: raise ValueError("cannot parse host from %r" % raw)
    port = port or (443 if scheme == "https" else 80)
    base = "%s://%s" % (scheme, host) + ("" if port in (80, 443) else ":%d" % port)
    return {"scheme": scheme, "host": host, "port": port, "base": base}

class Client:
    """Thread-safe HTTP client: one requests.Session per worker thread."""
    def __init__(self, base, timeout=8.0, ua=None, proxy=None, verify=False):
        self.base, self.timeout, self.verify, self.proxy = base.rstrip("/"), timeout, verify, proxy
        self.ua = ua or "AdminHunter/%s (+authorized-security-testing)" % __version__
        self._l = threading.local()
    def _s(self):
        s = getattr(self._l, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": self.ua,
                              "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
            s.verify = self.verify
            if self.proxy: s.proxies = {"http": self.proxy, "https": self.proxy}
            self._l.s = s
        return s
    def get(self, path, redir=True):
        url = path if path.startswith("http") else self.base + (path if path.startswith("/") else "/" + path)
        s = self._s()
        for i in range(2):
            try: return s.get(url, timeout=self.timeout, allow_redirects=redir)
            except requests.RequestException:
                if i: time.sleep(0.4)
        return None

# --------------------------- knowledge base --------------------------------
CMS_SIGS = [
    ("WordPress", [r"wp-content", r"wp-includes", r"/wp-json"]),
    ("Joomla", [r"joomla", r"com_content"]),
    ("Drupal", [r"drupal", r"sites/default/files"]),
    ("Magento", [r"magento", r"skin/frontend"]),
    ("Ghost", [r"ghost-sdk", r"/ghost/"]),
    ("phpMyAdmin", [r"phpmyadmin", r"pma_absolute_uri"]),
    ("Tomcat", [r"apache tomcat", r"/manager/html"]),
    ("Jenkins", [r"jenkins-", r"hudson"]),
    ("Grafana", [r"grafana"]),
    ("Laravel", [r"laravel_session", r"laravel"]),
]
CMS_ADMIN = {
    "WordPress": ["/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users"],
    "Joomla": ["/administrator/", "/administrator/index.php"],
    "Drupal": ["/user/login", "/admin"],
    "Magento": ["/admin", "/index.php/admin"],
    "phpMyAdmin": ["/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/"],
    "Tomcat": ["/manager/html", "/host-manager/html"],
    "Jenkins": ["/login", "/manage/"],
    "Grafana": ["/login"],
    "Laravel": ["/admin/login", "/telescope"],
    "Ghost": ["/ghost/", "/ghost/signin"],
}
CDN_HINTS = [("cf-ray", "Cloudflare"), ("cf-cache-status", "Cloudflare"),
             ("x-amz-cf-id", "AWS CloudFront"), ("x-served-by", "Fastly"),
             ("x-vercel-id", "Vercel"), ("x-shopify-stage", "Shopify"),
             ("x-iinfo", "Imperva/Incapsula WAF"), ("x-cdn", "generic CDN")]

ADMIN_SUBS = ["admin", "administrator", "adm", "adminpanel", "control",
              "controlpanel", "cp", "cpanel", "whm", "portal", "manage",
              "manager", "backend", "panel", "dashboard", "cms", "staging",
              "dev", "pma", "phpmyadmin", "mysql", "jenkins", "grafana",
              "kibana", "intranet", "secure"]

ADMIN_PORTS = [
    (2082, "cPanel HTTP"), (2083, "cPanel SSL"), (2086, "WHM HTTP"),
    (2087, "WHM SSL"), (2095, "cPanel Webmail"), (2096, "Webmail SSL"),
    (2222, "DirectAdmin"), (8443, "Plesk/Tomcat SSL"), (10000, "Webmin"),
    (4848, "GlassFish"), (7001, "WebLogic Admin"), (8080, "Tomcat/Jenkins"),
    (8000, "generic dev/admin"), (5601, "Kibana"), (3000, "Grafana/Node"),
    (15672, "RabbitMQ Mgmt"), (8161, "ActiveMQ console"),
    (9443, "WebSphere SSL"), (9090, "generic admin console"),
]
EXTRA_PORTS = [(3306, "MySQL exposed"), (5432, "PostgreSQL exposed"),
               (6379, "Redis exposed"), (5985, "WinRM HTTP"),
               (8888, "Jupyter/panel"), (4443, "admin SSL (generic)")]

LOG_PATHS = [
    "/access.log", "/access_log", "/logs/access.log", "/log/access.log",
    "/logs/access_log", "/apache/logs/access.log", "/apache/logs/access_log",
    "/httpd/logs/access_log", "/var/log/access.log", "/var/log/nginx/access.log",
    "/logs/nginx/access.log", "/wwwlogs/access.log", "/nginx/logs/access.log",
    "/logs/error.log", "/error.log", "/logs/admin.log", "/logs/app.log",
    "/logs/auth.log", "/var/log/auth.log", "/admin/logs/access.log",
    "/logs/prod.log", "/web/logs/access.log",
]

EMBEDDED = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php", "/admin.php",
    "/admin.html", "/adminpanel", "/adminarea", "/admincp", "/administrator",
    "/administrator/", "/administrator/index.php", "/admin/dashboard",
    "/admin/home", "/controlpanel", "/control-panel", "/cp", "/cpanel",
    "/cpanel/", "/secure", "/secure/login", "/management", "/manager",
    "/manager/", "/manager/html", "/host-manager/html", "/dashboard",
    "/dashboard/admin", "/dashboard/login", "/panel", "/panel/login",
    "/backend", "/backend/admin", "/backend/login", "/backoffice", "/webadmin",
    "/siteadmin", "/sysadmin", "/superadmin", "/login", "/login/", "/login.php",
    "/login/admin", "/signin", "/auth/login", "/user/login", "/users/login",
    "/member/login", "/cms", "/cms/admin", "/console", "/wp-admin",
    "/wp-admin/", "/wp-login.php", "/blog/wp-admin", "/wordpress/wp-admin",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/myadmin", "/mysql", "/adminer.php",
    "/adm", "/adm/", "/typo3/", "/umbraco/", "/sitecore/", "/ghost/",
    "/jenkins/login", "/grafana/login", "/kibana",
]

PASS_RE = re.compile(r'type\s*=\s*["\']?password', re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
ADMINISH = re.compile(r"(?i)(admin|manager|login|panel|dashboard|cpanel|phpmy|pma|backend|private|internal|control|webmail|portal)")
STRONG = re.compile(r"(?i)(wp-admin|wp-login|/administrator|admin[\w./-]*|manager/html|phpmyadmin|/pma|cpanel|/dashboard|webadmin|/backend)")
LOG_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(?:\S+\s+\S+\s+)?\[([^\]]+)\]\s+\"(\S+)\s+([^\"\s]+)[^\"]*\"\s+(\d{3})\s+(\d+|-)", re.M)

def title_of(h):
    m = TITLE_RE.search(h or "")
    return re.sub(r"\s+", " ", unescape(m.group(1))).strip()[:80] if m else ""
def tags(x): return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", x or ""))).strip()
def is_ip(s): return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", (s or "").strip()))
def md5(b): return hashlib.md5(b or b"").hexdigest()

# ------------------------------ modules ------------------------------------
def recon(t, home, meta, F):
    section("Target & hosting recon")
    hdr = {k.lower(): v for k, v in (home.headers or {}).items()}
    info("Server header : %s" % hdr.get("server", "(not disclosed)"))
    info("X-Powered-By  : %s" % hdr.get("x-powered-by", "(not disclosed)"))
    cdns = sorted({n for h, n in CDN_HINTS if h in hdr})
    if "cloudflare" in hdr.get("server", "").lower() and "Cloudflare" not in cdns:
        cdns.append("Cloudflare")
    meta["cdn"] = cdns
    if cdns:
        warn("CDN/WAF detected: %s (origin IP may be hidden)" % ", ".join(cdns))
    else:
        ok("No common CDN/WAF headers detected.")
    try:
        socket.setdefaulttimeout(4)
        ips = sorted({i[4][0] for i in socket.getaddrinfo(t["host"], None)})
    except Exception as e:
        warn("DNS resolution failed: %s" % e); return
    meta["ips"] = ips
    for ip in ips:
        try: rdns = socket.gethostbyaddr(ip)[0]
        except Exception: rdns = "-"
        priv = ip.startswith(("10.", "192.168.", "172.16.", "172.31.", "127."))
        ok("Resolved %s -> %s%s | rDNS: %s" % (t["host"], ip,
           " (private)" if priv else "", rdns))
    meta["primary_ip"] = ips[0] if ips else None

def fingerprint(client, home, meta, F):
    section("CMS / framework fingerprinting")
    body, t = home.text or "", title_of(home.text or "")
    if t: ok("Page title: %s" % t)
    meta["title"] = t
    for name, sigs in CMS_SIGS:
        if any(re.search(s, body, re.I) for s in sigs):
            meta["cms"].append(name); ok("Detected: %s" % name)
    if not meta["cms"]: dim("No well-known CMS markers found (custom stack?).")

def robots_hints(client, F, paths):
    section("robots.txt hints")
    r = client.get("/robots.txt")
    if r is None or r.status_code != 200 or "user-agent" not in (r.text or "").lower():
        dim("No useful robots.txt."); return
    ok("robots.txt found")
    for line in (r.text or "").splitlines():
        m = re.match(r"(?i)^\s*disallow\s*:\s*(\S.*)$", line.strip())
        if m and ADMINISH.search(m.group(1)):
            p = m.group(1)
            warn("robots.txt hides: %s" % p)
            paths.add(p if p.startswith("/") else "/" + p)
            F.add("info", "robots.txt references an admin-ish path",
                  "Disallow: %s - owners often disallow crawlers from admin "
                  "areas, which reveals the location." % p)

def subdomain_sweep(t, F):
    section("Admin subdomain enumeration (DNS)")
    found = []
    def resolve(name):
        try:
            return name, sorted({i[4][0] for i in socket.getaddrinfo(name + "." + t["host"], None)})
        except Exception:
            return name, None
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for name, ips in ex.map(resolve, ADMIN_SUBS):
            if ips:
                found.append((name, ips))
                ok("Admin-ish subdomain: %s.%s -> %s" % (name, t["host"], ", ".join(ips)))
                F.add("info", "Admin-ish subdomain exists",
                      "%s.%s resolves to %s - check it for its own admin panel."
                      % (name, t["host"], ", ".join(ips)), {"ips": ips})
    if not found: dim("None of %d common admin subdomains resolve." % len(ADMIN_SUBS))

def port_sweep(t, client, F, full=False):
    section("Control-panel port probing")
    ports = list(ADMIN_PORTS) + (EXTRA_PORTS if full else [])
    sslp = {8443, 2083, 2087, 2096, 9443}
    def probe(item):
        port, _ = item
        s = socket.socket(); s.settimeout(3.0)
        try:
            return item if s.connect_ex((t["host"], port)) == 0 else None
        finally: s.close()
    hits = []
    with cf.ThreadPoolExecutor(max_workers=24) as ex:
        for x in ex.map(probe, ports):
            if x: hits.append(x)
    for port, label in hits:
        title = ""
        for sch in (("https", "http") if port in sslp else ("http", "https")):
            r = client.get("%s://%s:%d/" % (sch, t["host"], port))
            if r is not None:
                title = title_of(r.text or ""); break
        warn("OPEN %s:%d - %s%s" % (t["host"], port, label,
             (" | " + title) if title else ""))
        F.add("low", "Control-panel service on port %d" % port,
              "%s:%d (%s)%s - admin surfaces on non-standard ports are common "
              "entry points." % (t["host"], port, label,
              (" - title: %s" % title) if title else ""), {"port": port})
    if not hits: dim("No common control-panel ports open.")

def load_paths(args):
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
            wl = [x.strip() for x in f if x.strip() and not x.startswith("#")]
        info("Wordlist: %s (%d paths)" % (args.wordlist, len(wl))); return wl
    bundled = os.path.join(HERE, "wordlists", "admin_paths.txt")
    if os.path.isfile(bundled):
        with open(bundled, encoding="utf-8", errors="ignore") as f:
            wl = [x.strip() for x in f if x.strip() and not x.startswith("#")]
        info("Bundled wordlist (%d paths)" % len(wl)); return wl
    warn("No wordlist file - using built-in list (%d paths)" % len(EMBEDDED))
    return list(EMBEDDED)

def scan_paths(client, paths, base, F, threads=20, delay=0.0, exts=""):
    section("Admin portal discovery (%d paths, %d threads)" % (len(paths), threads))
    if exts:
        el = ["." + e.strip(". ") for e in exts.split(",") if e.strip(". ")]
        paths = paths + [p + e for p in paths
                         if not re.search(r"\.(php\d?|html?|jsp|aspx?)$", p, re.I)
                         for e in el]
    paths = list(dict.fromkeys(paths))
    res = []
    def work(p):
        if delay: time.sleep(delay)
        r = client.get(p)
        if r is None or r.status_code == 404: return None
        if r.status_code == base["status"] and md5(r.content) == base["md5"]:
            return None  # soft-404: server returns 200 'not found' page
        body = (r.text or "")[:30000]
        return {"path": p, "status": r.status_code, "final": r.url,
                "title": title_of(body), "login": bool(PASS_RE.search(body)),
                "len": len(r.content or b"")}
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for x in ex.map(work, paths):
            if x:
                res.append(x)
                tag = c("32", "LOGIN PAGE") if x["login"] else c("33", "exists")
                ok("[HTTP %d] %-30s -> %s %s %s" % (x["status"], x["path"],
                   x["final"], ("| " + x["title"]) if x["title"] else "", tag))
                if x["login"]:
                    F.add("info", "Admin login page discovered",
                          "%s -> %s (HTTP %d, title: %s)" % (x["path"],
                          x["final"], x["status"], x["title"] or "n/a"),
                          {"path": x["path"], "final": x["final"]})
    dim("Checked %d paths; %d candidate(s)." % (len(paths), len(res)))
    return res

def parse_mod_status(text):
    users = defaultdict(list); ci = ri = None
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", text, re.S | re.I):
        cells = [tags(x) for x in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S | re.I)]
        if not cells: continue
        if "Client" in cells:
            ci = cells.index("Client")
            ri = cells.index("Request") if "Request" in cells else None
            continue
        if ci is not None and len(cells) > ci and is_ip(cells[ci]):
            users[cells[ci]].append(cells[ri] if ri is not None and len(cells) > ri else "")
    return dict(users)

def exposure(client, admin_paths, F):
    section("Admin-user exposure checks (who uses the portal, from which IP)")
    hit = False
    for p in ("/server-status", "/server-status/"):
        r = client.get(p)
        if r is None or r.status_code != 200: continue
        txt = r.text or ""
        if "Apache Server Status" not in txt and "<th>Client" not in txt: continue
        users = parse_mod_status(txt)
        if not users: continue
        hit = True
        crit("Apache mod_status is PUBLIC: %s" % p)
        rows = []
        for ip, reqs in users.items():
            adm = [q for q in reqs if STRONG.search(q)]
            ok("  %s | %d request(s) | %d admin-portal hit(s)" % (ip, len(reqs), len(adm)))
            for q in (adm or reqs)[:5]: dim("      %s" % q)
            rows.append({"ip": ip, "total": len(reqs), "admin": len(adm),
                         "sample": (adm or reqs)[:5]})
        rows.sort(key=lambda x: -x["admin"])
        F.add("high", "mod_status exposes client IPs and live requests",
              "%s is readable by anyone and lists the IP of every client "
              "using the server, including admin-portal traffic. %d client "
              "IP(s) observed." % (p, len(users)),
              {"user_ips": True, "source": "mod_status", "rows": rows})
        break
    for p in ("/nginx_status", "/stub_status", "/basic_status", "/status"):
        r = client.get(p)
        if r is not None and r.status_code == 200 and \
                re.search(r"Active connections", r.text or ""):
            warn("Nginx status page exposed: %s" % p)
            F.add("low", "Nginx stub status exposed",
                  "%s reveals server activity." % p)
    for p in LOG_PATHS:
        r = client.get(p)
        if r is None or r.status_code != 200: continue
        entries = [{"ip": m.group(1), "time": m.group(2), "method": m.group(3),
                    "path": m.group(4)} for m in LOG_LINE.finditer(r.text or "")]
        if len(entries) < 3: continue
        hit = True
        by = defaultdict(lambda: {"h": 0, "a": 0, "paths": []})
        for e in entries:
            d = by[e["ip"]]; d["h"] += 1
            strong = bool(STRONG.search(e["path"])) or \
                any(e["path"].startswith(ap) for ap in admin_paths)
            if strong:
                d["a"] += 1; d["paths"].append("%s %s" % (e["method"], e["path"]))
        crit("Log file WORLD-READABLE: %s (%d lines parsed)" % (p, len(entries)))
        rows = []
        for ip, d in sorted(by.items(), key=lambda kv: (-kv[1]["a"], -kv[1]["h"])):
            flag = " <-- ADMIN PORTAL" if d["a"] else ""
            ok("  IP %s | %d request(s) | %d admin-portal hit(s)%s"
               % (ip, d["h"], d["a"], flag))
            for q in d["paths"][:5]: dim("      %s" % q)
            rows.append({"ip": ip, "total": d["h"], "admin": d["a"],
                         "sample": d["paths"][:5]})
        F.add("high", "Access log exposed to the web",
              "%s is directly downloadable. It shows which IP addresses used "
              "the admin portal and what they requested - a privacy incident "
              "and an attacker goldmine." % p,
              {"user_ips": True, "source": "log:" + p, "rows": rows})
    r = client.get("/.env")
    if r is not None and r.status_code == 200:
        keys = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*=", r.text or "")
        if len(keys) >= 3:
            crit(".env file PUBLIC (%d config keys)" % len(keys))
            dim("Keys (values redacted): %s" % ", ".join(keys[:15]))
            sens = [k for k in keys if re.search(r"(?i)(pass|secret|token|key|mail|db|database)", k)]
            F.add("high" if sens else "medium", ".env file exposed",
                  "/.env is downloadable with keys: %s. Typically contains "
                  "database and cloud credentials." % ", ".join(keys[:12]))
    r = client.get("/.git/HEAD")
    if r is not None and r.status_code == 200 and (r.text or "").startswith("ref: refs/"):
        crit(".git repository PUBLIC (source disclosure)")
        F.add("high", "Exposed .git repository",
              "/.git/HEAD returns a valid ref; full source and history can be "
              "recovered with git-dumper.")
    if not hit:
        dim("No admin-user IP data is leaking from this target (secure config).")

def wp_users(client, F):
    section("WordPress user enumeration")
    found = []
    r = client.get("/wp-json/wp/v2/users?per_page=100")
    if r is not None and r.status_code == 200:
        try: data = json.loads(r.text)
        except ValueError: data = None
        if isinstance(data, list):
            for u in data:
                if isinstance(u, dict):
                    found.append({"name": u.get("name", "?"),
                                  "slug": u.get("slug", "?"),
                                  "roles": u.get("roles") or []})
                    ok("User: %-20s slug: %-15s roles: %s" % (u.get("name", "?"),
                       u.get("slug", "?"), ", ".join(u.get("roles") or []) or "?"))
    if not found:
        for i in range(1, 6):
            r = client.get("/?author=%d" % i)
            if r is None or r.status_code >= 400: continue
            m = re.search(r"/author/([^/?#\"]+)", r.url or "")
            if m:
                found.append({"name": m.group(1), "slug": m.group(1), "roles": []})
                ok("User (author probe): %s" % m.group(1))
    if found:
        warn("%d user(s) enumerable - usernames are half of the credential pair." % len(found))
        F.add("low", "WordPress usernames enumerable",
              "%d account(s): %s" % (len(found),
              ", ".join(u["slug"] for u in found)), {"users": found})
    else:
        dim("No WordPress users enumerable (good).")

# ------------------------------ reports ------------------------------------
def report_md(path, meta, F, scans):
    lines = ["# AdminHunter report", "",
             "- Target: %s" % meta["target"]["base"],
             "- Date: %s" % datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
             "- IPs: %s | CDN: %s | CMS: %s" % (", ".join(meta["ips"]) or "?",
             ", ".join(meta["cdn"]) or "none", ", ".join(meta["cms"]) or "unknown"),
             "", "## Findings", ""]
    for f in F.items:
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines += ["", f["detail"], ""]
        rows = f["extra"].get("rows")
        if rows:
            lines += ["| IP | Requests | Admin hits | Sample |", "|---|---|---|---|"]
            for r_ in rows:
                lines.append("| %s | %s | %s | %s |" % (r_["ip"], r_["total"],
                    r_["admin"], "; ".join(r_["sample"])[:120].replace("|", "\\|")))
            lines.append("")
    lines += ["## Admin path candidates", "",
              "| Status | Path | Final | Title | Login |", "|---|---|---|---|---|"]
    for s in scans:
        lines.append("| %s | %s | %s | %s | %s |" % (s["status"], s["path"],
            s["final"], s["title"].replace("|", "\\|") or "-",
            "YES" if s["login"] else "no"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    ok("Markdown report: %s" % path)

def report_json(path, meta, F, scans):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "findings": F.items, "candidates": scans},
                  fh, indent=2, default=str)
    ok("JSON report: %s" % path)

def summary(F, scans):
    section("Summary")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = F.count(sev)
        if n: print(c(SEVC[sev], "  %-8s: %d" % (sev.upper(), n)))
    logins = [s for s in scans if s["login"]]
    if logins:
        ok("Admin portal(s) with login forms:")
        for s in logins:
            print("      %s (HTTP %d) %s" % (s["final"], s["status"], s["title"]))
    elif scans:
        warn("Admin-ish paths exist but no confirmed login form "
             "(may be JS-rendered or API-only).")
    else:
        dim("No admin portal found - try a bigger wordlist:")
        dim("-w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt")
    ips_data = [f for f in F.items if f["extra"].get("user_ips")]
    if ips_data:
        ok("Admin-user IP data WAS obtainable - see HIGH findings for tables.")
    else:
        print()
        dim("No admin-user IPs obtainable externally: that data lives in")
        dim("server-side logs/status pages and this target is not leaking it.")

# -------------------------------- main -------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="adminhunter",
        description="AdminHunter v%s - admin portal discovery & exposure "
                    "assessment (authorized use only)." % __version__)
    ap.add_argument("target", help="target URL, e.g. http://10.0.0.5")
    ap.add_argument("-w", "--wordlist", help="custom path wordlist")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--exts", default="", help="fuzz extensions, e.g. php,html")
    ap.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--user-agent", dest="user_agent")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--full-ports", action="store_true")
    ap.add_argument("--skip-subs", action="store_true")
    ap.add_argument("--skip-ports", action="store_true")
    ap.add_argument("--skip-exposure", action="store_true")
    ap.add_argument("-o", "--output", help="markdown report file")
    ap.add_argument("--json", dest="json_out", help="JSON report file")
    a = ap.parse_args()

    print(c("1;36", "\nAdminHunter v%s - admin portal discovery & exposure assessment" % __version__))
    print(c("90", "Legal: authorized targets only.\n"))
    try: t = normalize_target(a.target)
    except ValueError as e:
        crit(str(e)); return 2

    F = Findings()
    meta = {"target": t, "time": datetime.now(timezone.utc).isoformat(),
            "cms": [], "ips": [], "cdn": []}
    client = Client(t["base"], a.timeout, a.user_agent, a.proxy, a.verify_tls)

    home = client.get("/")
    if home is None:
        crit("Target unreachable: %s" % t["base"]); return 2
    rnd = "".join(random.choices(string.ascii_lowercase, k=24))
    rb = client.get("/" + rnd)
    if rb is None:
        crit("Baseline request failed."); return 2
    base = {"status": rb.status_code, "md5": md5(rb.content)}
    info("Target: %s (soft-404 baseline: HTTP %d)" % (t["base"], rb.status_code))

    recon(t, home, meta, F)
    fingerprint(client, home, meta, F)
    hints = set()
    robots_hints(client, F, hints)
    if not a.skip_subs: subdomain_sweep(t, F)
    if not a.skip_ports: port_sweep(t, client, F, a.full_ports)

    paths = load_paths(a)
    for cms in meta["cms"]:
        for p in CMS_ADMIN.get(cms, []): paths.insert(0, p)
    paths += sorted(hints)
    scans = scan_paths(client, paths, base, F, max(1, a.threads), a.delay, a.exts)
    for s in scans: hints.add(s["path"])

    if not a.skip_exposure:
        exposure(client, hints, F)
        if "WordPress" in meta["cms"]: wp_users(client, F)

    summary(F, scans)
    if a.output: report_md(a.output, meta, F, scans)
    if a.json_out: report_json(a.json_out, meta, F, scans)
    print()
    return 0

if __name__ == "__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: print("\n[!] Interrupted."); sys.exit(130)
