#!/usr/bin/env python3
"""
vcenter_vmsa_2026_0011_check.py - REMOTE, read-only check for VMware vCenter CVE-2026-123903 (vmdir authentication
bypass, CVSS 9.8) and the other vCenter flaws fixed in Broadcom VMSA-2026-0011 (24 Nov 2026).
Vairav advisory VTS-SA-2026-1124-VCENTER-VMSA-0011.  Author: Astra (3tternp) / Vairav CSOC.

How it works (no exploit is sent):
  1. Asks https://HOST:PORT/sdk for the public service content (RetrieveServiceContent). vCenter and ESXi answer
     without login with product, version and build.
  2. Compares the build/version with the fixed levels (fixed_builds.json or --fixed-build).
  3. TCP-connects (no data) to management ports 2012, 5480, 22, 9080 to show what the scanning host can reach.

Two fix levels are tracked because vCenter 9.x needs a NEWER fix than the one for CVE-2026-123890 (VMSA-2026-0009):
  8.0   8.0 U3m fixes both
  9.0   9.0.2.0200 fixes VMSA-0009 only; 9.0.2.0300 (express patch) is needed for VMSA-0011
  9.1   9.1.1.0200 fixes VMSA-0009 only; 9.1.2 is needed for VMSA-0011
  7.0 / 6.x  presumed affected; no public fix (7.0 extended support only)

Verdicts
  VULNERABLE   build below the VMSA-0011 fix, or unsupported release (6.5/6.7/7.0)
  FIXED        at or above the VMSA-0011 fix
  VERIFY       fixed build for this branch not supplied (9.0.x); compare with Broadcom
  NOT APPLICABLE  ESXi host for the vCenter flaw (ESX has its own CVE-2026-123910/-123911: pass esxi builds to check)
  UNREACHABLE / NOT VCENTER   /sdk not readable

Exit codes: 0 nothing vulnerable, 1 at least one VULNERABLE, 2 VERIFY/UNREACHABLE only, 3 usage error.
Use only on systems you are authorised to assess. Python 3.6+, standard library only.
"""
import argparse, concurrent.futures as cf, csv, ipaddress, json, os, re, socket, ssl, sys, urllib.request

ADVISORY = "VTS-SA-2026-1124-VCENTER-VMSA-0011"
MGMT_PORTS = {2012: "SSO control (vmdird RPC)", 5480: "VAMI (appliance management)", 22: "SSH", 9080: "vCenter service port"}
SOAP = ('<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>'
        '<RetrieveServiceContent xmlns="urn:vim25"><_this type="ServiceInstance">ServiceInstance</_this></RetrieveServiceContent>'
        '</soapenv:Body></soapenv:Envelope>')
USE_COLOR = sys.stdout.isatty()
def col(t, code): return "\033[%sm%s\033[0m" % (code, t) if USE_COLOR else t
COLORS = {"VULNERABLE": "1;31", "FIXED": "1;32", "VERIFY": "1;33", "NOT APPLICABLE": "1;36", "UNREACHABLE": "0;37", "NOT VCENTER": "0;37"}

def expand(targets, default_port):
    out = []
    for t in targets:
        t = t.strip()
        if not t or t.startswith("#"): continue
        port, host = default_port, t
        if "/" in t:
            for ip in ipaddress.ip_network(t, strict=False).hosts(): out.append((str(ip), port))
            continue
        if t.count(":") == 1:
            host, p = t.split(":"); port = int(p)
        out.append((host, port))
    return out

def tcp_open(host, port, timeout):
    try:
        s = socket.create_connection((host, port), timeout=timeout); s.close(); return True
    except Exception:
        return False

def sdk_info(host, port, timeout):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    url = "https://%s:%d/sdk" % (host if ":" not in host else "[%s]" % host, port)
    req = urllib.request.Request(url, data=SOAP.encode(), headers={"Content-Type": "text/xml; charset=utf-8",
                                 "SOAPAction": "urn:vim25/8.0", "User-Agent": "Astra-vcenter-vmsa0011-check/1.0"})
    try:
        body = urllib.request.urlopen(req, timeout=timeout, context=ctx).read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "ignore")
    g = lambda tag: (re.search(r"<%s>([^<]*)</%s>" % (tag, tag), body) or [None, None])[1]
    return {"fullName": g("fullName"), "version": g("version"), "build": g("build"), "apiType": g("apiType")}

def vkey(v):
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", v or "")
    return tuple(int(x) if x else 0 for x in m.groups()) if m else None

def need(fixed, kind, key, level):
    """minimum fixed build for kind (vcenter/esxi), version key, level; None = unknown; 0 = 'any build of this version'"""
    e = fixed.get(kind, {}).get(key)
    if isinstance(e, dict): return e.get(level)
    return e if level == "vmsa_0011" else None

def verdict(info, fixed):
    api = info.get("apiType")
    ver = vkey(info.get("version")); build = int(info["build"]) if (info.get("build") or "").isdigit() else None
    if api == "HostAgent":
        if not ver: return "NOT VCENTER", "unexpected /sdk response"
        key = "%d.%d.%d" % ver; nb = need(fixed, "esxi", key, "vmsa_0011")
        if nb:
            if build is not None and build >= int(nb):
                return "FIXED", "ESX build %s >= %s (CVE-2026-123910 to -123916)" % (build, nb)
            return "VULNERABLE", "ESX build %s < %s: CVE-2026-123910/-123911 (critical, network, code execution on host) not fixed" % (build, nb)
        return "NOT APPLICABLE", "ESXi host (%s). Not affected by the vCenter flaw, but VMSA-2026-0011 also fixes critical ESX flaws; supply an esxi fixed build to check" % info.get("fullName")
    if api != "VirtualCenter" or not ver:
        return "NOT VCENTER", "unexpected /sdk response"
    key = "%d.%d.%d" % ver
    if ver[:2] in ((6, 5), (6, 7)):
        return "VULNERABLE", "vSphere %d.%d is unsupported and presumed affected; upgrade" % ver[:2]
    if ver[:2] == (7, 0):
        nb = need(fixed, "vcenter", key, "vmsa_0011")
        if nb and build is not None: return ("FIXED", "build %s >= %s" % (build, nb)) if build >= int(nb) else ("VULNERABLE", "build %s < %s" % (build, nb))
        return "VULNERABLE", "vCenter 7.0 is presumed affected; only an extended-support patch exists (contact Broadcom). Supply its build to clear it"
    if ver[:2] == (9, 1) and ver[2] >= 2:
        nb = need(fixed, "vcenter", key, "vmsa_0011")
        if nb and build is not None and build < int(nb):
            return "VULNERABLE", "build %s < %s" % (build, nb)
        return "FIXED", "version %s is at or above 9.1.2 (confirm build in VAMI)" % info.get("version")
    nb = need(fixed, "vcenter", key, "vmsa_0011")
    if nb:
        if build is not None and build >= int(nb):
            return "FIXED", "build %s >= fixed build %s for %s (fixes CVE-2026-123890 and CVE-2026-123903 to -123909)" % (build, nb, key)
        old = need(fixed, "vcenter", key, "vmsa_0009")
        extra = " (has the CVE-2026-123890 fix but not the new one)" if old and build is not None and build >= int(old) else ""
        return "VULNERABLE", "build %s < fixed build %s for %s%s" % (build, nb, key, extra)
    if ver[:2] == (9, 1):  # 9.1.0 / 9.1.1 are below 9.1.2
        old = need(fixed, "vcenter", key, "vmsa_0009")
        extra = " It already has the CVE-2026-123890 fix (9.1.1.0200) but not the new one." if old and build is not None and build >= int(old) else ""
        return "VULNERABLE", "version %s is below 9.1.2, the fix for CVE-2026-123903.%s" % (info.get("version"), extra)
    if ver[:2] == (9, 0):
        old = need(fixed, "vcenter", key, "vmsa_0009")
        if old and build is not None and build < int(old):
            return "VULNERABLE", "build %s is below even 9.0.2.0200 (%s)" % (build, old)
        return "VERIFY", "9.0.x needs the 9.0.2.0300 express patch. Add its build (--fixed-build 9.0.2=BUILD) or check VAMI; build is %s" % build
    if ver[:2] == (8, 0):
        return "VERIFY", "8.0 fixed build (8.0 U3m) not supplied; add it to fixed_builds.json (build is %s)" % build
    return "VERIFY", "version %s is not in the advisory table; verify with Broadcom" % info.get("version")

def scan(target, a, fixed):
    host, port = target
    r = {"host": host, "port": port, "status": None, "reason": None, "product": None, "version": None, "build": None, "exposed_ports": []}
    try:
        info = sdk_info(host, port, a.timeout)
    except Exception as e:
        r["status"] = "UNREACHABLE"; r["reason"] = "cannot read /sdk on %d: %s" % (port, str(e)[:80]); info = None
    if info:
        r["product"], r["version"], r["build"] = info["fullName"], info["version"], info["build"]
        if not info["version"]:
            r["status"], r["reason"] = "NOT VCENTER", "no VMware service content at /sdk"
        else:
            r["status"], r["reason"] = verdict(info, fixed)
    if (not a.no_portscan and r["status"] not in ("UNREACHABLE", "NOT VCENTER")) or a.always_portscan:
        for p in MGMT_PORTS:
            if tcp_open(host, p, a.timeout): r["exposed_ports"].append(p)
    return r

def main():
    ap = argparse.ArgumentParser(description="Remote check for vCenter CVE-2026-123903 / VMSA-2026-0011 (read-only).")
    ap.add_argument("targets", nargs="*", help="host, host:port or CIDR")
    ap.add_argument("-f", "--file", help="file with targets")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("--fixed-build", action="append", default=[], metavar="VER=BUILD", help="vCenter, e.g. 9.0.2=25XXXXXX (repeatable)")
    ap.add_argument("--esxi-fixed-build", action="append", default=[], metavar="VER=BUILD", help="ESX, e.g. 8.0.3=25XXXXXX")
    ap.add_argument("--fixed-file", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixed_builds.json"))
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--threads", type=int, default=32)
    ap.add_argument("--no-portscan", action="store_true"); ap.add_argument("--always-portscan", action="store_true")
    ap.add_argument("--csv", metavar="FILE"); ap.add_argument("--json", metavar="FILE")
    a = ap.parse_args()
    tl = list(a.targets)
    if a.file: tl += open(a.file).read().split()
    if not tl: ap.print_usage(); sys.exit(3)
    fixed = {"vcenter": {}, "esxi": {}}
    if os.path.exists(a.fixed_file):
        try:
            d = json.load(open(a.fixed_file))
            for k in ("vcenter", "esxi"):
                fixed[k].update({x: y for x, y in d.get(k, {}).items() if not x.startswith("_")})
        except Exception as e:
            print("warning: cannot read %s: %s" % (a.fixed_file, e))
    for fb in a.fixed_build:
        k, v = fb.split("="); fixed["vcenter"].setdefault(k, {})
        if not isinstance(fixed["vcenter"][k], dict): fixed["vcenter"][k] = {}
        fixed["vcenter"][k]["vmsa_0011"] = int(v)
    for fb in a.esxi_fixed_build:
        k, v = fb.split("="); fixed["esxi"][k] = int(v)
    targets = expand(tl, a.port)
    print("\nvCenter CVE-2026-123903 / VMSA-2026-0011 check | Vairav %s | %d target(s)\n" % (ADVISORY, len(targets)))
    with cf.ThreadPoolExecutor(a.threads) as ex: results = list(ex.map(lambda t: scan(t, a, fixed), targets))
    for r in results:
        if r["status"] in ("UNREACHABLE", "NOT VCENTER") and len(results) > 20: continue
        print("%s %s:%d" % (col("[%s]" % r["status"], COLORS.get(r["status"], "0")), r["host"], r["port"]))
        if r["product"]: print("    product: %s (build %s)" % (r["product"], r["build"]))
        print("    why: %s" % r["reason"])
        if r["exposed_ports"]:
            print("    reachable management ports: " + ", ".join("%d (%s)" % (p, MGMT_PORTS[p]) for p in r["exposed_ports"]))
            print("    note: these should be reachable only from admin workstations.")
        print()
    cnt = {}
    for r in results: cnt[r["status"]] = cnt.get(r["status"], 0) + 1
    print("Summary: " + ", ".join("%d %s" % (v, k) for k, v in sorted(cnt.items())))
    print("FIXED means patched, not proven clean: CVE-2026-123890 was exploited from early September 2026. See the advisory compromise checks.")
    if a.json: json.dump(results, open(a.json, "w"), indent=2)
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["host", "port", "status", "product", "version", "build", "exposed_ports", "reason"])
            for r in results: w.writerow([r["host"], r["port"], r["status"], r["product"], r["version"], r["build"], " ".join(map(str, r["exposed_ports"])), r["reason"]])
    st = [r["status"] for r in results]
    sys.exit(1 if "VULNERABLE" in st else (2 if any(s in ("VERIFY", "UNREACHABLE") for s in st) else 0))

if __name__ == "__main__":
    main()
