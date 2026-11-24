<div align="center">

# 🖥️ vCenter VMSA-2026-0011 Remote Checker (CVE-2026-123903)

**Is this vCenter still exposed to the new vmdir authentication bypass? Check by IP and port, no login needed.**

![python](https://img.shields.io/badge/python-3.6%2B-3776AB?logo=python&logoColor=white)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)
![mode](https://img.shields.io/badge/mode-read--only%20%7C%20no%20exploit-blue)
![cvss](https://img.shields.io/badge/CVE--2026--123903-CVSS%209.8-red)
![vmsa](https://img.shields.io/badge/Broadcom-VMSA--2026--0011-orange)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

By **Astra** ([@3tternp](https://github.com/3tternp))

</div>

---

## 📚 Contents

[🎯 Why](#-why) · [🚀 Quick start](#-quick-start) · [🔎 How it works](#-how-it-works) · [🧮 Verdicts](#-verdicts) · [✍️ Fixed builds](#️-fixed-builds) · [🖨️ Example output](#️-example-output) · [🩹 What to do next](#-what-to-do-next) · [🧪 Testing](#-testing) · [⚠️ Limits](#️-limits) · [🛡️ Safety](#️-safety)

## 🎯 Why

On **24 Nov 2026** Broadcom published **VMSA-2026-0011** (23 CVEs). For vCenter it fixes **CVE-2026-123903**, another **CVSS 9.8** authentication bypass in the VMware Directory Service (`vmdir`), plus an arbitrary file write (CVE-2026-123904, 7.5) and three `vmdir` denial-of-service flaws (CVE-2026-123905 to -123907). Network access to vCenter is all that is needed for the bypass. Broadcom does not say it is exploited, but **days earlier** the sister flaw CVE-2026-123890 was exploited as a zero-day (Armory Castle) and is in CISA KEV.

The catch: **vCenter 9.x patched last week is not enough.** 9.0 needs **9.0.2.0300** and 9.1 needs **9.1.2**. This tool lists which vCenters are still below the new fix. It can also check ESX hosts for the critical ESX flaws in the same advisory.

## 🚀 Quick start

```bash
git clone https://github.com/3tternp/vcenter-vmsa-2026-0011-check.git
cd vcenter-vmsa-2026-0011-check
python3 vcenter_vmsa_2026_0011_check.py 10.10.10.5
```

```bash
python3 vcenter_vmsa_2026_0011_check.py 10.10.10.5:8443 10.10.10.6        # several targets, custom port
python3 vcenter_vmsa_2026_0011_check.py 10.10.10.0/24 --csv result.csv    # a whole subnet
python3 vcenter_vmsa_2026_0011_check.py -f targets.txt --json out.json    # from a file
python3 vcenter_vmsa_2026_0011_check.py 10.10.10.5 --fixed-build 9.0.2=25XXXXXX
```

| Option | Purpose |
|---|---|
| `-p, --port` | HTTPS port (default `443`) |
| `-f, --file` | Targets file (host, host:port or CIDR; `#` comments) |
| `--fixed-build VER=BUILD` | vCenter fixed build for the new VMSA, repeatable |
| `--esxi-fixed-build VER=BUILD` | ESX fixed build, to check ESX hosts too |
| `--fixed-file` | Alternative JSON (default `fixed_builds.json`) |
| `--no-portscan` / `--always-portscan` | Skip or force TCP probes of 2012 / 5480 / 22 / 9080 |
| `--threads`, `--timeout` | Concurrency (32) and per-probe timeout (5 s) |
| `--csv`, `--json` | Save results |

## 🔎 How it works

1. 🔭 Sends the public **`RetrieveServiceContent`** request to `https://HOST:PORT/sdk`. vCenter and ESXi answer **without authentication** with product, version and build.
2. ⚖️ Compares with two fix levels: the **earlier** fix (VMSA-2026-0009, CVE-2026-123890) and the **new** fix (VMSA-2026-0011).
3. 🔌 Opens a plain TCP connection (no data) to management ports to show what your scanning host can reach.

**No exploit is sent** and the vulnerable service is not touched.

## 🧮 Verdicts

| Verdict | When |
|---|---|
| 🔴 **VULNERABLE** | 8.0 below **8.0 U3m** · 9.1 below **9.1.2** (even if 9.1.1.0200) · 9.0 below the supplied 9.0.2.0300 build · **6.5 / 6.7 / 7.0** (presumed affected, no public fix; 7.0 has extended-support patches only) · ESX below a supplied fixed build |
| 🟢 **FIXED** | At or above the new fix level |
| 🟡 **VERIFY** | 9.0.x with no 9.0.2.0300 build supplied; 8.0 with no build in the JSON |
| 🔵 **NOT APPLICABLE** | ESXi host with no ESX build supplied (the vCenter flaw is not in ESX) |
| ⚪ **UNREACHABLE** / **NOT VCENTER** | `/sdk` not readable: wrong port, filtered, or not VMware |

**Exit codes:** `0` nothing vulnerable · `1` at least one vulnerable · `2` only verify/unreachable · `3` usage error

## ✍️ Fixed builds

| Branch | Fix for CVE-2026-123903 | Build in `fixed_builds.json` |
|---|---|---|
| vCenter 8.0 | **8.0 U3m** (also fixes CVE-2026-123890) | `25934264` ⚠️ third-party source |
| vCenter 9.0 | **9.0.2.0300** express patch | ❌ not found, **you set it** |
| vCenter 9.1 | **9.1.2** | decided by version (`9.1.2` or higher) |
| VCF 5.x | vCenter 8.0 U3m (KB 88287) | as 8.0 |

> ⚠️ Build numbers for 8.0 U3m and the earlier 9.x patches come from a public build table, **not Broadcom**. Confirm them against Broadcom KB 326316 or the VMSA, and add the 9.0.2.0300 build yourself. A wrong build means a wrong verdict.

## 🖨️ Example output

```text
[VULNERABLE] 10.10.10.5:443
    product: VMware vCenter Server 9.1.1 build-25901347 (build 25901347)
    why: version 9.1.1 is below 9.1.2, the fix for CVE-2026-123903. It already has the CVE-2026-123890 fix (9.1.1.0200) but not the new one.
    reachable management ports: 2012 (SSO control (vmdird RPC)), 5480 (VAMI (appliance management))

[VERIFY] 10.10.10.7:443
    why: 9.0.x needs the 9.0.2.0300 express patch. Add its build (--fixed-build 9.0.2=BUILD) or check VAMI

[FIXED] 10.10.10.8:443
    why: build 25934264 >= fixed build 25934264 for 8.0.3 (fixes CVE-2026-123890 and CVE-2026-123903 to -123909)
```

## 🩹 What to do next

| Result | Action |
|---|---|
| 🔴 Vulnerable | Limit access to vCenter to admin networks now, then update. vCenter updates are **cumulative** and **not Quick Patch eligible**; the vSphere Client is unavailable during the update but VMs keep running |
| 🟡 Verify | Check the build in VAMI (`https://HOST:5480`) against Broadcom, add it to `fixed_builds.json`, re-run |
| 🟢 Fixed | Patched, **not proven clean**: CVE-2026-123890 was exploited from early September. Review SSO and local admin accounts, SSH enablement and ESXi `authorized_keys` |
| 🔌 Ports open | Restrict 22 / 2012 / 5480 to admin workstations. **No workaround** exists from Broadcom |
| 🖥️ ESX hosts | Also patch ESX (CVE-2026-123910 / -123911 are critical, network, code execution). Needs maintenance mode and vMotion |

## 🧪 Testing

A mock `/sdk` server is in `tests/`:

```bash
cd tests
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=mock
python3 mock_vcenter.py 9501 8.0.3 25600417 VirtualCenter &
python3 mock_vcenter.py 9504 9.1.1 25901347 VirtualCenter &
cd .. && python3 vcenter_vmsa_2026_0011_check.py 127.0.0.1:9501 127.0.0.1:9504
```

Tested against the mock for 8.0 (old and fixed), 9.0, 9.1.1, 9.1.2, 7.0, ESXi and a closed port. **Not yet validated against a real vCenter**; run on a lab instance first.

## ⚠️ Limits

- 🔢 Fixed builds must be confirmed by you (see above). The 9.0.2.0300 build is not set.
- 🧩 `/sdk` may report 9.x as `9.0.2` or `9.1.1` without the patch suffix, so the build number decides; 9.1.2 detection by version assumes the API reports it.
- 🚧 Firewalls or reverse proxies in front of vCenter can block or mask `/sdk`.
- ❌ It does **not** test exploitability and cannot tell whether a host was already compromised.
- 📦 Only the vCenter and ESX flaws are covered. Workstation, Fusion, VMware Tools and Avi fixes in the VMSA need their own checks.

## 🛡️ Safety

Read-only: one unauthenticated informational SOAP request plus TCP connects. No exploit payloads, no logins, no changes. Use only on systems you are authorised to assess.

## 📜 License

MIT, see [LICENSE](LICENSE). Verify results against Broadcom's advisory before acting.
