#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_shell_parse.py - Convertit la sortie brute de cmdb_collector.sh (archive tar.gz)
au même schéma JSON que cmdb_collector.py, pour que cmdb_build.py la traite
sans distinction.

Les règles d'interprétation (applications web, bibliothèques JS, paquets
Python/npm/composer, classes sentinelles Java, redaction des secrets) sont
importées du collecteur Python : une seule source de vérité.

Usage autonome : cmdb_shell_parse.py <dump.tar.gz> <sortie.json.gz>
"""
import argparse
import gzip
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR_PATH = os.path.join(HERE, "..", "roles", "cmdb_collect", "files", "cmdb_collector.py")


def load_collector():
    spec = importlib.util.spec_from_file_location("cmdb_collector", COLLECTOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = load_collector()


# ---------------------------------------------------------------------------
# Extraction sûre (le contenu vient des serveurs : on n'accepte que des
# fichiers et répertoires relatifs, sans "..", sans liens)
# ---------------------------------------------------------------------------
def safe_extract(tgz_bytes, dest):
    with tarfile.open(fileobj=io.BytesIO(tgz_bytes), mode="r:*") as tf:   # tar.gz, ou tar seul (AIX sans gzip)
        for m in tf.getmembers():
            name = m.name
            if name.startswith("/") or ".." in name.split("/") or not (m.isfile() or m.isdir()):
                continue
            target = os.path.realpath(os.path.join(dest, name))
            if not target.startswith(os.path.realpath(dest) + os.sep) and target != os.path.realpath(dest):
                continue
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def read_all(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


class Dump(object):
    def __init__(self, root):
        self.root = root
        self.fsroot = os.path.join(root, "fs")

    def cmd(self, name, ok_only=False):
        p = os.path.join(self.root, "cmd", name + ".out")
        if not os.path.exists(p):
            return None
        rc = self.rc(name)
        if rc == 127 or (ok_only and rc not in (0, None)):
            return None
        with open(p, "rb") as f:
            t = f.read().decode("utf-8", "replace")
        return t if t.strip() or rc == 0 else None

    def rc(self, name):
        p = os.path.join(self.root, "cmd", name + ".rc")
        try:
            with open(p) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def file(self, path, limit=64 << 20):
        p = self.fsroot + path
        if not os.path.isfile(p):
            return None
        with open(p, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")

    def exists(self, path):
        return os.path.exists(self.fsroot + path)

    def listdir(self, path):
        p = self.fsroot + path
        try:
            return sorted(os.listdir(p))
        except OSError:
            return []

    def scan(self, name):
        p = os.path.join(self.root, "scan", name)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return f.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Système
# ---------------------------------------------------------------------------
def synth_os_release(d):
    t = d.file("/etc/os-release")
    if t:
        return C.kv_text(t)
    rh = d.file("/etc/redhat-release") or d.file("/etc/centos-release") or d.file("/etc/oracle-release")
    if rh:
        line = rh.strip().splitlines()[0]
        m = re.search(r"release\s+(\d+(?:\.\d+)?)", line)
        ver = m.group(1) if m else ""
        upd = re.search(r"Update\s+(\d+)", line)
        if upd and "." not in ver:
            ver = "%s.%s" % (ver, upd.group(1))
        ident = "rhel"
        for key, val in (("CentOS", "centos"), ("Scientific", "scientific"), ("Oracle", "ol"), ("Fedora", "fedora")):
            if key in line:
                ident = val
        return {"ID": ident, "VERSION_ID": ver, "PRETTY_NAME": line, "ID_LIKE": "rhel fedora"}
    suse = d.file("/etc/SuSE-release")
    if suse:
        kv = C.kv_text(suse)
        lines = suse.strip().splitlines()
        ver = kv.get("VERSION", "")
        if kv.get("PATCHLEVEL"):
            ver = "%s.%s" % (ver, kv["PATCHLEVEL"])
        ident = "sles" if "Enterprise Server" in lines[0] else ("sled" if "Desktop" in lines[0] else "opensuse")
        return {"ID": ident, "VERSION_ID": ver, "PRETTY_NAME": lines[0]}
    lsb = C.kv_text(d.file("/etc/lsb-release") or "")
    if lsb.get("DISTRIB_ID"):
        return {"ID": lsb["DISTRIB_ID"].lower(), "VERSION_ID": lsb.get("DISTRIB_RELEASE", ""),
                "PRETTY_NAME": lsb.get("DISTRIB_DESCRIPTION", "")}
    deb = d.file("/etc/debian_version")
    if deb:
        v = deb.strip()
        return {"ID": "debian", "VERSION_ID": v.split(".")[0], "PRETTY_NAME": "Debian GNU/Linux %s" % v}
    return {}


def build_os(d):
    o = {"os_release": synth_os_release(d)}
    o["release_files"] = {}
    for f in ("/etc/redhat-release", "/etc/centos-release", "/etc/system-release", "/etc/oracle-release",
              "/etc/debian_version", "/etc/lsb-release", "/etc/SuSE-release", "/etc/issue"):
        t = d.file(f, 4096)
        if t:
            o["release_files"][f] = t.strip()
    o["uname"] = dict((k, (d.cmd("uname_" + s) or "").strip()) for k, s in
                      (("sysname", "s"), ("nodename", "n"), ("release", "r"), ("version", "v"), ("machine", "m")))
    o["hostname"] = (d.cmd("hostname", True) or "").strip() or o["uname"]["nodename"]
    o["fqdn"] = (d.cmd("hostname_f", True) or "").strip() or None
    o["machine_id"] = ((d.file("/etc/machine-id") or d.file("/var/lib/dbus/machine-id") or "").strip()) or None
    o["proc_version"] = (d.file("/proc/version") or "").strip()
    o["kernel_cmdline"] = (d.file("/proc/cmdline") or "").strip()
    up = d.file("/proc/uptime")
    if up:
        o["uptime_seconds"] = float(up.split()[0])
    bt = d.cmd("btime")
    if bt and bt.split():
        o["boot_time"] = C.now_iso(int(bt.split()[1]))
    o["timezone"] = (d.file("/etc/timezone") or "").strip() or C.kv_text(d.file("/etc/sysconfig/clock") or "").get("ZONE")
    g = (d.cmd("glibc", True) or "").strip()
    o["glibc"] = g or None
    o["selinux_getenforce"] = (d.cmd("getenforce", True) or "").strip() or None
    o["loadavg"] = (d.file("/proc/loadavg") or "").strip()
    o["reboot_required_file"] = d.exists("/var/run/reboot-required")
    if d.rc("needs_restarting") not in (None, 127):
        o["needs_restarting_r"] = {"rc": d.rc("needs_restarting"), "out": (d.cmd("needs_restarting") or "")[-4000:]}
    env = {}
    for f in ["/etc/environment"] + ["/etc/profile.d/" + n for n in d.listdir("/etc/profile.d")]:
        t = d.file(f, 65536)
        if t is not None:
            env[f] = C.redact(t)
    o["env_files"] = env
    o["runlevel"] = (d.cmd("runlevel", True) or "").strip() or None
    return o


def parse_dmidecode(text):
    out = {}
    if not text:
        return out
    block = None
    for line in text.splitlines():
        if not line.startswith("\t"):
            block = line.strip()
            continue
        k, _, v = line.strip().partition(":")
        v = v.strip()
        if block == "System Information":
            key = {"Manufacturer": "sys_vendor", "Product Name": "product_name", "Version": "product_version",
                   "Serial Number": "product_serial", "UUID": "product_uuid"}.get(k)
        elif block == "BIOS Information":
            key = {"Vendor": "bios_vendor", "Version": "bios_version", "Release Date": "bios_date"}.get(k)
        else:
            key = None
        if key and key not in out:
            out[key] = v
    return out


def sys_blocks(text, marker):
    """Blocs "@@MARQUEUR nom" suivis de lignes "clé valeur" -> [(nom, {clé: [valeurs]})]."""
    out = []
    cur = None
    for line in (text or "").splitlines():
        if line.startswith(marker + " "):
            cur = (line[len(marker) + 1:].strip(), {})
            out.append(cur)
        elif cur is not None and line.strip():
            k, _, v = line.partition(" ")
            cur[1].setdefault(k, []).append(v.strip())
    return out


def first(kv, key):
    v = kv.get(key)
    return v[0] if v else None


def build_interfaces(d):
    details = C.parse_ip_link_details(d.cmd("ip_link_d", True))
    bonding, perm = {}, {}
    for n in d.listdir("/proc/net/bonding"):
        t = d.file("/proc/net/bonding/" + n)
        if t:
            bonding[n] = t
            perm.update(C.parse_bonding_perm(t))
    ifaces = []
    for name, kv in sys_blocks(d.cmd("net_sys"), "@@IF"):
        i = {"name": name}
        for k in ("address", "mtu", "operstate", "carrier", "speed", "duplex", "type", "ifindex", "iflink",
                  "addr_assign_type"):
            i[k] = first(kv, k)
        dev = first(kv, "device")
        i["virtual"] = not dev
        if dev:
            i["bus_info"] = dev.rsplit("/", 1)[-1]
            i["pci_slot"] = C.pci_slot_of(first(kv, "realdevice") or dev)
            i["pci_ids"] = ":".join(x for x in (first(kv, "device/vendor"), first(kv, "device/device")) if x) or None
        i["driver"] = first(kv, "driver")
        if first(kv, "master"):
            i["master"] = first(kv, "master")
        is_bond, is_bridge = bool(first(kv, "isbond")), "bridge_ports" in kv
        if is_bond:
            i["bond_mode"] = first(kv, "bonding/mode")
            i["bond_slaves"] = (first(kv, "bonding/slaves") or "").split()
        if is_bridge:
            i["bridge_ports"] = (first(kv, "bridge_ports") or "").split()
        det = details.get(name, {})
        i["kind"] = C.nic_kind(name, bool(dev), is_bond, is_bridge, first(kv, "devtype"), det.get("kind"))
        if det.get("vlan_id") is not None:
            i["vlan_id"] = det["vlan_id"]
        if det.get("parent"):
            i["parent"] = det["parent"]
        if name in perm:
            i["permanent_address"] = perm[name]
        ei = C.parse_colon_kv("\n".join(kv.get("ethtool_i", [])))
        if ei:
            i["ethtool"] = dict((k, ei.get(k)) for k in ("driver", "version", "firmware-version", "bus-info") if ei.get(k))
        pm = re.search(r"Permanent address:\s*(\S+)", "\n".join(kv.get("ethtool_P", [])))
        if pm and "permanent_address" not in i and pm.group(1) != "00:00:00:00:00:00":
            i["permanent_address"] = pm.group(1)
        ifaces.append(dict((k, v) for k, v in i.items() if v is not None))
    return ifaces, bonding


def build_disks(d):
    lsblk = {}
    for line in (d.cmd("lsblk", True) or "").splitlines():
        kv = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if kv.get("NAME"):
            lsblk[kv["NAME"]] = kv
    disks = []
    for name, kv in sys_blocks(d.cmd("disk_sys"), "@@DISK"):
        e = {"name": name}
        try:
            e["size_bytes"] = int(first(kv, "size") or 0) * 512
        except ValueError:
            pass
        for k, src in (("removable", "removable"), ("ro", "ro"), ("rotational", "queue/rotational"),
                       ("model", "device/model"), ("vendor", "device/vendor"), ("rev", "device/rev"),
                       ("serial", "device/serial"), ("wwid", "device/wwid"), ("dm_name", "dm/name"), ("dm_uuid", "dm/uuid")):
            if first(kv, src):
                e[k] = first(kv, src)
        if not e.get("wwid") and first(kv, "wwid"):
            e["wwid"] = first(kv, "wwid")
        sp = first(kv, "syspath") or ""
        e["sys_path"] = sp
        e["pci_slot"] = C.pci_slot_of(sp)
        e["transport"] = "device-mapper" if name.startswith("dm-") else ("md" if name.startswith("md") else C.disk_transport(sp))
        e["slaves"] = (first(kv, "slaves") or "").split()
        lb = lsblk.get(name, {})
        for src, dst in (("SERIAL", "serial"), ("WWN", "wwn"), ("MODEL", "model"), ("TRAN", "transport"), ("VENDOR", "vendor")):
            if lb.get(src) and not e.get(dst):
                e[dst] = lb[src].strip()
        disks.append(e)
    fc = []
    for name, kv in sys_blocks(d.cmd("fc_sys"), "@@FC"):
        fc.append(dict([("name", name)] + [(k, first(kv, k)) for k in ("port_name", "node_name", "port_state", "speed",
                                                                      "symbolic_name", "port_type")]))
    return disks, fc


def build_hardware(d):
    h = {}
    dmi = {}
    for n in d.listdir("/sys/class/dmi/id"):
        t = d.file("/sys/class/dmi/id/" + n, 4096)
        if t is not None:
            dmi[n] = t.strip()
    raw = d.cmd("dmidecode", True)
    for k, v in parse_dmidecode(raw).items():
        dmi.setdefault(k, v)
    h["dmi"] = dmi
    h["dmidecode"] = raw
    cpu = {"count": 0}
    for line in (d.file("/proc/cpuinfo") or "").splitlines():
        if ":" not in line:
            continue
        k, v = [x.strip() for x in line.split(":", 1)]
        if k == "processor":
            cpu["count"] += 1
        elif k in ("model name", "vendor_id", "cpu family", "model", "stepping", "microcode", "bugs", "flags") and k not in cpu:
            cpu[k] = v
    h["cpu"] = cpu
    mem = {}
    for line in (d.file("/proc/meminfo") or "").splitlines():
        m = re.match(r"(\S+):\s+(\d+)", line)
        if m:
            mem[m.group(1)] = int(m.group(2))
    h["meminfo_kb"] = mem
    h["df"] = d.cmd("df")
    h["mount"] = d.cmd("mount")
    h["mounts"] = parse_df(d.cmd("df", True), proc_mounts_info(d.file("/proc/mounts")),
                           skip_types=tuple(t for t in C.PSEUDO_FS if t != "overlay"))
    h["lsblk_raw"] = d.cmd("lsblk", True)
    h["lspci"] = d.cmd("lspci", True)
    h["pci"] = C.parse_lspci_vmm(d.cmd("lspci_vmm", True))
    h["lscpu"] = d.cmd("lscpu", True)
    h["lscpu_kv"] = C.parse_colon_kv(h["lscpu"])
    h["hostnamectl_kv"] = C.parse_colon_kv(d.cmd("hostnamectl", True))
    h["disks"], h["fc_hosts"] = build_disks(d)
    vulns = {}
    for n in d.listdir("/sys/devices/system/cpu/vulnerabilities"):
        vulns[n] = (d.file("/sys/devices/system/cpu/vulnerabilities/" + n) or "").strip()
    h["cpu_vulnerabilities"] = vulns
    return h


def build_packages(d):
    p = {"managers": {}}
    t = d.cmd("rpm_qa", True)
    if t:
        keys = ["name", "epoch", "version", "release", "arch", "vendor", "installtime", "buildtime", "sourcerpm",
                "packager", "sig_rsa", "sig_pgp", "summary"]
        rows = []
        for line in t.splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            row = dict(zip(keys, parts))
            for k in list(row):
                if row[k] in ("(none)", ""):
                    row[k] = None
            rows.append(row)
        p["managers"]["rpm"] = rows
    t = d.cmd("dpkg_query", True)
    if t:
        keys = ["name", "version", "arch", "status", "source", "source_version", "maintainer", "installed_size", "summary"]
        p["managers"]["dpkg"] = [dict(zip(keys, line.split("\t"))) for line in t.splitlines() if line.count("\t") >= 3]
    apk = d.file("/lib/apk/db/installed")
    if apk:
        rows, cur = [], {}
        for line in apk.splitlines() + [""]:
            if not line.strip():
                if cur.get("P"):
                    rows.append({"name": cur.get("P"), "version": cur.get("V"), "arch": cur.get("A"), "origin": cur.get("o")})
                cur = {}
            elif len(line) > 2 and line[1] == ":":
                cur[line[0]] = line[2:]
        p["managers"]["apk"] = rows
    repos = {}
    for dn in ("/etc/yum.repos.d", "/etc/apt/sources.list.d", "/etc/zypp/repos.d"):
        for n in d.listdir(dn):
            repos[dn + "/" + n] = C.redact(d.file(dn + "/" + n) or "")
    for f in ("/etc/apt/sources.list", "/etc/yum.conf", "/etc/sysconfig/rhn/sources"):
        t = d.file(f)
        if t is not None:
            repos[f] = C.redact(t)
    p["repo_files"] = repos
    return p


def owner_index(d):
    idx = {}
    for name in ("owners_rpm", "owners_dpkg", "owners_lslpp"):
        for line in (d.cmd(name) or "").splitlines():
            path, _, pkg = line.rpartition("\t")
            if path and pkg:
                idx.setdefault(path, pkg)
    return idx


def lookup_owner(idx, path):
    if not idx or not path:
        return None
    for c in (path, path[4:] if path.startswith("/usr/") else "/usr" + path):
        if c in idx:
            return idx[c]
    return None




def parse_df(text, fsinfo=None, skip_types=()):
    """df -P -k (Linux, POSIX) ou df -k (AIX) -> [{mountpoint, device, fstype, size/used/avail_bytes...}].

    Linux : Filesystem 1024-blocks Used Available Capacity Mounted on
    AIX   : Filesystem 1024-blocks Free %Used Iused %Iused Mounted on   (utilisé = total - libre)
    fsinfo : {point de montage: (type, options)} tiré de /proc/mounts ou de la commande mount."""
    fsinfo = fsinfo or {}
    lines = (text or "").splitlines()
    if not lines:
        return []
    aix = bool(re.search(r"\bFree\b.*%Used", lines[0]))
    out, pending = {}, None
    for line in lines[1:]:
        p = line.split()
        if pending and p and len(p) >= 5:      # nom de périphérique long replié sur la ligne précédente
            p = [pending] + p
        pending = None
        if len(p) == 1:
            pending = p[0]
            continue
        if len(p) < 6 if not aix else len(p) < 7:
            continue

        def num(v):
            return int(v) * 1024 if re.match(r"^\d+$", v or "") else None
        if aix:
            dev, size, free, iused_pct, mp = p[0], num(p[1]), num(p[2]), p[5], " ".join(p[6:])
            if size is None:
                continue                          # /proc et pseudo-systèmes : "-"
            e = {"device": dev, "mountpoint": mp, "size_bytes": size, "avail_bytes": free,
                 "used_bytes": size - free if free is not None else None}
            if iused_pct.rstrip("%").isdigit():
                e["inodes_used_pct"] = int(iused_pct.rstrip("%"))
        else:
            dev, size, used, avail, mp = p[0], num(p[1]), num(p[2]), num(p[3]), " ".join(p[5:])
            if size is None:
                continue
            e = {"device": dev, "mountpoint": mp, "size_bytes": size, "used_bytes": used, "avail_bytes": avail}
        fst, opts = fsinfo.get(mp, (None, None))
        if fst in skip_types:
            continue
        e["fstype"], e["options"] = fst, opts
        out[mp] = e                               # montages empilés : le dernier l'emporte, comme df
    return list(out.values())


def proc_mounts_info(text):
    info = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) >= 4:
            info[p[1].replace("\\040", " ")] = (p[2], p[3])
    return info


def aix_mount_info(text):
    """Sortie mount AIX : [nœud] monté sur type date options (nœud absent pour un montage local)."""
    info = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) < 4 or p[0] in ("node", "--------") or p[0].startswith("-"):
            continue
        if p[0].startswith("/"):
            mp, vfs = p[1], p[2]
        elif len(p) >= 5:
            mp, vfs = p[2], p[3]
        else:
            continue
        info[mp] = (vfs, p[-1] if "=" in p[-1] or "," in p[-1] or p[-1] in ("rw", "ro") else None)
    return info

# ---------------------------------------------------------------------------
# AIX
# ---------------------------------------------------------------------------
def aix_attrs(text):
    """Sortie lsattr -El : "attribut valeur description... True|False" -> {attribut: valeur}."""
    d = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) >= 2:
            d.setdefault(p[0], p[1])
    return d


def aix_dev_attrs(text):
    out, cur = {}, None
    for line in (text or "").splitlines():
        if line.startswith("@@DEV "):
            cur = out.setdefault(line[6:].strip(), [])
        elif cur is not None:
            cur.append(line)
    return dict((k, aix_attrs("\n".join(v))) for k, v in out.items())


def aix_lscfg(text):
    """lscfg -vp : blocs "  nom  emplacement  description" puis lignes VPD "Clé......valeur"."""
    devs, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^  (\S+)\s{2,}(\S+)?\s{2,}(.+)$", line) or re.match(r"^  (\S+)\s+(U\S+)\s+(.+)$", line)
        if m and not line.startswith("    "):
            cur = devs.setdefault(m.group(1), {"location": m.group(2), "description": m.group(3).strip()})
            continue
        m = re.match(r"^\s+(.+?)\.{2,}(.*)$", line)
        if m and cur is not None:
            cur[m.group(1).strip()] = m.group(2).strip()
    return devs


def aix_lsdev(text):
    devs = {}
    for line in (text or "").splitlines():
        p = line.split(":", 6)
        if len(p) == 7:
            devs[p[0]] = {"class": p[1], "subclass": p[2], "type": p[3], "status": p[4], "location": p[5], "description": p[6]}
    return devs


def aix_mac(v):
    """"40.f2.e9.a1.b2.c0" ou "40F2E9A1B2C0" -> "40:f2:e9:a1:b2:c0"."""
    if not v:
        return None
    v = v.strip().lower()
    if "." in v:
        parts = v.split(".")
        if len(parts) == 6:
            return ":".join(x.zfill(2) for x in parts)
    if re.match(r"^[0-9a-f]{12}$", v):
        return ":".join(v[i:i + 2] for i in range(0, 12, 2))
    return v


def aix_wwn(v):
    v = (v or "").strip().lower()
    return "0x" + v if re.match(r"^[0-9a-f]{16}$", v) else (v or None)


def aix_oslevel(d):
    lvl = (d.cmd("oslevel_s", True) or "").strip()
    m = re.match(r"^(\d)(\d)00-(\d+)-(\d+)", lvl)
    if m:
        return lvl, "%s.%s" % (m.group(1), m.group(2)), "AIX %s.%s TL%d SP%d (%s)" % (m.group(1), m.group(2), int(m.group(3)), int(m.group(4)), lvl)
    return lvl, (d.cmd("uname_v", True) or "").strip() + "." + (d.cmd("uname_r", True) or "").strip(), "AIX " + lvl


def build_aix(d):
    """Sections os / hardware / packages / network / services pour AIX."""
    lvl, ver, pretty = aix_oslevel(d)
    prt = C.parse_colon_kv(d.cmd("prtconf", True))
    lpar = C.parse_colon_kv(d.cmd("lparstat_i", True))
    sys0 = aix_attrs(d.cmd("sys0", True))
    attrs = aix_dev_attrs(d.cmd("dev_attrs", True))
    vpd = aix_lscfg(d.cmd("lscfg_vp", True))
    lsdev = aix_lsdev(d.cmd("lsdev_C", True))
    o = {"os_release": {"ID": "aix", "VERSION_ID": ver, "PRETTY_NAME": pretty},
         "uname": {"sysname": "AIX", "nodename": (d.cmd("uname_n", True) or "").strip(), "release": lvl or ver,
                   "version": (d.cmd("uname_v", True) or "").strip(), "machine": (d.cmd("uname_p", True) or "powerpc").strip()},
         "hostname": (d.cmd("hostname", True) or d.cmd("uname_n", True) or "").strip(),
         "machine_id": (d.cmd("uname_m", True) or "").strip() or None,
         "aix": {"oslevel_s": lvl, "oslevel_r": (d.cmd("oslevel_r", True) or "").strip(),
                 "lpar": (d.cmd("uname_L", True) or "").strip(), "kernel_bitmode": (d.cmd("kernel_bitmode", True) or "").strip(),
                 "lparstat": lpar, "prtconf": prt, "sys0": sys0, "instfix": d.cmd("instfix", True),
                 "lslpp_Lcq_raw": d.cmd("lslpp_Lcq", True), "emgr_raw": d.cmd("emgr", True), "emgr_rc": d.rc("emgr")},
         "uptime_raw": d.cmd("uptime", True), "env_files": {}}
    env = d.file("/etc/environment")
    if env:
        o["env_files"]["/etc/environment"] = C.redact(env)
    mem_kb = None
    try:
        mem_kb = int(sys0.get("realmem"))
    except (TypeError, ValueError):
        m = re.match(r"(\d+)\s*MB", prt.get("Memory Size", ""))
        mem_kb = int(m.group(1)) * 1024 if m else None
    ncpu = None
    try:
        ncpu = int(lpar.get("Online Virtual CPUs") or prt.get("Number Of Processors"))
    except (TypeError, ValueError):
        pass
    h = {"dmi": {"sys_vendor": "IBM", "product_name": prt.get("System Model") or sys0.get("modelname"),
                 "product_serial": prt.get("Machine Serial Number") or (sys0.get("systemid") or "").replace("IBM,", "") or None,
                 "bios_version": prt.get("Firmware Version") or sys0.get("fwversion"),
                 "board_name": prt.get("Platform Firmware level")},
         "cpu": {"count": ncpu, "model name": " ".join(x for x in (prt.get("Processor Type"), prt.get("Processor Clock Speed")) if x) or None},
         "meminfo_kb": {"MemTotal": mem_kb} if mem_kb else {},
         "virtualization": "powervm", "lscpu_kv": {"Hypervisor vendor": "PowerVM " + (lpar.get("Type") or "").strip()},
         "hostnamectl_kv": {}, "df": d.cmd("df", True), "mount": d.cmd("mount", True), "lsps": d.cmd("lsps", True),
         "lparstat": lpar, "prtconf_raw": d.cmd("prtconf", True), "lscfg_raw": d.cmd("lscfg_vp", True),
         "mounts": parse_df(d.cmd("df", True), aix_mount_info(d.cmd("mount", True)), skip_types=("procfs", "ahafs")),
         "cpu_vulnerabilities": {}}
    # adaptateurs (équivalent "PCI") : emplacement, description, référence, firmware
    pci = {}
    for name, dv in sorted(lsdev.items()):
        if dv["class"] != "adapter":
            continue
        v = vpd.get(name, {})
        slot = v.get("Hardware Location Code") or v.get("location") or dv["location"] or name
        pci[slot] = {"Slot": slot, "Class": dv["subclass"] + " " + dv["type"], "Vendor": "IBM",
                     "Device": "%s (%s)" % (dv["description"], name), "Driver": dv["type"],
                     "Rev": v.get("ROM Level.(alterable)") or v.get("ROS Level and ID"), "PartNumber": v.get("Part Number")}
    h["pci"] = pci
    # disques
    disks = []
    lspv = {}
    for line in (d.cmd("lspv", True) or "").splitlines():
        p = line.split()
        if len(p) >= 3:
            lspv[p[0]] = {"pvid": p[1], "vg": p[2]}
    for name, dv in sorted(lsdev.items()):
        if dv["class"] != "disk":
            continue
        a, v = attrs.get(name, {}), vpd.get(name, {})
        e = {"name": name, "transport": {"fcp": "fc", "vscsi": "vscsi", "sas": "sas", "scsi": "scsi", "iscsi": "iscsi"}.get(dv["subclass"], dv["subclass"]),
             "model": v.get("Machine Type and Model") or dv["description"], "vendor": v.get("Manufacturer"),
             "serial": v.get("Serial Number") or None, "wwid": a.get("unique_id"), "wwn": aix_wwn(a.get("ww_name")),
             "pci_slot": (v.get("location") or dv["location"]), "slaves": []}
        try:
            e["size_bytes"] = int(a.get("size_in_mb")) * 1048576
        except (TypeError, ValueError):
            pass
        if name in lspv:
            e["dm_name"] = "VG %s (PVID %s)" % (lspv[name]["vg"], lspv[name]["pvid"])
        disks.append(dict((k, v) for k, v in e.items() if v not in (None, "")))
    h["disks"] = disks
    h["fc_hosts"] = [{"name": n, "port_name": aix_wwn(vpd.get(n, {}).get("Network Address")),
                      "node_name": aix_wwn(vpd.get(n, {}).get("Device Specific.(Z8)")), "port_state": dv["status"],
                      "speed": None, "symbolic_name": dv["description"], "port_type": None}
                     for n, dv in sorted(lsdev.items()) if n.startswith("fcs")]
    # interfaces : enN (IP) appuyées sur entN (carte, EtherChannel ou VLAN), cartes physiques membres
    addrs, ifaces, cur = [], [], None
    for line in (d.cmd("ifconfig", True) or "").splitlines():
        m = re.match(r"^(\S+): flags=", line)
        if m:
            cur = m.group(1)
            continue
        t = line.split()
        if cur and len(t) >= 2 and t[0] == "inet":
            pfx = None
            if "netmask" in t:
                try:
                    pfx = bin(int(t[t.index("netmask") + 1], 16)).count("1")
                except ValueError:
                    pfx = None
            addrs.append({"ifname": cur, "family": "inet", "cidr": t[1] + ("/%d" % pfx if pfx is not None else ""),
                          "scope": "host" if t[1].startswith("127.") else "global"})
        elif cur and len(t) >= 2 and t[0] == "inet6":
            a6 = re.sub(r"%\d+", "", t[1])
            addrs.append({"ifname": cur, "family": "inet6", "cidr": a6,
                          "scope": "link" if a6.startswith("fe80") else ("host" if a6.startswith("::1") else "global")})
    macs = {}
    for line in (d.cmd("netstat_in", True) or "").splitlines():
        p = line.split()
        if len(p) >= 4 and p[2].startswith("link#"):
            macs[p[0]] = aix_mac(p[3]) if re.match(r"^[0-9a-f.]+$", p[3] or "", re.I) and p[3].count(".") == 5 else None
    member_of = {}
    for name, a in attrs.items():
        for m in (a.get("adapter_names") or "").split(","):
            if m:
                member_of[m] = name
    ip_ifs = sorted(set(a["ifname"] for a in addrs) | set(n for n in macs))
    for n in ip_ifs:
        ent = re.sub(r"^en", "ent", n) if re.match(r"^en\d+$", n) else None
        a, v, dv = attrs.get(ent, {}), vpd.get(ent, {}), lsdev.get(ent, {})
        kind = "loopback" if n.startswith("lo") else ("bond" if a.get("adapter_names") else ("vlan" if a.get("vlan_tag_id") else
                ("virtual" if "Virtual" in dv.get("description", "") else ("physical" if ent else "virtual"))))
        i = {"name": n, "kind": kind, "address": macs.get(n) or aix_mac(v.get("Network Address")),
             "permanent_address": aix_mac(v.get("Network Address")), "mtu": attrs.get(n, {}).get("mtu"),
             "operstate": attrs.get(n, {}).get("state") or ("up" if n in macs else None),
             "driver": dv.get("type"), "pci_slot": v.get("Hardware Location Code") or None, "virtual": kind != "physical"}
        if a.get("adapter_names"):
            i["bond_mode"] = a.get("mode")
            i["bond_slaves"] = a["adapter_names"].split(",")
        if a.get("vlan_tag_id"):
            i["vlan_id"] = int(a["vlan_tag_id"]) if a["vlan_tag_id"].isdigit() else None
            i["parent"] = a.get("base_adapter")
        if ent:
            i["ethtool"] = {"driver": dv.get("type"), "firmware-version": v.get("ROM Level.(alterable)")}
            i["aix_adapter"] = ent
        ifaces.append(dict((k, val) for k, val in i.items() if val not in (None, "", [])))
    for ent, master in sorted(member_of.items()):
        v, dv = vpd.get(ent, {}), lsdev.get(ent, {})
        ifaces.append(dict((k, val) for k, val in {
            "name": ent, "kind": "physical", "master": re.sub(r"^ent", "en", master), "address": aix_mac(v.get("Network Address")),
            "permanent_address": aix_mac(v.get("Network Address")), "driver": dv.get("type"), "pci_slot": v.get("Hardware Location Code"),
            "operstate": dv.get("status"), "ethtool": {"driver": dv.get("type"), "firmware-version": v.get("ROM Level.(alterable)")},
            "virtual": False}.items() if val not in (None, "")))
        slot = v.get("Hardware Location Code")
        if slot and slot in pci:
            pass
    # ports en écoute et connexions (netstat -an ; pas de PID sans root)
    listening, conns = [], {}

    def split_addr(x):
        if "." not in x:
            return x, None
        host, port = x.rsplit(".", 1)
        return host, port
    lports = set()
    rows = []
    for line in (d.cmd("netstat_an", True) or "").splitlines():
        p = line.split()
        if len(p) >= 5 and p[0] in ("tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"):
            rows.append(p)
    for p in rows:
        if p[0].startswith("tcp") and len(p) >= 6 and p[5] == "LISTEN":
            h_, pt = split_addr(p[3])
            if pt and pt.isdigit():
                lports.add(int(pt))
    for p in rows:
        proto = p[0] if p[0][-1] in "46" else p[0] + "6"
        h_, pt = split_addr(p[3])
        if not (pt and pt.isdigit()):
            continue
        addr = ("0.0.0.0" if proto.endswith("4") else "::") if h_ == "*" else h_
        if (p[0].startswith("tcp") and len(p) >= 6 and p[5] == "LISTEN") or (p[0].startswith("udp") and p[4] == "*.*"):
            listening.append({"proto": proto, "address": addr, "port": int(pt), "pid": None, "process": None, "user": None})
        elif p[0].startswith("tcp") and len(p) >= 6 and p[5] == "ESTABLISHED":
            rh, rp = split_addr(p[4])
            key = ("in", int(pt), rh, None, None) if int(pt) in lports else ("out", None, rh, int(rp) if rp and rp.isdigit() else None, None)
            conns[key] = conns.get(key, 0) + 1
    n = {"interfaces": ifaces, "addresses": addrs, "listening": listening,
         "established": [{"direction": k[0], "local_port": k[1], "remote_addr": k[2], "remote_port": k[3], "process": k[4],
                          "count": c} for k, c in sorted(conns.items(), key=lambda kv: -kv[1])][:5000],
         "routes_v4": d.cmd("netstat_rn", True), "resolv_conf": d.file("/etc/resolv.conf"), "hosts_file": d.file("/etc/hosts"),
         "ifconfig": d.cmd("ifconfig", True), "netstat_in": d.cmd("netstat_in", True)}
    # paquets : filesets installp et RPM (AIX Toolbox)
    pk = {"managers": {}}
    rows = []
    for line in (d.cmd("lslpp_Lcq", True) or "").splitlines():
        if line.startswith("#"):
            continue
        p = line.split(":")
        if len(p) >= 8 and p[1]:
            rows.append({"package": p[0], "name": p[1], "version": p[2], "state": p[3], "ptf": p[4].strip() or None,
                         "fix_state": p[5].strip() or None, "type": p[6].strip() or None, "summary": p[7]})
    pk["managers"]["lslpp"] = rows
    rpm_rows = build_packages(d)["managers"].get("rpm")
    if rpm_rows:
        pk["managers"]["rpm"] = rpm_rows
    pk["repo_files"] = {}
    # services SRC
    units = []
    for line in (d.cmd("lssrc", True) or "").splitlines()[1:]:
        p = line.split()
        if len(p) >= 2:
            units.append({"unit": p[0], "load": "src", "active": "active" if p[-1] == "active" else "inactive",
                          "sub": p[-1], "description": "SRC" + (" groupe " + p[1] if len(p) >= 3 and not p[1].isdigit() else "")})
    sv = {"units": units, "inittab": d.file("/etc/inittab"), "rc_dirs": d.cmd("rc_dirs", True)}
    return o, h, pk, n, sv


# ---------------------------------------------------------------------------
# Processus et réseau
# ---------------------------------------------------------------------------
def build_processes(d, idx, users, btime):
    procs, inode_pid, names = [], {}, {}
    cur = None
    text = d.cmd("procs") or ""

    def flush(p):
        if p:
            procs.append(p)

    for line in text.splitlines():
        if line.startswith("@@PID "):
            flush(cur)
            cur = {"pid": int(line[6:].strip()), "mapped_libs": [], "deleted_mapped_files": [], "open_archives": [],
                   "env": {}, "in_container_ns": False}
            continue
        if cur is None:
            continue
        key, _, val = line.partition(" ")
        if key == "st":
            k, _, v = val.partition(" ")
            if k == "PPid:":
                cur["ppid"] = int(v) if v.isdigit() else None
            elif k == "Uid:":
                cur["uid"] = int(v) if v.isdigit() else None
                cur["user"] = users.get(cur["uid"])
            elif k == "Name:":
                cur["comm"] = v
        elif key == "exe":
            cur["exe"] = val or None
        elif key == "cwd":
            cur["cwd"] = val or None
        elif key == "cmd":
            cur["cmdline"] = C.redact(val.strip())[:8192]
        elif key == "stat":
            r = val.rfind(")")
            f = val[r + 2:].split()
            try:
                cur["start"] = C.now_iso(btime + int(f[19]) / 100.0) if btime else None
                cur["rss_bytes"] = int(f[21]) * 4096
            except (IndexError, ValueError):
                pass
        elif key == "del":
            if not val.startswith(("/dev/", "/memfd:", "/SYSV", "[")):
                cur["deleted_mapped_files"].append(val)
        elif key == "lib":
            cur["mapped_libs"].append(val)
        elif key == "fd":
            if val.startswith("socket:["):
                inode_pid[val[8:-1]] = cur["pid"]
            else:
                cur["open_archives"].append(val)
        elif key == "env":
            k, _, v = val.partition("=")
            cur["env"][k] = C.redact(v)[:2048]
        elif key == "cg":
            m = re.search(r"([0-9a-f]{64})", val)
            if m:
                cur["container_id"] = m.group(1)
                cur["in_container_ns"] = True
    flush(cur)
    for p in procs:
        for k in ("mapped_libs", "deleted_mapped_files", "open_archives", "env"):
            if not p[k]:
                del p[k]
        if p.get("exe"):
            if p["exe"].endswith(" (deleted)"):
                p["exe_deleted"] = True
            else:
                p["exe_owner_pkg"] = lookup_owner(idx, p["exe"])
        names[p["pid"]] = (p.get("comm"), p.get("user"))
    return {"count": len(procs), "list": procs}, inode_pid, names


def build_network(d, inode_pid, names):
    n = {}
    n["interfaces"], n["bonding"] = build_interfaces(d)
    addrs = C.parse_ip_o_addr(d.cmd("ip_addr", True))
    if not addrs:   # ifconfig ancien ("inet addr:10.0.0.5  Mask:255.255.255.0") ou récent
        ifname = None
        for line in (d.cmd("ifconfig", True) or "").splitlines():
            if line and not line[0].isspace():
                ifname = line.split()[0].rstrip(":")
            m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
            if m and ifname:
                addrs.append({"ifname": ifname, "family": "inet", "cidr": m.group(1),
                              "scope": "host" if m.group(1).startswith("127.") else "global"})
    n["addresses"] = addrs
    n["ifconfig"] = d.cmd("ifconfig", True)
    n["routes_v4"] = d.cmd("ip_route", True) or d.cmd("route", True)
    n["resolv_conf"] = d.file("/etc/resolv.conf")
    n["hosts_file"] = d.file("/etc/hosts")
    n["netstat_listen"] = d.cmd("netstat_listen", True) or d.cmd("ss_listen", True)
    raw = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        for line in (d.file("/proc/net/" + proto) or "").splitlines()[1:]:
            p = line.split()
            if len(p) >= 10:
                raw.append((proto, p))
    listen_ports = set()
    for proto, p in raw:
        if (proto.startswith("tcp") and p[3] == "0A") or (proto.startswith("udp") and p[3] == "07" and p[2].endswith(":0000")):
            listen_ports.add(int(p[1].split(":")[1], 16))
    listening, conns = [], {}
    for proto, p in raw:
        lip, lport = p[1].split(":")
        rip, rport = p[2].split(":")
        pid = inode_pid.get(p[9])
        comm, user = names.get(pid, (None, None))
        if (proto.startswith("tcp") and p[3] == "0A") or (proto.startswith("udp") and p[3] == "07" and rport == "0000"):
            listening.append({"proto": proto, "address": C.Collector._hex_ip(lip), "port": int(lport, 16),
                              "pid": pid, "process": comm, "user": user, "uid": int(p[7])})
        elif proto.startswith("tcp") and p[3] == "01":
            lp = int(lport, 16)
            key = ("in", lp, C.Collector._hex_ip(rip), None, comm) if lp in listen_ports else \
                ("out", None, C.Collector._hex_ip(rip), int(rport, 16), comm)
            conns[key] = conns.get(key, 0) + 1
    n["listening"] = listening
    n["established"] = [{"direction": k[0], "local_port": k[1], "remote_addr": k[2], "remote_port": k[3],
                         "process": k[4], "count": v} for k, v in sorted(conns.items(), key=lambda kv: -kv[1])][:5000]
    return n


def build_services(d):
    s = {}
    units = []
    for line in (d.cmd("systemctl_units", True) or "").splitlines():
        p = line.split(None, 4)
        if len(p) >= 4 and "." in p[0]:
            units.append({"unit": p[0], "load": p[1], "active": p[2], "sub": p[3], "description": p[4] if len(p) > 4 else ""})
    if units:
        s["units"] = units
    s["chkconfig"] = d.cmd("chkconfig", True)
    s["initctl"] = d.cmd("initctl", True)
    s["rc_dirs"] = d.cmd("rc_dirs", True)
    s["inittab"] = d.file("/etc/inittab")
    # Services SysV actifs vus par chkconfig, présentés comme des unités pour la base
    if not units and s["chkconfig"]:
        for line in s["chkconfig"].splitlines():
            p = line.split()
            if len(p) >= 8 and ":" in p[1]:
                on = [x.split(":")[0] for x in p[1:8] if x.endswith(":on")]
                s.setdefault("units", []).append({"unit": p[0] + ".service", "load": "sysv",
                                                  "active": "enabled" if on else "disabled",
                                                  "sub": "runlevels " + ",".join(on), "description": "SysV"})
    return s


def oracle_listing(text):
    """Sortie de oracle_ls : "== chemin" suivi des entrées du répertoire."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        if line.startswith("== "):
            cur = out.setdefault(line[3:], [])
        elif cur is not None and line:
            cur.append(line)
    return out


def build_oracle(d, procs):
    ora = {}
    if d.file("/etc/oratab") is not None:
        ora["oratab"] = d.file("/etc/oratab")
    loc = C.kv_text(d.file("/etc/oraInst.loc") or "")
    if loc:
        ora["oraInst_loc"] = loc
        inv = d.file(loc.get("inventory_loc", "") + "/ContentsXML/inventory.xml") if loc.get("inventory_loc") else None
        if inv:
            ora["central_inventory_homes"] = C.parse_central_inventory(inv)
    olr = d.file("/etc/oracle/olr.loc")
    if olr:
        ora["olr_loc"] = C.kv_text(olr)
    cands = C.oracle_home_candidates(ora.get("oratab"), ora.get("central_inventory_homes"), olr, procs)
    listing = oracle_listing(d.cmd("oracle_ls"))
    homes = []
    for home in sorted(cands)[:40]:
        f = C.oracle_home_facts(home, lambda rel, h=home: d.file(h + "/" + rel),
                                lambda rel, h=home: listing.get(h + "/" + rel))
        f["sources"] = cands[home]
        f["exists"] = (home + "/inventory/oneoffs") in listing
        homes.append(f)
    if homes:
        ora["homes"] = homes
    return ora


def build_misc(d, users_rows, procs=None):
    sched = {"cron_files": {}}
    for f in ["/etc/crontab", "/etc/anacrontab"]:
        t = d.file(f)
        if t is not None:
            sched["cron_files"][f] = C.redact(t)
    for dn in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
        for n in d.listdir(dn):
            t = d.file(dn + "/" + n)
            if t is not None:
                sched["cron_files"][dn + "/" + n] = C.redact(t)
    sched["cron_dirs_raw"] = d.cmd("cron_dirs", True)
    acc = {"passwd": users_rows, "groups": []}
    for line in (d.file("/etc/group") or "").splitlines():
        p = line.split(":")
        if len(p) >= 4:
            acc["groups"].append({"name": p[0], "gid": p[2], "members": [m for m in p[3].split(",") if m]})
    acc["sudoers"] = {}
    for f in ["/etc/sudoers"] + ["/etc/sudoers.d/" + n for n in d.listdir("/etc/sudoers.d")]:
        t = d.file(f)
        if t is not None:
            acc["sudoers"][f] = C.redact(t)
    acc["who"] = d.cmd("who", True)
    sec = {"sestatus": d.cmd("sestatus", True), "selinux_config": d.file("/etc/selinux/config"),
           "iptables_save": d.cmd("iptables", True), "ip6tables_save": d.cmd("ip6tables", True)}
    sshd_t = d.cmd("sshd_T", True)
    if sshd_t:
        sec["sshd_effective_config"] = sshd_t
    else:
        sec["sshd_config"] = C.redact(d.file("/etc/ssh/sshd_config") or "")
    ker = {"modules": [], "tainted": (d.file("/proc/sys/kernel/tainted") or "").strip(), "sysctl": d.cmd("sysctl"),
           "boot_dir_raw": d.cmd("boot", True)}
    for line in (d.file("/proc/modules") or "").splitlines():
        p = line.split()
        if p:
            ker["modules"].append({"name": p[0], "size": p[1], "state": p[4] if len(p) > 4 else None})
    ora = build_oracle(d, procs)
    return sched, acc, sec, ker, ora


# ---------------------------------------------------------------------------
# Système de fichiers : on rejoue le parcours du collecteur Python sur la copie
# ---------------------------------------------------------------------------
class DumpScanner(C.Collector):
    def __init__(self, dump, idx):
        args = C.parse_args(["-o", "/dev/null", "--exclude=/nonexistent"])
        args.exclude = []
        args.scan_root = [dump.fsroot]
        args.scan_max_seconds = 3600
        args.hash_archives = False
        C.Collector.__init__(self, args)
        self.dump = dump
        self.idx = idx
        self.prefix = dump.fsroot

    def owner(self, path):
        if path and path.startswith(self.prefix):
            path = path[len(self.prefix):]
        return lookup_owner(self.idx, path)

    def add_probe_candidate(self, path, origin):
        return None

    def resolve_db_hosts(self, refs):
        return {}           # pas de résolution depuis le contrôleur : le DNS n'est pas celui de la cible


def strip_prefix(obj, prefix):
    if isinstance(obj, dict):
        return dict((k, strip_prefix(v, prefix)) for k, v in obj.items())
    if isinstance(obj, list):
        return [strip_prefix(v, prefix) for v in obj]
    if isinstance(obj, str) and prefix in obj:
        return obj.replace(prefix, "")
    return obj


def parse_archives(text, idx):
    """Records A/m/p/c/s/X/E -> arborescence identique à inspect_archive()."""
    flat = []
    cur = None
    for line in (text or "").splitlines():
        tag, _, rest = line.partition("\t")
        if tag == "A":
            parts = rest.split("\t")
            cur = {"path": parts[0], "_manifest": [], "_pom": {}, "_classes": [], "_server": []}
            if len(parts) > 1 and parts[1].isdigit():
                cur["size"] = int(parts[1])
            if len(parts) > 2 and parts[2] not in ("-", ""):
                cur["sha1"] = parts[2]
            flat.append(cur)
        elif cur is None:
            continue
        elif tag == "m":
            cur["_manifest"].append(rest)
        elif tag == "p":
            entry, _, l2 = rest.partition("\t")
            cur["_pom"].setdefault(entry, []).append(l2)
        elif tag == "c":
            cur["_classes"].append(rest)
        elif tag == "s":
            cur["_server"].append(rest)
        elif tag == "X":
            cur["error"] = rest[:300]
    by_path = {}
    roots = []
    for a in flat:
        if a["_manifest"]:
            a["manifest"] = C.parse_manifest("\n".join(a["_manifest"]))
        mav = []
        for _entry, lines in sorted(a["_pom"].items()):
            pp = C.parse_properties("\n".join(lines))
            mav.append({"groupId": pp.get("groupId"), "artifactId": pp.get("artifactId"), "version": pp.get("version")})
        if mav:
            a["maven"] = mav
        marks = set()
        for name in a["_classes"]:
            base = name.rsplit("/", 1)[-1]
            for key in C.CLASS_MARKER_BASENAMES.get(base, []):
                if name.endswith(key):
                    marks.add(C.CLASS_MARKERS[key] + ("" if name == key else " (shaded:%s)" % name[:-len(key)].rstrip("/")))
        if marks:
            a["markers"] = sorted(marks)
        if a["_server"]:
            a["special"] = {"tomcat_serverinfo": C.parse_properties("\n".join(a["_server"]))}
        for k in ("_manifest", "_pom", "_classes", "_server"):
            del a[k]
        by_path[a["path"]] = a
        if "!/" in a["path"]:
            parent = by_path.get(a["path"].rsplit("!/", 1)[0])
            if parent is not None:
                parent.setdefault("nested", []).append(a)
                continue
        o = lookup_owner(idx, a["path"])
        if o:
            a["owner_pkg"] = o
        roots.append(a)
    return roots


def build_filesystem(d, idx):
    sc = DumpScanner(d, idx)
    fs = sc.scan_filesystem()
    fs = strip_prefix(fs, d.fsroot)
    fs["java_archives"] = parse_archives(d.cmd("archives"), idx)
    found_set = set((d.scan("found.lst") or "").splitlines())
    proc_set = set((d.scan("proc_archives.lst") or "").splitlines())
    for a in fs["java_archives"]:
        if a["path"] in proc_set and a["path"] not in found_set:
            a["origin"] = "process"
    fs["archives_method"] = (d.scan("archives.method") or "").strip() or None
    # JDK : le shell n'a copié "release" que si bin/java existait
    fs["jdk_homes"] = []
    fs["db_datadirs"] = [x for x in fs.get("db_datadirs", []) if x.get("engine") != "postgresql"]
    for root, _dirs, files in os.walk(d.fsroot):
        rel = root[len(d.fsroot):] or "/"
        if "release" in files:
            t = d.file(rel + "/release") or ""
            if "JAVA_VERSION" in t:
                fs["jdk_homes"].append({"path": rel, "release": C.kv_text(t),
                                        "owner_pkg": lookup_owner(idx, rel + "/release")})
        if "PG_VERSION" in files and "/base/" not in rel + "/":
            fs["db_datadirs"].append({"engine": "postgresql", "path": rel,
                                      "version": (d.file(rel + "/PG_VERSION") or "").strip()})
    libs = []
    for line in (d.scan("native_libs.lst") or "").splitlines():
        path, _, embedded = line.partition("\t")
        if not path or "-packages/" in path:   # mêmes règles que le collecteur Python
            continue
        name = path.rsplit("/", 1)[-1]
        fm = re.search(r"\.so\.([\d.]+)$", name) or re.search(r"-([\d.]+)\.so$", name)
        e = {"path": path, "name": name, "version_from_filename": fm.group(1) if fm else None}
        m = re.match(r"OpenSSL (\S+)", embedded.strip()) or re.match(r"X-Powered-By: PHP/(\S+)", embedded.strip())
        if m:
            e["embedded_version"] = m.group(1)
        o = lookup_owner(idx, path)
        if o:
            e["owner_pkg"] = o
        libs.append(e)
    fs["native_libs"] = libs
    stats = fs.get("stats") or {}
    found = d.scan("found.lst") or ""
    stats.update({"files_matched": found.count("\n"), "find_rc": (d.scan("find.rc") or "").strip(),
                  "truncated": (d.scan("find.rc") or "").strip() in ("143", "137")})
    for k in ("skipped_mounts", "excludes", "files", "dirs"):
        stats.pop(k, None)
    fs["stats"] = stats
    return fs


def parse_fingerprints(d, idx):
    """fingerprints.lst : chemin, raison, produit, chaîne trouvée -> {chemin: entrée}."""
    rx = dict(C.FINGERPRINTS)
    out = {}
    for line in (d.scan("fingerprints.lst") or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        path, reason, product, raw = parts[0], parts[1], parts[2], "\t".join(parts[3:])
        m = rx[product].search(raw.encode("utf-8", "replace")) if product in rx else None
        if not m:
            continue
        e = out.setdefault((path, reason), {"path": path, "reason": reason, "found": {}})
        v = m.group(1).decode("utf-8", "replace")
        if v not in e["found"].setdefault(product, []):
            e["found"][product].append(v)
        if reason in ("process_exe", "mapped_lib", "probe"):
            o = lookup_owner(idx, path)
            if o:
                e["owner_pkg"] = o
    return out


def build_runtimes(d, idx, fps=None):
    text = d.scan("probes.txt") or ""
    entries, aliases = [], {}
    cur, out = None, None
    for line in text.splitlines():
        if line.startswith("@@PROBE\t"):
            parts = (line.split("\t") + ["", "", "", "", ""])[:5]
            cur = {"probe": parts[1], "realpath": parts[2], "paths": [parts[3]], "origins": ["shell"]}
            if parts[4]:
                cur["skipped"] = parts[4]
            o = lookup_owner(idx, parts[2])
            if o:
                cur["owner_pkg"] = o
            entries.append(cur)
            out = None
        elif line.startswith("@@ALIAS\t"):
            _, rp, path = (line.split("\t") + ["", ""])[:3]
            aliases.setdefault(rp, []).append(path)
        elif line.startswith("@@ARGS\t") and cur is not None:
            out = {"args": line[7:].split(), "rc": None, "output": []}
            cur.setdefault("outputs", []).append(out)
        elif line.startswith("@@RC\t") and out is not None:
            try:
                out["rc"] = int(line[5:])
            except ValueError:
                pass
            out["timeout"] = out["rc"] in (143, 137)
            out["output"] = "\n".join(out["output"]).strip()[:65536]
            out = None
        elif out is not None:
            out["output"].append(line)
    for e in entries:
        e["paths"] = sorted(set(e["paths"] + aliases.get(e["realpath"], [])))
        fp = (fps or {}).get((e["realpath"], "probe"))
        if fp:
            e["fingerprint"] = fp["found"]
    return {"count": len(entries), "list": entries}


# ---------------------------------------------------------------------------
def convert(tgz_bytes):
    tmp = tempfile.mkdtemp(prefix="cmdb-sh-")
    try:
        safe_extract(tgz_bytes, tmp)
        d = Dump(tmp)
        meta_kv = C.kv_text(read_all(os.path.join(tmp, "meta.txt")))
        idx = owner_index(d)
        users_rows, users = [], {}
        for line in (d.file("/etc/passwd") or "").splitlines():
            p = line.split(":")
            if len(p) >= 7:
                uid = int(p[2]) if p[2].isdigit() else p[2]
                users_rows.append({"name": p[0], "uid": uid, "gid": p[3], "gecos": p[4], "home": p[5], "shell": p[6]})
                users[uid] = p[0]
        bt = (d.cmd("btime") or "").split()
        btime = int(bt[1]) if len(bt) > 1 and bt[1].isdigit() else 0
        doc = {"schema": C.SCHEMA, "meta": {
            "collector": "shell", "collector_version": meta_kv.get("collector_version"),
            "run_id": meta_kv.get("run_id") or None, "os": meta_kv.get("os") or None,
            "tags": dict((k[4:], v) for k, v in meta_kv.items() if k.startswith("tag_")),
            "started_at": meta_kv.get("started_at"), "finished_at": meta_kv.get("finished_at"),
            "duration_seconds": float(meta_kv.get("duration_seconds") or 0),
            "host_label": meta_kv.get("host_label") or None, "uid": meta_kv.get("uid"),
            "shell": meta_kv.get("shell"), "converted_at": C.now_iso(), "errors": [],
            "log": read_all(os.path.join(tmp, "log.txt")),
        }}
        is_aix = (meta_kv.get("os") or (d.cmd("uname_s", True) or "").strip()) == "AIX"
        if is_aix:
            doc["os"], doc["hardware"], doc["packages"], aix_net, doc["services"] = build_aix(d)
        else:
            doc["os"] = build_os(d)
            doc["hardware"] = build_hardware(d)
            doc["packages"] = build_packages(d)
        doc["packages"]["owner_index"] = {"kind": "shell", "entries": len(idx)}
        doc["processes"], inode_pid, names = build_processes(d, idx, users, btime)
        if is_aix:
            doc["network"] = aix_net
        else:
            doc["network"] = build_network(d, inode_pid, names)
            doc["services"] = build_services(d)
        doc["scheduled"], doc["accounts"], doc["security"], doc["kernel"], doc["oracle"] = build_misc(d, users_rows, doc["processes"]["list"])
        doc["containers"] = {}
        doc["software_dirs"] = {"raw": d.cmd("software_dirs", True)}
        if os.path.exists(os.path.join(tmp, "scan", "found.lst")) or os.path.exists(os.path.join(tmp, "scan", "archives.lst")):
            doc["filesystem"] = build_filesystem(d, idx)
        fps = parse_fingerprints(d, idx)
        doc["runtimes"] = build_runtimes(d, idx, fps)
        procs = doc["processes"]["list"]
        doc["meta"]["visibility"] = {"processes": len(procs),
                                     "processes_exe_readable": sum(1 for p in procs if p.get("exe")),
                                     "fs_unreadable_dirs": None}
        doc["meta"]["user"] = users.get(int(meta_kv["uid"])) if (meta_kv.get("uid") or "").isdigit() else None
        doc["process_artifacts"] = {
            "jvm_homes": [{"path": h, "release": C.kv_text(d.file(h + "/release") or ""),
                           "already_in_filesystem_scan": True}
                          for h in (d.scan("jvm_homes.lst") or "").splitlines() if h],
            "archives": [],   # intégrées à filesystem.java_archives (origin = process)
            "fingerprints": [v for (path, reason), v in sorted(fps.items()) if reason != "probe"],
        }
        doc["go_binaries"] = {"list": [], "note": "non collecté par le collecteur shell"}
        return C.sanitize(doc)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Convertit une collecte shell (tar.gz) en JSON CMDB")
    ap.add_argument("src")
    ap.add_argument("dst")
    a = ap.parse_args()
    with open(a.src, "rb") as f:
        data = f.read()
    t0 = time.time()
    doc = convert(data)
    with gzip.open(a.dst, "wb") as f:
        f.write(json.dumps(doc).encode("utf-8"))
    print("%s : converti en %.1fs" % (a.dst, time.time() - t0))


if __name__ == "__main__":
    sys.exit(main())
