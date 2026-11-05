#!/bin/sh
# ---------------------------------------------------------------------------
# cmdb_collector.sh - collecteur CMDB de secours en shell POSIX
#
# Pour AIX, pour les Linux trop anciens pour cmdb_collector.py (Python < 2.6 :
# CentOS/RHEL 4-5, SLES 10, Debian <= 5...) et pour les systèmes sans Python.
# Compatible ksh (AIX), bash 3, dash, busybox sh ; n'utilise que des outils
# présents partout (find, sed, awk, grep, dd, tar ; gzip, base64, readlink,
# mktemp et "date +%s" sont facultatifs). Aucun privilège requis.
#
# Principe : ce script ne fait AUCUNE interprétation. Il entasse les sorties
# de commandes et des copies tronquées des fichiers utiles dans un
# répertoire temporaire, l'archive (tar.gz), l'encode en base64 et l'écrit
# sur stdout entre deux marqueurs. Le contrôleur (tools/cmdb_unpack.py +
# tools/cmdb_shell_parse.py) le convertit au même format JSON que le
# collecteur Python ; la consolidation est ensuite identique.
#
# Lecture seule. Les seuls binaires exécutés pour obtenir une version sont
# des exécutables (ELF ou XCOFF) appartenant à root dans une arborescence non
# modifiable par d'autres utilisateurs ; tout le reste est seulement lu.
# ---------------------------------------------------------------------------

VERSION="1.2.0-sh"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/etc:/usr/ucb:/opt/freeware/bin:/opt/freeware/sbin
# Tests uniquement : répertoire de substituts placé en tête du PATH
[ -n "$CMDB_TEST_PATH" ] && PATH="$CMDB_TEST_PATH:$PATH"
LC_ALL=C
LANG=C
export PATH LC_ALL LANG
umask 077

HOST_LABEL=""
DO_SCAN=1
DO_EXEC=1
DO_HASH=1
SCAN_MAX=900
EXEC_MAX=300
EXEC_TIMEOUT=20
EXTRA_PRUNE=""
EXTRA_EXCL=""
TAGS=""
RUN_ID=""

while [ $# -gt 0 ]; do
    # option à valeur sans valeur : ignorée plutôt qu'une erreur fatale de "shift"
    case "$1" in
        --host-label|--scan-max-seconds|--exec-max-seconds|--exec-timeout|--extra-exclude|--tag|--run-id)
            [ $# -ge 2 ] || break ;;
    esac
    case "$1" in
        --host-label) HOST_LABEL=$2; shift ;;
        --host-label=*) HOST_LABEL=${1#*=} ;;
        --scan-max-seconds) SCAN_MAX=$2; shift ;;
        --scan-max-seconds=*) SCAN_MAX=${1#*=} ;;
        --exec-max-seconds) EXEC_MAX=$2; shift ;;
        --exec-max-seconds=*) EXEC_MAX=${1#*=} ;;
        --exec-timeout) EXEC_TIMEOUT=$2; shift ;;
        --exec-timeout=*) EXEC_TIMEOUT=${1#*=} ;;
        --no-scan-filesystem) DO_SCAN=0 ;;
        --no-exec-probes) DO_EXEC=0 ;;
        --no-hash-archives) DO_HASH=0 ;;
        --extra-exclude) EXTRA_PRUNE="$EXTRA_PRUNE -o -path $2"; EXTRA_EXCL="$EXTRA_EXCL $2"; shift ;;
        --extra-exclude=*) EXTRA_PRUNE="$EXTRA_PRUNE -o -path ${1#*=}"; EXTRA_EXCL="$EXTRA_EXCL ${1#*=}" ;;
        --tag) TAGS="$TAGS $2"; shift ;;
        --tag=*) TAGS="$TAGS ${1#*=}" ;;
        --run-id) RUN_ID=$2; shift ;;
        --run-id=*) RUN_ID=${1#*=} ;;
        *) ;;   # options du collecteur Python ignorées
    esac
    shift
done

# have CMD : présent dans le PATH ? (sans "command -v", absent de certains ksh)
have() {
    _hv_ifs=$IFS; IFS=:
    for _hv_d in $PATH; do
        if [ -x "$_hv_d/$1" ] && [ ! -d "$_hv_d/$1" ]; then IFS=$_hv_ifs; return 0; fi
    done
    IFS=$_hv_ifs; return 1
}

# Secondes depuis l'époque, sans dépendre de "date +%s" (absent d'AIX)
now_epoch() {
    _ne=$(date +%s 2>/dev/null)
    case "$_ne" in ''|*[!0-9]*) _ne=$(awk 'BEGIN { srand(); print srand() }' 2>/dev/null) ;; esac
    case "$_ne" in ''|*[!0-9]*) _ne=$(perl -e 'print time' 2>/dev/null) ;; esac
    echo "${_ne:-0}"
}

OS=$(uname -s 2>/dev/null)
# /proc au format texte de Linux (absent d'AIX, où l'on passe par ps)
if [ -r "/proc/$$/stat" ] && [ -z "$CMDB_FORCE_PS" ]; then PROC_TEXT=1; else PROC_TEXT=0; fi

# Priorité basse
renice 19 -p $$ >/dev/null 2>&1 || renice -n 19 -p $$ >/dev/null 2>&1
have ionice && ionice -c 3 -p $$ >/dev/null 2>&1

W=""
TMPBASE=${TMPDIR:-/tmp}
if have mktemp; then W=$(mktemp -d "$TMPBASE/cmdb.XXXXXX" 2>/dev/null); fi
if [ -z "$W" ]; then W=$TMPBASE/cmdb.$$.$(now_epoch); mkdir "$W" || exit 1; fi
cleanup() { rm -rf "$W" "$W.tgz"; }
trap cleanup 0
trap 'exit 1' INT TERM HUP
mkdir "$W/cmd" "$W/fs" "$W/scan"
START_EPOCH=$(now_epoch)
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >>"$W/log.txt"; }

# Identité d'un processus : date de démarrage (champ 22 de /proc/PID/stat) sous
# Linux, PID parent ailleurs (AIX). Sert à s'assurer qu'un PID n'a pas été
# réattribué avant de lui envoyer un signal (les PID bouclent vite pendant une
# collecte ; un PID recyclé peut être le shell principal lui-même).
pstart() {
    if [ "$PROC_TEXT" = 1 ]; then
        sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
    else
        ps -o ppid= -p "$1" 2>/dev/null | awk 'NF {print "ppid" $1}'
    fi
}

children_of() {
    if [ "$PROC_TEXT" = 1 ]; then
        cat /proc/[0-9]*/stat 2>/dev/null | sed 's/ (.*) / X /' | awk -v p="$1" '$4 == p {print $1}'
    else
        ps -e -o pid= -o ppid= 2>/dev/null | awk -v p="$1" '$2 == p {print $1}'
    fi
}

# killtree PID SIGNAL : signal envoyé au processus et à tous ses descendants
# (une fonction shell en arrière-plan ne relaie pas le signal à ses enfants).
killtree() {
    for _k in $(children_of "$1"); do
        killtree "$_k" "$2"
    done
    kill -"$2" "$1" 2>/dev/null
}

# tmo SECONDES commande... : exécute avec un délai maximal (sans "timeout",
# absent des vieux coreutils).
#  - la commande et le chien de garde tournent dans des sous-shells dont les
#    pièges (trap) sont explicitement réinitialisés : selon les shells, un
#    sous-shell tué pouvait sinon exécuter le nettoyage final du script ;
#  - le chien de garde n'est jamais tué : il s'arrête seul (au plus 1 s) dès
#    que la commande est terminée, et ne frappe que si le PID désigne toujours
#    le même processus ;
#  - il n'hérite pas de stdout (sinon Ansible attendrait sa fin).
tmo() {
    _t=$1; shift
    ( trap - 0 INT TERM HUP; "$@" ) </dev/null &
    _p=$!
    _s=$(pstart "$_p")
    if [ -n "$_s" ]; then
        ( trap - 0 INT TERM HUP
          _i=0
          while [ "$_i" -lt "$_t" ]; do
              sleep 1
              [ "$(pstart "$_p")" = "$_s" ] || exit 0
              _i=$((_i + 1))
          done
          killtree "$_p" TERM
          sleep 2
          [ "$(pstart "$_p")" = "$_s" ] && killtree "$_p" KILL
        ) </dev/null >/dev/null 2>&1 &
    fi
    wait "$_p"
}

# capt SECONDES NOM commande... : sortie, erreurs et code retour dans cmd/NOM.*
capt() {
    _ct=$1; _n=$2; shift 2
    tmo "$_ct" "$@" >"$W/cmd/$_n.out" 2>"$W/cmd/$_n.err"
    echo $? >"$W/cmd/$_n.rc"
}
cap() { capt 60 "$@"; }

# grab FICHIER... : copie (tronquée à 4 Mo) sous fs/<chemin d'origine>
_lastdir=""
grab_lim() {
    _lim=$1; shift
    for _f in "$@"; do
        [ -f "$_f" ] && [ -r "$_f" ] || continue
        _d="$W/fs${_f%/*}"
        if [ "$_d" != "$_lastdir" ]; then mkdir -p "$_d" 2>/dev/null; _lastdir=$_d; fi
        dd if="$_f" of="$W/fs$_f" bs=1024 count="$_lim" 2>/dev/null
    done
}
grab() { grab_lim 4096 "$@"; }

# Recherche de chaînes dans un binaire : grep -a -o si disponible, sinon strings
if echo x | grep -a x >/dev/null 2>&1; then GREPA="grep -a"; else GREPA="grep"; fi
if [ "$(echo xab | grep -o ab 2>/dev/null)" = ab ]; then GREP_O=1; else GREP_O=0; fi
bin_match() {   # FICHIER MOTIF_BRE -> première occurrence
    if [ "$GREP_O" = 1 ]; then $GREPA -o "$2" "$1" 2>/dev/null | head -1
    elif have strings; then strings -a "$1" 2>/dev/null | grep "$2" | head -1
    fi
}

# Nature d'un fichier exécutable : elf (Linux), xcoff (AIX 32/64 bits) ou autre
bin_kind() {
    _bk=$(dd if="$1" bs=4 count=1 2>/dev/null | od -A n -t x1 2>/dev/null | tr -d ' \n')
    case "$_bk" in 7f454c46*) echo elf ;; 01df*|01f7*) echo xcoff ;; *) echo other ;; esac
}
is_bin() { case "$(bin_kind "$1")" in elf|xcoff) return 0 ;; esac; return 1; }

# Chemin exclu (options --extra-exclude), pour les find sans -path
excluded() {
    for _x in /proc /sys /dev /run /var/run /var/lib/docker /var/lib/containers $EXTRA_EXCL; do
        case "$1" in "$_x"|"$_x"/*) return 0 ;; esac
    done
    return 1
}
# ---------------------------------------------------------------------------
section_os() {
    log "os"
    grab /etc/os-release /etc/redhat-release /etc/centos-release /etc/system-release /etc/oracle-release \
         /etc/debian_version /etc/lsb-release /etc/SuSE-release /etc/issue /etc/machine-id \
         /var/lib/dbus/machine-id /etc/timezone /etc/sysconfig/clock /etc/locale.conf /etc/default/locale \
         /etc/sysconfig/i18n /etc/environment /etc/profile.d/* /proc/version /proc/cmdline /proc/uptime \
         /proc/loadavg /etc/inittab
    cap btime grep '^btime' /proc/stat
    cap uname_s uname -s; cap uname_n uname -n; cap uname_r uname -r; cap uname_v uname -v; cap uname_m uname -m
    cap hostname hostname
    capt 10 hostname_f hostname -f
    cap getenforce getenforce
    cap glibc getconf GNU_LIBC_VERSION
    cap needs_restarting needs-restarting -r
    cap runlevel runlevel
    [ -f /var/run/reboot-required ] && grab /var/run/reboot-required /var/run/reboot-required.pkgs
}

# Interfaces, disques et HBA lus dans /sys (lisible sans root, présent depuis les noyaux 2.6)
net_dump() {
    for _i in /sys/class/net/*; do
        [ -e "$_i" ] || continue
        _n=${_i##*/}
        printf '@@IF %s\n' "$_n"
        for _k in address mtu operstate carrier speed duplex type ifindex iflink addr_assign_type \
                  device/vendor device/device bonding/mode bonding/slaves; do
            _v=$(cat "$_i/$_k" 2>/dev/null) && [ -n "$_v" ] && printf '%s %s\n' "$_k" "$_v"
        done
        if [ -e "$_i/device" ]; then
            printf 'device %s\n' "$(readlink "$_i/device" 2>/dev/null)"
            printf 'realdevice %s\n' "$(cd "$_i/device" 2>/dev/null && pwd -P)"
            _d=$(readlink "$_i/device/driver" 2>/dev/null); [ -n "$_d" ] && printf 'driver %s\n' "${_d##*/}"
            if have ethtool; then
                ethtool -i "$_n" 2>/dev/null | sed 's/^/ethtool_i /'
                ethtool -P "$_n" 2>/dev/null | sed 's/^/ethtool_P /'
            fi
        fi
        _d=$(readlink "$_i/master" 2>/dev/null); [ -n "$_d" ] && printf 'master %s\n' "${_d##*/}"
        [ -d "$_i/bonding" ] && echo "isbond 1"
        [ -d "$_i/bridge" ] && printf 'bridge_ports %s\n' "$(ls "$_i/brif" 2>/dev/null | tr '\n' ' ')"
        sed -n 's/^DEVTYPE=/devtype /p' "$_i/uevent" 2>/dev/null
    done
}

disk_dump() {
    for _b in /sys/block/*; do
        [ -e "$_b" ] || continue
        _n=${_b##*/}
        case "$_n" in loop*|ram*|zram*|fd*) continue ;; esac
        printf '@@DISK %s\n' "$_n"
        for _k in size removable ro queue/rotational device/model device/vendor device/rev device/serial \
                  device/wwid wwid dm/name dm/uuid; do
            _v=$(cat "$_b/$_k" 2>/dev/null) && [ -n "$_v" ] && printf '%s %s\n' "$_k" "$_v"
        done
        _sp=$(readlink "$_b" 2>/dev/null); [ -n "$_sp" ] || _sp=$(cd "$_b/device" 2>/dev/null && pwd -P)
        printf 'syspath %s\n' "$_sp"
        printf 'slaves %s\n' "$(ls "$_b/slaves" 2>/dev/null | tr '\n' ' ')"
    done
}

fc_dump() {
    for _f in /sys/class/fc_host/*; do
        [ -e "$_f" ] || continue
        printf '@@FC %s\n' "${_f##*/}"
        for _k in port_name node_name port_state speed symbolic_name port_type; do
            _v=$(cat "$_f/$_k" 2>/dev/null) && [ -n "$_v" ] && printf '%s %s\n' "$_k" "$_v"
        done
    done
}

section_hw() {
    log "hardware"
    cap dmidecode dmidecode
    grab /proc/cpuinfo /proc/meminfo /proc/mounts /sys/class/dmi/id/* /sys/devices/system/cpu/vulnerabilities/*
    capt 30 df df -P -k -l     # -l : systèmes de fichiers locaux seulement (un NFS figé bloquerait df)
    [ "$(cat "$W/cmd/df.rc")" = 0 ] || capt 30 df df -P -k
    cap mount mount
    cap lspci lspci
    cap lsblk lsblk -P -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,WWN,TRAN,VENDOR
    [ "$(cat "$W/cmd/lsblk.rc")" = 0 ] || cap lsblk lsblk -P -b -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT
    cap net_sys net_dump
    cap disk_sys disk_dump
    cap fc_sys fc_dump
    cap ip_link_d ip -o -d link show
    cap lscpu lscpu
    cap lspci_vmm lspci -D -vmm -nn -k
    [ "$(cat "$W/cmd/lspci_vmm.rc")" = 0 ] || cap lspci_vmm lspci -vmm -nn
    cap hostnamectl hostnamectl
    grab /proc/net/bonding/*
}

OWN_RX='(\.(jar|war|ear|so(\.[0-9.]+)?|js|json|php|inc|gemspec|txt|xml|cfg)	|/(METADATA|PKG-INFO|release|PG_VERSION)	|/s?bin/|/libexec/|\.(dist|egg)-info)'

rpm_owners() { rpm -qa --qf '[%{FILENAMES}\t%{NAME}\n]' 2>/dev/null | grep -E "$OWN_RX"; }
dpkg_owners() {
    for _l in /var/lib/dpkg/info/*.list; do
        [ -f "$_l" ] || continue
        _pkg=${_l##*/}; _pkg=${_pkg%.list}; _pkg=${_pkg%%:*}
        sed "s|\$|	$_pkg|" "$_l" | grep -E "$OWN_RX"
    done
}

section_packages() {
    log "packages"
    if have rpm; then
        capt 300 rpm_qa rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{SOURCERPM}\t%{PACKAGER}\t\t\t%{SUMMARY}\n'
        capt 600 owners_rpm rpm_owners
    fi
    if have dpkg-query; then
        capt 300 dpkg_query dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${Source}\t\t${Maintainer}\t${Installed-Size}\t\n'
        capt 600 owners_dpkg dpkg_owners
    fi
    grab /etc/yum.conf /etc/yum.repos.d/* /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/zypp/repos.d/* \
         /etc/sysconfig/rhn/sources /lib/apk/db/installed
}

# Processus : un bloc par PID, lu directement dans /proc
ENV_RX='^(JAVA_HOME|JRE_HOME|CATALINA_HOME|CATALINA_BASE|JBOSS_HOME|ORACLE_HOME|ORACLE_SID|PATH|LD_LIBRARY_PATH|LD_PRELOAD|PYTHONPATH|PHPRC|GEM_HOME|PGDATA|JAVA_OPTS|CATALINA_OPTS)='
proc_dump() {
    for _pd in /proc/[0-9]*; do
        _pid=${_pd#/proc/}
        [ "$_pid" = "$$" ] && continue
        [ -r "$_pd/cmdline" ] || continue
        _cmd=$(tr '\000' ' ' <"$_pd/cmdline" 2>/dev/null)
        [ -n "$_cmd" ] || continue          # threads noyau
        printf '@@PID %s\n' "$_pid"
        awk '/^(PPid|Uid|Name):/ {print "st", $1, $2}' "$_pd/status" 2>/dev/null
        printf 'exe %s\n' "$(readlink "$_pd/exe" 2>/dev/null)"
        printf 'cwd %s\n' "$(readlink "$_pd/cwd" 2>/dev/null)"
        printf 'cmd %s\n' "$_cmd"
        printf 'stat %s\n' "$(cat "$_pd/stat" 2>/dev/null)"
        grep ' (deleted)' "$_pd/maps" 2>/dev/null | awk '{print "del", $6}' | sort -u
        grep '\.so' "$_pd/maps" 2>/dev/null | awk '$6 ~ /^\// {print "lib", $6}' | sort -u
        ls -l "$_pd/fd" 2>/dev/null | sed -n 's/.* -> //p' | grep -E '^socket:|\.(jar|war|ear)$' | sed 's/^/fd /'
        tr '\000' '\n' <"$_pd/environ" 2>/dev/null | grep -E "$ENV_RX" | sed 's/^/env /'
        grep -E 'docker|lxc|libpod' "$_pd/cgroup" 2>/dev/null | head -1 | sed 's/^/cg /'
    done
}

section_processes() { log "processes"; capt 300 procs proc_dump; }

section_network() {
    log "network"
    grab /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 /etc/resolv.conf /etc/hosts /etc/nsswitch.conf \
         /etc/sysconfig/network /etc/sysconfig/network-scripts/ifcfg-* /etc/network/interfaces
    cap ip_addr ip -o addr show
    cap ifconfig ifconfig -a
    cap ip_route ip route
    cap route route -n
    cap netstat_listen netstat -tulnp
    cap ss_listen ss -tulnp
}

section_services() {
    log "services"
    cap chkconfig chkconfig --list
    cap initctl initctl list
    cap rc_dirs sh -c 'ls -l /etc/rc.d/rc[0-6].d /etc/rc[0-6S].d /etc/init.d 2>/dev/null'
    if have systemctl; then
        cap systemctl_units systemctl list-units --all --no-legend --no-pager
        cap systemctl_files systemctl list-unit-files --no-legend --no-pager
    fi
}

# ORACLE_HOME connus : oratab, inventaire central, olr.loc, listeners en cours d'exécution
oracle_homes() {
    {
        [ -r /etc/oratab ] && awk -F: '$0 !~ /^[ \t]*#/ && NF >= 2 { print $2 }' /etc/oratab
        if [ -r /etc/oraInst.loc ]; then
            _inv=$(sed -n 's/^inventory_loc=//p' /etc/oraInst.loc | head -1)
            [ -r "$_inv/ContentsXML/inventory.xml" ] && grep '<HOME ' "$_inv/ContentsXML/inventory.xml" \
                | grep -v 'REMOVED="T"' | sed -n 's/.* LOC="\([^"]*\)".*/\1/p'
        fi
        [ -r /etc/oracle/olr.loc ] && sed -n 's/^crs_home=//p' /etc/oracle/olr.loc
        ps -eo args 2>/dev/null | sed -n 's#^\(/[^ ]*\)/bin/tnslsnr.*#\1#p'
    } | sed 's#/*$##' | sort -u | grep '^/' | head -40
}
oracle_ls() {
    while IFS= read -r _h; do
        for _r in inventory/oneoffs .patch_storage dbs; do
            echo "== $_h/$_r"; ls -1A "$_h/$_r" 2>/dev/null | head -1000
        done
    done <"$W/scan/oracle_homes.lst"
}
# Lecture seule des fichiers d'inventaire ; opatch n'est jamais exécuté (compte oracle,
# et il écrit dans cfgtoollogs). Un ORACLE_HOME illisible se traduit par des fichiers absents.
section_oracle() {
    if [ -f /etc/oraInst.loc ]; then
        _inv=$(sed -n 's/^inventory_loc=//p' /etc/oraInst.loc | head -1)
        [ -n "$_inv" ] && grab "$_inv/ContentsXML/inventory.xml"
    fi
    grab /etc/oracle/olr.loc
    oracle_homes >"$W/scan/oracle_homes.lst" 2>/dev/null
    [ -s "$W/scan/oracle_homes.lst" ] || return 0
    while IFS= read -r _h; do
        grab_lim 16384 "$_h/inventory/ContentsXML/comps.xml"
        grab_lim 1024 "$_h/inventory/globalvariables/oracle.server/globalvariables.xml"
        grab_lim 8 "$_h/OPatch/version.txt"
        grab_lim 256 "$_h/network/admin/listener.ora" "$_h/network/admin/tnsnames.ora"
        grab_lim 128 "$_h"/inventory/oneoffs/*/etc/config/inventory.xml
    done <"$W/scan/oracle_homes.lst"
    capt 60 oracle_ls oracle_ls
}

section_misc() {
    log "cron/comptes/sécurité/noyau/oracle"
    grab /etc/crontab /etc/anacrontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* \
         /etc/passwd /etc/group /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/selinux/config \
         /proc/modules /proc/sys/kernel/tainted /etc/oratab /etc/oraInst.loc
    cap cron_dirs sh -c 'ls -l /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null'
    cap who who
    cap sshd_T sshd -T
    cap iptables iptables-save
    cap ip6tables ip6tables-save
    cap sestatus sestatus
    cap sysctl sysctl -a
    cap boot ls -l /boot
    section_oracle
    section_modules
    cap software_dirs sh -c 'for d in /opt /usr/local /srv /app /apps /applis /data /u01 /u02 /home /var/www /usr/share/java; do
        [ -d "$d" ] || continue; echo "== $d"; ls -1A "$d" 2>/dev/null | head -500
        for s in "$d"/*; do [ -d "$s" ] && [ ! -h "$s" ] && echo "-- $s: $(ls -1A "$s" 2>/dev/null | head -200 | tr "\n" " ")"; done
    done'
}

# ---------------------------------------------------------------------------
# Parcours du système de fichiers
# ---------------------------------------------------------------------------
local_mounts() {
    # Tests uniquement : parcours limité à un répertoire
    if [ -n "$CMDB_TEST_SCAN_ROOT" ]; then echo "$CMDB_TEST_SCAN_ROOT"; return; fi
    if [ ! -r /proc/mounts ]; then
        # AIX : "mount" ; lignes locales = première colonne /dev/... (pas de nœud distant)
        mount 2>/dev/null | awk '$1 ~ /^\/dev\// && ($3 == "jfs2" || $3 == "jfs") {print $2}' | sort -u
        return
    fi
    awk '$3 !~ /^(proc|sysfs|devtmpfs|devpts|tmpfs|cgroup|cgroup2|securityfs|pstore|bpf|debugfs|tracefs|configfs|fusectl|mqueue|hugetlbfs|autofs|rpc_pipefs|nfsd|binfmt_misc|selinuxfs|efivarfs|nsfs|ramfs|usbfs|squashfs|iso9660|udf|overlay|aufs|nfs|nfs4|cifs|smbfs|smb3|ncpfs|ceph|glusterfs|9p|gpfs|lustre|afs|davfs|ocfs2|gfs|gfs2|rootfs|fuse|fuse\..*)$/ {print $2}' /proc/mounts 2>/dev/null | sort -u
}

# find portable (AIX et vieux find sans -path) : exclusions et filtres faits par classify()
# Fichiers pouvant contenir une chaîne de connexion (voir grab_dbcfg)
DBCFG_FIND="-o -name *.properties -o -name .env -o -name *.env -o -name .env.* -o -name application*.yml \
 -o -name application*.yaml -o -name bootstrap*.yml -o -name bootstrap*.yaml -o -name *-jdbc.xml -o -name *datasource*.xml \
 -o -name *datasource*.yml -o -name *datasource*.yaml -o -name appsettings*.json -o -name context.xml -o -name server.xml \
 -o -name standalone*.xml -o -name domain.xml -o -name hibernate.cfg.xml -o -name persistence.xml -o -name resources.xml \
 -o -name tnsnames.ora -o -name pgbouncer.ini -o -name pgpool.conf -o -name pg_service.conf -o -name .pg_service.conf \
 -o -name odbc.ini -o -name .odbc.ini -o -name my.cnf -o -name .my.cnf -o -name wp-config.php -o -name config.php \
 -o -name configuration.php -o -name config.inc.php -o -name settings.php -o -name settings.py -o -name local_settings.py \
 -o -name database.yml -o -name database.yaml -o -name database.php -o -name db.php -o -name parameters.yml \
 -o -name parameters.yaml -o -name web.config"

# Fichiers de configuration dont seules les directives de chargement de modules sont copiées
MOD_FIND="-o -name httpd.conf -o -name apache2.conf -o -name nginx.conf -o -name php.ini -o -name postgresql.conf \
 -o -name postgresql.auto.conf -o -name redis.conf -o -name mysqld.cnf -o -name mariadb.cnf -o -name server.cnf -o -name haproxy.cfg \
 -o -name ports.conf -o -name httpd-vhosts.conf -o -name httpd-ssl.conf -o -name vhosts.conf"
# Clés et certificats (voir crypto_one)
CRYPTO_FIND="-o -name *.key -o -name *.pem -o -name *.crt -o -name *.cer -o -name *.der -o -name *.p12 -o -name *.pfx \
 -o -name *.jks -o -name *.keystore -o -name *.jceks -o -name *.bcfks -o -name *.kdb -o -name *.sth -o -name *.p7b \
 -o -name *.p8 -o -name *.pk8 -o -name *.ppk -o -name *.truststore -o -name *.sso -o -name id_rsa -o -name id_dsa \
 -o -name id_ecdsa -o -name id_ed25519 -o -name keystore -o -name truststore -o -name secring.gpg -o -name ssh_host_*_key"

# grab_mod FICHIER... : seules les directives de chargement sont copiées (pas de secret dans ces lignes)
grab_mod() {
    for _f in "$@"; do
        [ -f "$_f" ] && [ -r "$_f" ] || continue
        _d="$W/fs${_f%/*}"
        if [ "$_d" != "$_lastdir" ]; then mkdir -p "$_d" 2>/dev/null; _lastdir=$_d; fi
        dd if="$_f" bs=1024 count=1024 2>/dev/null | grep -iE \
            '^[ 	]*(LoadModule|load_module|extension|zend_extension|shared_preload_libraries|loadmodule|plugin[-_]load|</?VirtualHost|ServerName|ServerAlias|DocumentRoot|Listen|ProxyPass|SSLEngine|SSLCertificateFile|server[ 	]|server\{|server_name|root[ 	]|proxy_pass|ssl_certificate[ 	]|upstream[ 	]|location[ 	]|frontend[ 	]|backend[ 	]|bind[ 	])' >>"$W/fs$_f"
    done
}
# Les répertoires de modules activés sont faits de liens symboliques, invisibles de "find -type f"
section_modules() {
    log "modules"
    grab_mod /etc/apache2/mods-enabled/*.load /etc/httpd/conf.modules.d/*.conf /etc/nginx/modules-enabled/*.conf \
        /etc/php.d/*.ini /etc/php/*/*/conf.d/*.ini /etc/php/conf.d/*.ini \
        /etc/apache2/sites-enabled/* /etc/apache2/vhosts.d/*.conf /etc/httpd/conf.d/*.conf /etc/httpd/vhosts.d/*.conf \
        /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /opt/IBM/HTTPServer/conf/*.conf /usr/IBM/HTTPServer/conf/*.conf
}

# crypto_one FICHIER NUMERO : ce fichier est toujours mentionné. Seuls sortent les certificats
# (publics) ; une clé privée n'est ni copiée ni décodée, on n'en lit que l'en-tête.
crypto_one() {
    _f=$1; _n=$2; _fl=""
    _ls=$(ls -ld "$_f" 2>/dev/null)
    if [ ! -r "$_f" ]; then printf '%s\t%s\t%s\n' "$_f" "unreadable" "$_ls" >>"$W/scan/crypto.tsv"; return; fi
    _m=$(dd if="$_f" bs=1 count=4 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    case "$_m" in
        feedfeed|cececece)
            case "$_m" in feedfeed) _fl=jks ;; *) _fl=jceks ;; esac
            if have keytool; then
                tmo 10 keytool -list -v -keystore "$_f" 2>/dev/null \
                    | grep -E '^(Alias name|Entry type|Owner|Issuer|Serial number|Valid from)' >"$W/scan/crypto/$_n.keytool"
            fi ;;
        *)
            if grep -- '-----BEGIN ' "$_f" >/dev/null 2>&1; then
                _fl=pem
                _k=$(grep -- '-----BEGIN .*PRIVATE KEY-----' "$_f" | head -1 | sed 's/^-----BEGIN //; s/ *PRIVATE KEY-----.*//')
                if grep -- '-----BEGIN .*PRIVATE KEY-----' "$_f" >/dev/null 2>&1; then
                    _fl="pem,key=${_k:-PKCS8}"
                    grep -- 'ENCRYPTED' "$_f" >/dev/null 2>&1 && _fl="$_fl,encrypted"
                fi
                awk '/-----BEGIN (TRUSTED |X509 )?CERTIFICATE-----/ {p=1} p {print} /-----END (TRUSTED |X509 )?CERTIFICATE-----/ {p=0}' \
                    "$_f" >"$W/scan/crypto/$_n.pem" 2>/dev/null
            else
                case "$_f" in
                    *.p12|*.pfx)
                        _fl=pkcs12
                        if have openssl; then
                            tmo 10 openssl pkcs12 -in "$_f" -nokeys -passin pass: 2>/dev/null >"$W/scan/crypto/$_n.pem"
                            [ -s "$W/scan/crypto/$_n.pem" ] || tmo 10 openssl pkcs12 -in "$_f" -nokeys -passin pass: -legacy 2>/dev/null >"$W/scan/crypto/$_n.pem"
                            if [ -s "$W/scan/crypto/$_n.pem" ]; then _fl="$_fl,emptypw"; else _fl="$_fl,encrypted"; fi
                        fi ;;
                    *.der|*.cer|*.crt)
                        if have openssl; then
                            tmo 10 openssl x509 -inform DER -in "$_f" -outform PEM 2>/dev/null >"$W/scan/crypto/$_n.pem" && _fl=der
                        fi ;;
                    *.kdb) _fl=gskit-kdb ;;
                    *.sth) _fl=gskit-stash ;;
                    *.sso) _fl=oracle-wallet ;;
                esac
            fi ;;
    esac
    printf '%s\t%s\t%s\n' "$_f" "$_fl" "$_ls" >>"$W/scan/crypto.tsv"
}
section_crypto() {
    [ -s "$W/scan/crypto.lst" ] || return 0
    log "clés et certificats"
    mkdir "$W/scan/crypto" 2>/dev/null
    _i=0
    while IFS= read -r _c && [ "$_i" -lt 2000 ]; do
        _i=$((_i + 1)); crypto_one "$_c" "$_i"
    done <"$W/scan/crypto.lst"
}

# dbcfg_skip CHEMIN : mêmes exclusions que DB_CONFIG_SKIP_RX du collecteur Python
dbcfg_skip() {
    case "$1" in
        */sample/*|*/samples/*|*/example/*|*/examples/*|*/demo/*|*/demos/*|*/doc/*|*/docs/*|*/test/*|*/tests/*|*/testdata/*) return 0 ;;
        */fixtures/*|*/node_modules/*|*/site-packages/*|*/dist-packages/*|*/vendor/*|*/i18n/*|*/locale/*|*/locales/*) return 0 ;;
        /usr/share/*|/usr/lib/*|/usr/lib64/*|*/product/[0-9]*) return 0 ;;
    esac
    return 1
}

# grab_dbcfg FICHIER : copie EXPURGÉE sous fs/<chemin d'origine>. Les secrets ne quittent pas
# le serveur : seules passent les URL de bases sans identifiants ni paramètres, et les lignes
# hôte/port/base/moteur, une fois retiré tout ce qui ressemble à un mot de passe.
grab_dbcfg() {
    [ -f "$1" ] && [ -r "$1" ] || return 0
    _d="$W/fs${1%/*}"
    if [ "$_d" != "$_lastdir" ]; then mkdir -p "$_d" 2>/dev/null; _lastdir=$_d; fi
    dd if="$1" bs=1024 count=256 2>/dev/null | awk '
    BEGIN {
        Q = sprintf("%c", 39)
        RXU = "[A-Za-z][A-Za-z0-9+:_-]*://[^ \t\"<>`" Q "]*"
        RXO = "[Jj][Dd][Bb][Cc]:[Oo][Rr][Aa][Cc][Ll][Ee]:[A-Za-z0-9]*:[^ \t\"<>`" Q "]*"
        RXS = "[Pp][Aa][Ss][Ss][A-Za-z_]*[\"" Q "]?[ \t]*(=>|=|:|,)[ \t]*[^ \t;,)]*"
        RXW = "[Pp][Ww][Dd][A-Za-z_]*[\"" Q "]?[ \t]*(=>|=|:|,)[ \t]*[^ \t;,)]*"
    }
    {
        l = substr($0, 1, 2000); lo = tolower(l); done = 0
        if (index(lo, "(description") == 0) {
            r = l
            while (match(r, RXO)) {
                t = substr(r, RSTART, RLENGTH); r = substr(r, RSTART + RLENGTH); done = 1
                n = split(t, a, "@")
                if (n > 1) print "jdbc:oracle:thin:@" a[n]
            }
        }
        r = l
        while (match(r, RXU)) {
            t = substr(r, RSTART, RLENGTH); r = substr(r, RSTART + RLENGTH)
            if (tolower(t) !~ /^(jdbc:|postgres|pgsql|mysql|maria|mongodb|redis|oracle|mssql|sqlserver|db2)/) continue
            done = 1
            sub(/[?#].*/, "", t)
            k = index(t, "://"); n = split(substr(t, k + 3), a, "@")
            if (n > 1) t = substr(t, 1, k + 2) a[n]
            keep = ""
            if (match(t, /;[Dd][Aa][Tt][Aa][Bb][Aa][Ss][Ee]([Nn][Aa][Mm][Ee])?=[^;]*/)) keep = substr(t, RSTART, RLENGTH)
            sub(/;.*/, "", t)
            print t keep
        }
        if (done) next
        sub(/thin:[^@ ]*@/, "thin:@", l)
        gsub(RXS, "", l); gsub(RXW, "", l)
        lo = tolower(l)
        if (lo ~ /pass|pwd|secret|token|credential|private/) next
        if (lo ~ /^[ \t]*\[/ || l ~ /^[^ \t].*:[ \t]*$/ ||
            lo ~ /host|server|port|dbname|database|db_|sid|service|adapter|engine|driver|connection|description|plugin|<connector|<context|<alias|appbase|protocol|sslenabled|socket-binding/ || lo ~ /^[ \t]*\/?>[ \t]*$/) print substr(l, 1, 400)
    }' >"$W/fs$1" 2>/dev/null
}

do_find_simple() {
    set -f
    for _m in $(local_mounts); do
        find "$_m" -xdev \( -name .git -o -name .svn -o -name .hg -o -name .m2 -o -name .gradle -o -name .ivy2 \
            -o -name .npm -o -name .cache -o -name __pycache__ -o -name lost+found \) -prune -o -type f \( \
            -name '*.jar' -o -name '*.war' -o -name '*.ear' -o -name '*.hpi' -o -name '*.jpi' \
            -o -name release -o -name METADATA -o -name PKG-INFO -o -name '*.egg-info' -o -name pyvenv.cfg \
            -o -name package.json -o -name package-lock.json -o -name installed.json -o -name composer.lock \
            -o -name '*.gemspec' -o -name '*.deps.json' -o -name PG_VERSION -o -name mysql_upgrade_info \
            -o -name pom.properties -o -name version.php -o -name Version.php -o -name Config.php -o -name Drupal.php \
            -o -name bootstrap.inc -o -name define.php -o -name Defines.php -o -name DefaultSettings.php \
            -o -name iniset.php -o -name filefunc.inc.php -o -name inc_version.php -o -name CodeIgniter.php \
            -o -name Smarty.class.php -o -name class.phpmailer.php -o -name PHPMailer.php \
            -o -name version-manifest.txt -o -name version.txt -o -name comps.xml \
            -o -name WAS.product -o -name IHS.product -o -name PLG.product -o -name WCT.product -o -name ND.product \
            -o -name BASE.product -o -name WXS.product -o -name JDK.product \
            -o -name 'jquery*.js' -o -name 'angular*.js' -o -name 'bootstrap*.js' -o -name 'moment*.js' \
            -o -name 'lodash*.js' -o -name 'underscore*.js' -o -name 'vue*.js' -o -name 'react*.js' \
            -o -name 'handlebars*.js' -o -name 'knockout*.js' -o -name 'backbone*.js' -o -name 'ckeditor*.js' \
            -o -name 'tinymce*.js' -o -name 'prototype*.js' -o -name 'mootools*.js' -o -name 'dojo*.js' \
            -o -name 'select2*.js' -o -name 'purify*.js' -o -name 'swfobject*.js' -o -name 'highcharts*.js' \
            -o -name 'lib*.so*' -o -name 'libssl*.a' -o -name 'libcrypto*.a' \
            -o -name java -o -name 'python*' -o -name 'php*' -o -name node -o -name nodejs -o -name 'ruby*' \
            -o -name perl -o -name postgres -o -name postmaster -o -name psql -o -name mysqld -o -name mariadbd \
            -o -name mysql -o -name mongod -o -name redis-server -o -name nginx -o -name httpd -o -name apache2 \
            -o -name haproxy -o -name openssl -o -name curl -o -name 'zabbix_agent*' -o -name db2ls -o -name dspmqver \
            $DBCFG_FIND $MOD_FIND $CRYPTO_FIND \) -print 2>/dev/null
    done
    set +f
}

do_find() {
    if [ "$FIND_PATH" != 1 ]; then do_find_simple; return; fi
    set -f
    for _m in $(local_mounts); do
        find "$_m" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \
            -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/lxc \
            -o -path /var/cache/yum -o -path /var/cache/apt -o -path /usr/share/doc -o -path /usr/share/man \
            -o -path /usr/share/locale -o -path /usr/share/zoneinfo -o -path /usr/share/icons -o -path /usr/share/fonts \
            -o -path /usr/src -o -path /usr/include -o -path /var/lib/rpm -o -path /var/lib/dpkg \
            -o -path /var/lib/apt/lists -o -path /lost+found \
            -o -name .git -o -name .svn -o -name .hg -o -name .m2 -o -name .gradle -o -name .ivy2 -o -name .npm \
            -o -name .cache -o -name __pycache__ $EXTRA_PRUNE \) -prune -o -type f \( \
            -name '*.jar' -o -name '*.war' -o -name '*.ear' -o -name '*.hpi' -o -name '*.jpi' \
            -o -name release -o -name METADATA -o -name PKG-INFO -o -name '*.egg-info' -o -name pyvenv.cfg \
            -o -name package.json -o -name package-lock.json -o -name installed.json -o -name composer.lock \
            -o -name '*.gemspec' -o -name '*.deps.json' -o -name PG_VERSION -o -name mysql_upgrade_info \
            -o -name pom.properties -o -path '*/conda-meta/*.json' \
            -o -name version.php -o -name Version.php -o -name Config.php -o -name Drupal.php -o -name bootstrap.inc \
            -o -name define.php -o -name Defines.php -o -name DefaultSettings.php -o -name iniset.php \
            -o -name filefunc.inc.php -o -name inc_version.php -o -name CodeIgniter.php -o -name Smarty.class.php \
            -o -name class.phpmailer.php -o -name PHPMailer.php -o -name version-manifest.txt -o -name version.txt \
            -o -name comps.xml -o -name WAS.product -o -name IHS.product -o -name PLG.product -o -name WCT.product \
            -o -name ND.product -o -name BASE.product -o -name WXS.product -o -name JDK.product \
            -o -name 'jquery*.js' -o -name 'angular*.js' -o -name 'bootstrap*.js' -o -name 'moment*.js' \
            -o -name 'lodash*.js' -o -name 'underscore*.js' -o -name 'vue*.js' -o -name 'react*.js' \
            -o -name 'handlebars*.js' -o -name 'knockout*.js' -o -name 'backbone*.js' -o -name 'ckeditor*.js' \
            -o -name 'tinymce*.js' -o -name 'prototype*.js' -o -name 'mootools*.js' -o -name 'dojo*.js' \
            -o -name 'select2*.js' -o -name 'purify*.js' -o -name 'swfobject*.js' -o -name 'highcharts*.js' \
            -o \( -name 'lib*.so*' ! -path '/lib/*' ! -path '/lib64/*' ! -path '/usr/lib/*' ! -path '/usr/lib64/*' \) \
            -o \( -path '*bin/*' \( -name java -o -name 'python*' -o -name 'php*' -o -name node -o -name nodejs \
                -o -name 'ruby*' -o -name perl -o -name postgres -o -name postmaster -o -name psql -o -name mysqld \
                -o -name mariadbd -o -name mysql -o -name mongod -o -name redis-server -o -name nginx -o -name httpd \
                -o -name apache2 -o -name haproxy -o -name openssl -o -name curl -o -name 'zabbix_agent*' \
                -o -name db2ls -o -name dspmqver \) \) \
            $DBCFG_FIND $MOD_FIND $CRYPTO_FIND \) -print 2>/dev/null
    done
    set +f
}

# Tri des fichiers trouvés : copies tronquées, listes d'archives / binaires / bibliothèques
classify() {
    while IFS= read -r f; do
        b=${f##*/}; d=${f%/*}; db=${d##*/}; pd=${d%/*}; pdb=${pd##*/}
        if [ "$FIND_PATH" != 1 ]; then
            excluded "$f" && continue
            case "$f" in /usr/share/doc/*|/usr/share/man/*|/usr/share/locale/*|/usr/src/*|/usr/include/*) continue ;; esac
        fi
        case "$b" in
            *.jar|*.war|*.ear|*.hpi|*.jpi) printf '%s\n' "$f" >>"$W/scan/archives.lst"; continue ;;
            release) [ -f "$d/bin/java" ] && grab_lim 64 "$f"; continue ;;
            METADATA|PKG-INFO) case "$db" in *.dist-info|*.egg-info) grab_lim 64 "$f" ;; esac; continue ;;
            package.json)
                case "$f" in
                    */node_modules/*)
                        if [ "$pdb" = node_modules ]; then grab_lim 64 "$f"
                        else case "$pdb" in @*) [ "${pd%/*}" != "$pd" ] && [ "$(basename "${pd%/*}")" = node_modules ] && grab_lim 64 "$f" ;; esac
                        fi ;;
                    *) grab_lim 256 "$f" ;;
                esac
                continue ;;
            PG_VERSION) [ -d "$d/global" ] && grab_lim 1 "$f"; continue ;;
            comps.xml) grab_lim 16384 "$f"; continue ;;
            httpd.conf|apache2.conf|nginx.conf|php.ini|postgresql.conf|postgresql.auto.conf|redis.conf|mysqld.cnf|mariadb.cnf|server.cnf|\
            haproxy.cfg|ports.conf|httpd-vhosts.conf|httpd-ssl.conf|vhosts.conf)
                grab_mod "$f"; continue ;;
            *.key|*.pem|*.crt|*.cer|*.der|*.p12|*.pfx|*.jks|*.keystore|*.jceks|*.bcfks|*.kdb|*.sth|*.p7b|*.p8|*.pk8|*.ppk|\
            *.truststore|*.sso|id_rsa|id_dsa|id_ecdsa|id_ed25519|keystore|truststore|secring.gpg|ssh_host_*_key)
                case "$f" in
                    /etc/ssl/certs/*|/etc/pki/ca-trust/*|/etc/pki/tls/certs/ca-*|/etc/ca-certificates/*|/usr/share/ca-certificates/*|\
                    /usr/share/pki/*|/usr/share/doc/*|*/certifi/*|/usr/lib/ssl/certs/*) ;;
                    *) printf '%s\n' "$f" >>"$W/scan/crypto.lst" ;;
                esac
                continue ;;
            pom.properties) grab "$f"; continue ;;
            tnsnames.ora) case "$f" in */samples/*) ;; *) grab_lim 256 "$f" ;; esac; continue ;;
            *.properties|.env|*.env|.env.*|application*.y*ml|bootstrap*.y*ml|*-jdbc.xml|*datasource*.xml|*datasource*.y*ml|\
            appsettings*.json|context.xml|server.xml|standalone*.xml|domain.xml|hibernate.cfg.xml|persistence.xml|\
            resources.xml|pgbouncer.ini|pgpool.conf|pg_service.conf|.pg_service.conf|odbc.ini|.odbc.ini|my.cnf|.my.cnf|\
            wp-config.php|config.php|configuration.php|config.inc.php|settings.php|settings.py|local_settings.py|\
            database.yml|database.yaml|database.php|db.php|parameters.yml|parameters.yaml|web.config)
                dbcfg_skip "$f" || grab_dbcfg "$f"; continue ;;
            *.js) case "$f" in */node_modules/*) ;; *) grab_lim 1 "$f" ;; esac; continue ;;
            lib*.so*|libssl*.a|libcrypto*.a)
                case "$f" in /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) [ "$FIND_PATH" = 1 ] || continue ;; esac
                _v=""
                case "$b" in
                    libssl*|libcrypto*) _v=$(bin_match "$f" 'OpenSSL [0-9]\.[0-9]*\.[0-9]*[a-z]* *[0-9]* [A-Z][a-z][a-z] [0-9][0-9][0-9][0-9]') ;;
                    libphp*) _v=$(bin_match "$f" 'X-Powered-By: PHP/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*') ;;
                esac
                printf '%s\t%s\n' "$f" "$_v" >>"$W/scan/native_libs.lst"
                continue ;;
        esac
        case "$f" in
            */bin/*|*/sbin/*) [ -x "$f" ] && printf '%s\n' "$f" >>"$W/scan/candidates.lst"; continue ;;
        esac
        pname "$b"; [ -n "$PN" ] && continue      # binaire homonyme hors bin/ : ignoré
        grab "$f"
    done
}

section_filesystem() {
    # find sait-il filtrer par chemin (-path) ? (absent de certains find, dont AIX selon la version)
    if find "$W" -path "$W" -print 2>/dev/null | grep . >/dev/null 2>&1 && [ -z "$CMDB_FORCE_SIMPLE_FIND" ]; then
        FIND_PATH=1; else FIND_PATH=0; fi
    log "filesystem (budget ${SCAN_MAX}s, find -path : $FIND_PATH)"
    : >"$W/scan/archives.lst"; : >"$W/scan/native_libs.lst"; : >"$W/scan/candidates.lst"
    tmo "$SCAN_MAX" do_find >"$W/scan/found.lst" 2>/dev/null
    echo $? >"$W/scan/find.rc"
    log "find terminé : $(wc -l <"$W/scan/found.lst") fichiers"
    classify <"$W/scan/found.lst"
    section_crypto
}

# ---------------------------------------------------------------------------
# Ce que révèlent les processus en mémoire, même hors du parcours disque
# (montage réseau, répertoire exclu, budget dépassé, binaire supprimé, nom
# de binaire inconnu) : JVM chargées, archives ouvertes, empreintes statiques.
# ---------------------------------------------------------------------------

# fp_file FICHIER_A_LIRE CHEMIN_AFFICHE RAISON : chaînes de version compilées dans
# un binaire (lecture seule, rien n'est exécuté)
fp_file() {
    [ -f "$1" ] && [ -r "$1" ] || return 0
    for _pat in 'httpd|Apache/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' \
                'nginx|nginx/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' \
                'php|X-Powered-By: PHP/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' \
                'lighttpd|lighttpd/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' \
                'openssl|OpenSSL [0-9]\.[0-9]*\.[0-9]*[a-z]* *[0-9]* [A-Z][a-z][a-z] [0-9][0-9][0-9][0-9]' \
                'curl|libcurl/[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*'; do
        _v=$(bin_match "$1" "${_pat#*|}")
        [ -n "$_v" ] && printf '%s\t%s\t%s\t%s\n' "$2" "$3" "${_pat%%|*}" "$_v" >>"$W/scan/fingerprints.lst"
    done
}

section_process_artifacts() {
    log "artefacts des processus"
    _po="$W/cmd/procs.out"
    [ -f "$_po" ] || return 0
    touch "$W/scan/archives.lst" "$W/scan/fingerprints.lst"
    # JVM chargées (hors conteneurs) : fichier release du répertoire de la JVM, rt.jar (Java <= 8)
    awk '/^@@PID /{c=0} /^cg /{c=1} /^lib .*\/libjvm\.so$/ && !c {
            p=$2; if (sub(/\/lib\/([^\/]+\/)?(server|client|j9vm|default|minimal)\/libjvm\.so$/, "", p)) print p }' "$_po" \
        | sort -u >"$W/scan/jvm_homes.lst"
    while IFS= read -r _h; do
        grab_lim 64 "$_h/release"
        case "$_h" in */jre) grab_lim 64 "${_h%/jre}/release" ;; esac
        for _rt in "$_h/lib/rt.jar" "$_h/jre/lib/rt.jar"; do [ -f "$_rt" ] && printf '%s\n' "$_rt" >>"$W/scan/proc_archives.lst"; done
    done <"$W/scan/jvm_homes.lst"
    # Archives Java ouvertes par des processus (hors conteneurs : chemins de l'hôte)
    awk '/^@@PID /{c=0} /^cg /{c=1} /^fd / && !c { sub(/^fd /, ""); if ($0 !~ /^socket:/) print }' "$_po" \
        >>"$W/scan/proc_archives.lst"
    # Ligne de commande : seule information lisible sur les processus des AUTRES comptes
    # quand on n'est pas root (exe, maps, fd et environ sont alors refusés).
    : >"$W/scan/cmd_firsts.lst"
    set -f
    awk '/^@@PID /{c=0} /^cg /{c=1} /^cmd / && !c {sub(/^cmd /, ""); print}' "$_po" | while IFS= read -r _cl; do
        _first=""
        for _t in $(printf '%s\n' "$_cl" | tr ' :=,;"' '\n\n\n\n\n\n' | grep '^/'); do
            [ -n "$_first" ] || _first=$_t
            case "$_t" in
                *.jar|*.war|*.ear) [ -f "$_t" ] && [ -r "$_t" ] && printf '%s\n' "$_t" >>"$W/scan/proc_archives.lst" ;;
                */\*) set +f
                      for _j in "${_t%/\*}"/*.jar "${_t%/\*}"/*.war; do [ -f "$_j" ] && printf '%s\n' "$_j" >>"$W/scan/proc_archives.lst"; done
                      set -f ;;
            esac
        done
        [ -n "$_first" ] && printf '%s\n' "$_first" >>"$W/scan/cmd_firsts.lst"
        for _w in $_cl; do
            case "$_w" in
                -Dcatalina.home=/*|-Dcatalina.base=/*)
                    for _j in "${_w#*=}/lib/catalina.jar" "${_w#*=}/bin/bootstrap.jar"; do
                        [ -f "$_j" ] && printf '%s\n' "$_j" >>"$W/scan/proc_archives.lst"; done ;;
                -Djboss.home.dir=/*) [ -f "${_w#*=}/jboss-modules.jar" ] && printf '%s\n' "${_w#*=}/jboss-modules.jar" >>"$W/scan/proc_archives.lst" ;;
                -Djava.home=/*) printf '%s/bin/java\n' "${_w#*=}" >>"$W/scan/cmd_firsts.lst" ;;
            esac
        done
    done
    set +f
    sort -u "$W/scan/cmd_firsts.lst" | while IFS= read -r _f; do
        case "$_f" in
            */bin/*)   # .../bin/java, lanceur renommé... : JVM si release ou rt.jar
                _h=${_f%/bin/*}
                grep -q JAVA_VERSION "$_h/release" 2>/dev/null && grab_lim 64 "$_h/release"
                for _rt in "$_h/lib/rt.jar" "$_h/jre/lib/rt.jar"; do [ -f "$_rt" ] && printf '%s\n' "$_rt" >>"$W/scan/proc_archives.lst"; done ;;
        esac
        [ -f "$_f" ] && [ -r "$_f" ] && fp_file "$_f" "$_f" process_cmdline
    done
    sort -u "$W/scan/proc_archives.lst" -o "$W/scan/proc_archives.lst" 2>/dev/null
    sort -u "$W/scan/archives.lst" "$W/scan/proc_archives.lst" >"$W/scan/archives.tmp" && mv "$W/scan/archives.tmp" "$W/scan/archives.lst"
    # Empreintes : exécutables des processus (via /proc/PID/exe : fonctionne aussi pour un
    # binaire supprimé ou un conteneur) et bibliothèques PHP/OpenSSL/curl chargées hors système
    awk '/^@@PID /{pid=$2; c=0} /^cg /{c=1} /^exe /{sub(/^exe /, ""); if ($0 != "") print pid "\t" c "\t" $0}' "$_po" \
        | sort -t "$(printf '\t')" -k3,3 -u >"$W/scan/proc_exes.lst"
    while IFS="$(printf '\t')" read -r _pid _c _exe; do
        case "$_exe" in *" (deleted)") _r=process_exe_deleted ;; *) [ "$_c" = 1 ] && _r=process_exe_container || _r=process_exe ;; esac
        fp_file "/proc/$_pid/exe" "$_exe" "$_r"
    done <"$W/scan/proc_exes.lst"
    awk '/^@@PID /{c=0} /^cg /{c=1} /^lib / && !c {print $2}' "$_po" | sort -u | while IFS= read -r _l; do
        case "$_l" in /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) continue ;; esac
        case "${_l##*/}" in libphp*.so*|mod_php*.so*|libssl*.so*|libcrypto*.so*|libcurl*.so*) fp_file "$_l" "$_l" mapped_lib ;; esac
    done
}

# ---------------------------------------------------------------------------
# AIX : commandes natives lisibles sans privilège
# ---------------------------------------------------------------------------
aix_dev_attrs() {   # lsattr de chaque carte réseau, interface, disque et HBA
    lsdev -C -F name 2>/dev/null | grep -E '^(ent|en|et|hdisk|fcs|fscsi|vscsi|sys0|mem0|proc)[0-9]*$' | while IFS= read -r _dv; do
        printf '@@DEV %s\n' "$_dv"
        lsattr -El "$_dv" 2>/dev/null
    done
}

lslpp_owners() {   # index fichier -> fileset à partir de "lslpp -f"
    lslpp -f 2>/dev/null | awk '
        /^ +[A-Za-z0-9_.+-]+ +[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ *$/ { fs = $1; next }
        /^ +\// { if (fs != "") print $1 "\t" fs }' | grep -E "$OWN_RX"
}

proc_dump_ps() {   # processus via ps (AIX : pas de /proc texte)
    ps -e -o pid= -o ppid= -o uid= -o user= -o comm= -o args= 2>/dev/null | awk -v me="$$" '
        $1 != me { pid = $1; ppid = $2; uid = $3; comm = $5
          $1 = ""; $2 = ""; $3 = ""; $4 = ""; $5 = ""; sub(/^ +/, "")
          print "@@PID " pid; print "st PPid: " ppid; print "st Uid: " uid; print "st Name: " comm; print "cmd " $0 }'
}

section_aix() {
    log "aix : système, matériel, paquets, réseau, services"
    grab /etc/environment /etc/profile /etc/inittab /etc/resolv.conf /etc/hosts /etc/netsvc.conf /etc/security/login.cfg
    cap uname_s uname -s; cap uname_n uname -n; cap uname_r uname -r; cap uname_v uname -v; cap uname_m uname -m
    cap uname_p uname -p; cap uname_L uname -L; cap uname_a uname -a
    cap hostname hostname
    cap oslevel_s oslevel -s
    cap oslevel_r oslevel -r
    cap kernel_bitmode getconf KERNEL_BITMODE
    cap uptime uptime
    cap lparstat_i lparstat -i
    cap sys0 lsattr -El sys0
    capt 300 prtconf prtconf
    capt 120 instfix instfix -i
    capt 120 emgr emgr -lv3                  # correctifs provisoires : souvent réservé à root
    capt 120 lsdev_C lsdev -C -F 'name:class:subclass:type:status:location:description'
    capt 300 lscfg_vp lscfg -vp
    cap lspv lspv
    capt 300 dev_attrs aix_dev_attrs
    cap lsps lsps -a
    capt 60 df df -k
    cap mount mount
    capt 300 lslpp_Lcq lslpp -Lcq
    capt 600 owners_lslpp lslpp_owners
    if have rpm; then
        capt 300 rpm_qa rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{SOURCERPM}\t%{PACKAGER}\t\t\t%{SUMMARY}\n'
        capt 600 owners_rpm rpm_owners
    fi
    capt 300 procs proc_dump_ps
    cap ifconfig ifconfig -a
    cap netstat_in netstat -in
    cap netstat_rn netstat -rn
    capt 120 netstat_an netstat -an
    cap lssrc lssrc -a
    cap rc_dirs sh -c 'ls -l /etc/rc.d/rc2.d 2>/dev/null'
    cap no_a no -a
}

# ---------------------------------------------------------------------------
# Archives Java : Python (2.3 à 3.x) si présent, sinon unzip, sinon l'outil jar
# d'un JDK (lent : une JVM par archive, plafonné), sinon liste seule
# Format : A<TAB>chemin<TAB>taille<TAB>sha1 / m manifeste / p pom.properties /
#          c classe sentinelle / s ServerInfo / X erreur / E fin
# ---------------------------------------------------------------------------
JAR_PY='
import sys, zipfile, os
PY3 = sys.version_info[0] >= 3
if PY3:
    import io  # novermin (branche Python 3 uniquement)
    BIO = io.BytesIO
    def T(b):
        return b.decode("latin-1")
    def P(b):
        return b.decode("utf-8", "replace")
    _out = sys.stdout.buffer
    def w(t):
        _out.write(t.encode("utf-8", "replace"))
else:
    try:
        import cStringIO
        BIO = cStringIO.StringIO
    except ImportError:
        import StringIO
        BIO = StringIO.StringIO
    def T(b):
        return b
    P = T
    w = sys.stdout.write
try:
    import hashlib  # novermin (repli "sha" pour 2.3/2.4)
    def newsha():
        return hashlib.sha1()
except ImportError:
    import sha
    def newsha():
        return sha.new()
MARK = {}
for n in ("JndiLookup", "LoggerContext", "JMSAppender", "SocketServer", "Logger", "ScriptStringLookup",
          "SpringVersion", "SpringApplication", "Dispatcher", "Yaml", "ObjectMapper", "InvokerTransformer",
          "XStream", "SecurityUtils", "JSON", "Driver", "Catalina", "Server", "HttpObjectDecoder",
          "XmlRpcRequest", "AxisServer", "Service"):
    MARK[n + ".class"] = 1
HASH = sys.argv[2] == "1"
def clean(s):
    return s.replace("\t", " ").replace("\r", "").replace("\n", " ")
def inspect(z, disp, depth):
    try:
        names = z.namelist()
    except Exception:
        w("X\tnamelist\nE\n")
        return
    nm = 0
    for n in names:
        if n == "META-INF/MANIFEST.MF":
            try:
                for line in T(z.read(n)[:262144]).split("\n"):
                    w("m\t%s\n" % clean(line))
            except Exception:
                pass
        elif n[:15] == "META-INF/maven/" and n[-15:] == "/pom.properties":
            try:
                for line in T(z.read(n)[:65536]).split("\n"):
                    w("p\t%s\t%s\n" % (n, clean(line)))
            except Exception:
                pass
        elif n == "org/apache/catalina/util/ServerInfo.properties":
            try:
                for line in T(z.read(n)[:65536]).split("\n"):
                    w("s\t%s\n" % clean(line))
            except Exception:
                pass
        else:
            b = n[n.rfind("/") + 1:]
            if b in MARK and nm < 300:
                w("c\t%s\n" % n)
                nm = nm + 1
    w("E\n")
    if depth >= 3:
        return
    for n in names:
        l = n.lower()
        if l[-4:] not in (".jar", ".war", ".ear"):
            continue
        try:
            size = z.getinfo(n).file_size
        except Exception:
            continue
        sub = disp + "!/" + n
        if size > 104857600:
            w("A\t%s\t%d\t-\nX\ttoo_large\nE\n" % (sub, size))
            continue
        try:
            data = z.read(n)
            h = newsha()
            h.update(data)
            w("A\t%s\t%d\t%s\n" % (sub, len(data), h.hexdigest()))
            inspect(zipfile.ZipFile(BIO(data)), sub, depth + 1)
        except Exception:
            w("X\t%s\nE\n" % clean(str(sys.exc_info()[1]))[:200])
_lf = open(sys.argv[1], "rb")
_paths = _lf.read().split("\n".encode("ascii"))
_lf.close()
for path in _paths:
    if not path:
        continue
    try:
        size = os.path.getsize(path)
    except Exception:
        continue
    digest = "-"
    if HASH and size <= 268435456:
        try:
            h = newsha()
            f = open(path, "rb")
            while 1:
                b = f.read(1048576)
                if not b:
                    break
                h.update(b)
            f.close()
            digest = h.hexdigest()
        except Exception:
            pass
    w("A\t%s\t%d\t%s\n" % (P(path), size, digest))
    try:
        fo = open(path, "rb")
        z = zipfile.ZipFile(fo)
    except Exception:
        w("X\t%s\nE\n" % clean(str(sys.exc_info()[1]))[:200])
        continue
    inspect(z, P(path), 0)
    z.close()
    fo.close()
'

sha1_of() {
    if have sha1sum; then sha1sum "$1" 2>/dev/null | awk '{print $1}'
    elif have openssl; then openssl sha1 "$1" 2>/dev/null | sed 's/.*= *//'
    elif have csum; then csum -h SHA1 "$1" 2>/dev/null | awk '{print $1}'
    else echo -; fi
}

jars_unzip() {   # $1 = liste des archives (pas de stdin : tmo le redirige vers /dev/null)
    while IFS= read -r j; do
        _s=$(ls -ln "$j" 2>/dev/null | awk '{print $5}')
        _h=-; [ "$DO_HASH" = 1 ] && _h=$(sha1_of "$j")
        printf 'A\t%s\t%s\t%s\n' "$j" "$_s" "$_h"
        unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | dd bs=1024 count=256 2>/dev/null | tr -d '\r' | sed 's/^/m	/'
        _lst=$(unzip -l "$j" 2>/dev/null | awk 'NR>3 && NF>=4 {print $NF}')
        for _e in $(printf '%s\n' "$_lst" | grep '^META-INF/maven/.*/pom\.properties$'); do
            unzip -p "$j" "$_e" 2>/dev/null | tr -d '\r' | sed "s|^|p	$_e	|"
        done
        printf '%s\n' "$_lst" | grep -E '/(JndiLookup|JMSAppender|SocketServer|ScriptStringLookup|InvokerTransformer|SpringVersion|XStream|Catalina)\.class$' | head -300 | sed 's/^/c	/'
        case "$_lst" in
            *org/apache/catalina/util/ServerInfo.properties*)
                unzip -p "$j" org/apache/catalina/util/ServerInfo.properties 2>/dev/null | tr -d '\r' | sed 's/^/s	/' ;;
        esac
        echo E
        for _e in $(printf '%s\n' "$_lst" | grep -E '\.(jar|war|ear)$'); do
            printf 'A\t%s!/%s\t-\t-\nX\tnested_not_inspected_without_python\nE\n' "$j" "$_e"
        done
    done <"$1"
}

# jar d'un JDK (AIX : IBM Java) : extraction ciblée dans un répertoire temporaire.
# Une JVM par appel : limité à JAR_MAX archives, les suivantes sont seulement listées.
JAR_MAX=300
jars_jar() {   # $1 = liste, $2 = binaire jar
    _jn=0; _jx="$W/jx"
    while IFS= read -r j; do
        _jn=$((_jn + 1))
        _s=$(ls -ln "$j" 2>/dev/null | awk '{print $5}')
        _h=-; [ "$DO_HASH" = 1 ] && _h=$(sha1_of "$j")
        printf 'A\t%s\t%s\t%s\n' "$j" "$_s" "$_h"
        if [ "$_jn" -gt "$JAR_MAX" ]; then printf 'X\tjar_budget\nE\n'; continue; fi
        _lst=$("$2" tf "$j" 2>/dev/null)
        rm -rf "$_jx"; mkdir "$_jx"
        _ents=$(printf '%s\n' "$_lst" | grep -E '^META-INF/MANIFEST\.MF$|^META-INF/maven/.*/pom\.properties$|^org/apache/catalina/util/ServerInfo\.properties$')
        # shellcheck disable=SC2086
        [ -n "$_ents" ] && ( cd "$_jx" && "$2" xf "$j" $_ents ) >/dev/null 2>&1
        [ -f "$_jx/META-INF/MANIFEST.MF" ] && dd if="$_jx/META-INF/MANIFEST.MF" bs=1024 count=256 2>/dev/null | tr -d '\r' | sed 's/^/m	/'
        for _e in $(printf '%s\n' "$_ents" | grep 'pom\.properties$'); do
            [ -f "$_jx/$_e" ] && tr -d '\r' <"$_jx/$_e" | sed "s|^|p	$_e	|"
        done
        [ -f "$_jx/org/apache/catalina/util/ServerInfo.properties" ] && tr -d '\r' <"$_jx/org/apache/catalina/util/ServerInfo.properties" | sed 's/^/s	/'
        printf '%s\n' "$_lst" | grep -E '/(JndiLookup|JMSAppender|SocketServer|ScriptStringLookup|InvokerTransformer|SpringVersion|XStream|Catalina)\.class$' | head -300 | sed 's/^/c	/'
        echo E
        for _e in $(printf '%s\n' "$_lst" | grep -E '\.(jar|war|ear)$'); do
            printf 'A\t%s!/%s\t-\t-\nX\tnested_not_inspected_without_python\nE\n' "$j" "$_e"
        done
    done <"$1"
    rm -rf "$_jx"
}

jars_list_only() {
    while IFS= read -r j; do
        printf 'A\t%s\t%s\t%s\nX\tno_zip_tool\nE\n' "$j" "$(ls -ln "$j" 2>/dev/null | awk '{print $5}')" "$(sha1_of "$j")"
    done <"$1"
}

section_archives() {
    [ -f "$W/scan/archives.lst" ] || return 0
    _n=$(wc -l <"$W/scan/archives.lst" | tr -d ' ')
    log "archives java : $_n"
    [ "$_n" -gt 0 ] || return 0
    PYJ=""; _nounzip=""
    for _p in python3 python python2 python2.7 python2.6 python2.5 python2.4 python2.3 python3.12 python3.11 \
              python3.9 python3.8 python3.7 python3.6; do
        if have "$_p" && "$_p" -c 'import zipfile' 2>/dev/null; then PYJ=$_p; break; fi
    done
    _jarbin=""
    for _jb in /usr/java*/bin/jar /usr/lib/jvm/*/bin/jar /usr/java/*/bin/jar /opt/*/bin/jar; do
        [ -x "$_jb" ] && { _jarbin=$_jb; break; }
    done
    case "$CMDB_TEST_ARCHIVE_METHOD" in jar) PYJ=""; _nounzip=1 ;; esac   # tests uniquement
    if [ -n "$PYJ" ]; then
        echo "python:$PYJ" >"$W/scan/archives.method"
        capt 1800 archives "$PYJ" -c "$JAR_PY" "$W/scan/archives.lst" "$DO_HASH"
    elif have unzip && [ -z "$_nounzip" ]; then
        echo "unzip" >"$W/scan/archives.method"
        capt 1800 archives jars_unzip "$W/scan/archives.lst"
    elif [ -n "$_jarbin" ]; then
        echo "jar:$_jarbin" >"$W/scan/archives.method"
        # budget limité : d'abord les archives des processus, puis WAR/EAR, puis le reste, JDK en dernier
        { [ -f "$W/scan/proc_archives.lst" ] && cat "$W/scan/proc_archives.lst"
          grep -E '\.(war|ear)$' "$W/scan/archives.lst"
          grep -vE '\.(war|ear)$|/usr/lib/jvm/|/usr/java|/jre/lib/|/jdk[^/]*/lib/' "$W/scan/archives.lst"
          grep -E '/usr/lib/jvm/|/usr/java|/jre/lib/|/jdk[^/]*/lib/' "$W/scan/archives.lst"
        } | awk '!seen[$0]++' >"$W/scan/archives.prio"
        capt 1800 archives jars_jar "$W/scan/archives.prio" "$_jarbin"
    else
        echo "none" >"$W/scan/archives.method"
        capt 1800 archives jars_list_only "$W/scan/archives.lst"
    fi
}

# ---------------------------------------------------------------------------
# Sondes de version
# ---------------------------------------------------------------------------
pname() {   # positionne PN (pas de sous-shell : des milliers d'appels)
    PN=""
    case "$1" in
        java) PN=java ;;
        python|python[23]|python[23].[0-9]|python[23].[0-9][0-9]|platform-python) PN=python ;;
        php-fpm*|php[0-9]*-fpm) PN=php-fpm ;;
        php|php[0-9]|php[0-9].[0-9]|php[0-9][0-9]|php-cgi*) PN=php ;;
        node|nodejs) PN=node ;;
        ruby|ruby[0-9]*) PN=ruby ;;
        perl) PN=perl ;;
        postgres|postmaster) PN=postgresql ;;
        psql) PN=psql ;;
        mysqld|mariadbd) PN=mysqld ;;
        mysql) PN=mysql-client ;;
        mongod) PN=mongod ;;
        redis-server) PN=redis ;;
        memcached) PN=memcached ;;
        nginx) PN=nginx ;;
        httpd|apache2) PN=httpd ;;
        haproxy) PN=haproxy ;;
        squid) PN=squid ;;
        named) PN=bind ;;
        postconf) PN=postfix ;;
        smbd) PN=samba ;;
        ssh) PN=openssh-client ;;
        sshd) PN=openssh-server ;;
        openssl) PN=openssl ;;
        sudo) PN=sudo ;;
        bash) PN=bash ;;
        curl) PN=curl ;;
        wget) PN=wget ;;
        git) PN=git ;;
        rsync) PN=rsync ;;
        sqlite3) PN=sqlite ;;
        libc.so.6) PN=glibc ;;
        zabbix_agentd|zabbix_server|zabbix_proxy) PN=zabbix ;;
        slapd) PN=openldap ;;
        convert) PN=imagemagick ;;
        gs) PN=ghostscript ;;
        xz) PN=xz ;;
        pkexec) PN=polkit ;;
        db2ls) PN=db2 ;;
        dspmqver) PN=ibm-mq ;;
        *) PN="" ;;
    esac
}

probe_args() {   # une ligne par jeu d'arguments
    case "$1" in
        java) echo "-version" ;;
        python) echo "-V" ;;
        php) printf '%s\n' "-v" "-m" "-i" ;;
        php-fpm) printf '%s\n' "-v" "-i" ;;
        httpd) printf '%s\n' "-v" "-M" ;;
        haproxy|squid|bind|proftpd) echo "-v" ;;
        node) echo "--version" ;;
        perl) echo "-v" ;;
        postfix) echo "-h mail_version" ;;
        openssh-client|openssh-server|samba|zabbix|memcached) echo "-V" ;;
        openldap) echo "-VV" ;;
        openssl) echo "version -a" ;;
        sudo) echo "-V" ;;
        nginx) echo "-V" ;;
        imagemagick) echo "-version" ;;
        sqlite) echo "-version" ;;
        glibc|db2|ibm-mq) echo "" ;;
        *) echo "--version" ;;
    esac
}

# Fichier et tous ses répertoires parents à root, non modifiables par d'autres ?
trusted() {
    _f=$1
    set -- $(ls -ldn "$_f" 2>/dev/null)
    [ "$3" = 0 ] || return 1
    case "$1" in ?????w*|????????w*) return 1 ;; esac
    _d=${_f%/*}; [ -n "$_d" ] || _d=/
    while :; do
        set -- $(ls -ldn "$_d" 2>/dev/null)
        [ "$3" = 0 ] || return 1
        case "$1" in
            ?????????[tT]*) ;;
            ?????w*|????????w*) return 1 ;;
        esac
        [ "$_d" = / ] && return 0
        _d=${_d%/*}; [ -n "$_d" ] || _d=/
    done
}


realpath_of() {
    _r=$(readlink -f "$1" 2>/dev/null)
    [ -n "$_r" ] && echo "$_r" || echo "$1"
}

# php -i : l'environnement et les valeurs ressemblant à un secret ne quittent pas le serveur
# (même règle que phpinfo_filter du collecteur Python)
php_filter() {
    awk '
    $0 == "Environment" || $0 == "PHP Variables" { skip = 1; next }
    skip { if ($0 ~ /^[A-Z][A-Za-z ]*$/) skip = 0; else next }
    /^\$_/ { next }
    {
        i = index($0, "=>")
        if (i > 0 && tolower(substr($0, 1, i)) ~ /pass|secret|token|_key[^a-z_]/) { print substr($0, 1, i + 1) " ***"; next }
        l = $0
        gsub(/:\/\/[^\/@ ]*@/, "://***@", l)
        print l
    }'
}

section_probes() {
    log "sondes"
    _c="$W/scan/candidates.lst"
    touch "$_c"
    for _d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin /usr/libexec \
              /usr/lib/jvm/*/bin /usr/lib/jvm/*/jre/bin /usr/java/*/bin /usr/pgsql-*/bin /usr/lib/postgresql/*/bin \
              /opt/*/bin /opt/*/sbin /opt/*/*/bin /usr/local/*/bin /usr/local/*/sbin /opt/rh/*/root/usr/bin \
              /usr/java*/bin /usr/java*/jre/bin /opt/freeware/bin /usr/IBM/HTTPServer/bin /opt/IBM/HTTPServer/bin \
              /opt/IBM/db2/*/bin /usr/opt/db2*/bin /usr/mqm/bin /opt/mqm/bin /usr/local/bin; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            pname "${_f##*/}"; [ -n "$PN" ] && printf '%s\n' "$_f" >>"$_c"
        done
    done
    for _f in /lib/libc.so.6 /lib64/libc.so.6 /lib/*/libc.so.6; do [ -f "$_f" ] && printf '%s\n' "$_f" >>"$_c"; done
    for _p in /proc/[0-9]*; do
        _e=$(readlink "$_p/exe" 2>/dev/null)
        [ -n "$_e" ] || continue
        pname "${_e##*/}"; [ -n "$PN" ] && printf '%s\n' "$_e" >>"$_c"
    done
    # binaires des lignes de commande (seule source sans root, et la seule sous AIX)
    [ -f "$W/scan/cmd_firsts.lst" ] && while IFS= read -r _e; do
        pname "${_e##*/}"; [ -n "$PN" ] && [ -f "$_e" ] && printf '%s\n' "$_e" >>"$_c"
    done <"$W/scan/cmd_firsts.lst"
    _out="$W/scan/probes.txt"
    : >"$_out"
    [ "$DO_EXEC" = 1 ] || { echo "disabled" >"$W/scan/probes.disabled"; }
    _deadline=$(( $(now_epoch) + EXEC_MAX ))
    _seen=" "
    sort -u "$_c" | while IFS= read -r _f; do
        [ -f "$_f" ] || continue
        _rp=$(realpath_of "$_f")
        pname "${_rp##*/}"; [ -n "$PN" ] || pname "${_f##*/}"
        _name=$PN
        [ -n "$_name" ] || continue
        case "$_seen" in *" $_rp "*) printf '@@ALIAS\t%s\t%s\n' "$_rp" "$_f" >>"$_out"; continue ;; esac
        _seen="$_seen$_rp "
        _skip=""
        if [ "$DO_EXEC" != 1 ]; then _skip=disabled
        elif [ "$(now_epoch)" -gt "$_deadline" ]; then _skip=exec_budget
        elif ! is_bin "$_rp"; then _skip=not_executable_binary
        elif ! trusted "$_rp"; then _skip=untrusted_owner_or_perms
        fi
        printf '@@PROBE\t%s\t%s\t%s\t%s\n' "$_name" "$_rp" "$_f" "$_skip" >>"$_out"
        is_bin "$_rp" && fp_file "$_rp" "$_rp" probe
        [ -z "$_skip" ] || continue
        probe_args "$_name" | while IFS= read -r _a; do
            printf '@@ARGS\t%s\n' "$_a" >>"$_out"
            # shellcheck disable=SC2086
            if [ "$_a" = "-i" ]; then
                tmo "$EXEC_TIMEOUT" "$_rp" $_a 2>&1 | php_filter >>"$_out"
            else
                tmo "$EXEC_TIMEOUT" "$_rp" $_a >>"$_out" 2>&1
            fi
            printf '\n@@RC\t%s\n' "$?" >>"$_out"
        done
    done
}

# ---------------------------------------------------------------------------
if [ "$OS" = AIX ]; then
    section_aix
else
    section_os
    section_hw
    section_packages
    section_processes
    section_network
    section_services
fi
section_misc
[ "$DO_SCAN" = 1 ] && section_filesystem
section_process_artifacts
section_archives
section_probes

END_EPOCH=$(now_epoch)
{
    echo "collector_version=$VERSION"
    echo "started_at=$START"
    echo "finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "duration_seconds=$(( ${END_EPOCH:-0} - ${START_EPOCH:-0} ))"
    echo "host_label=$HOST_LABEL"
    echo "run_id=$RUN_ID"
    echo "os=$OS"
    for _t in $TAGS; do case "$_t" in *=*) echo "tag_$_t" ;; esac; done
    echo "uid=$(id -u)"
    echo "shell=$(readlink /proc/$$/exe 2>/dev/null)"
    echo "scan_max_seconds=$SCAN_MAX"
} >"$W/meta.txt"

# Archive + encodage base64 (premier outil disponible)
if have gzip; then
    ( cd "$W" && tar cf - . 2>/dev/null ) | gzip -c >"$W.tgz"
else
    ( cd "$W" && tar cf - . 2>/dev/null ) >"$W.tgz"      # AIX sans gzip : archive non compressée
fi
b64() {
    if have base64; then base64 "$1"
    elif have openssl; then openssl base64 -in "$1"
    elif have uuencode; then uuencode -m "$1" cmdb
    elif have perl; then perl -MMIME::Base64 -e 'local $/; open(F, "<", $ARGV[0]) or die; binmode F; print encode_base64(<F>)' "$1"
    else
        for _p in python python2 python3; do
            have "$_p" && { "$_p" -c 'import sys, base64; sys.stdout.write(base64.b64encode(open(sys.argv[1], "rb").read()).decode("ascii") if sys.version_info[0] > 2 else base64.b64encode(open(sys.argv[1], "rb").read()))' "$1"; echo; return; }
        done
        return 1
    fi
}
echo "CMDB-B64-BEGIN"
b64 "$W.tgz"
echo "CMDB-B64-END"
printf '{"collector": "shell", "version": "%s", "bytes_tgz": %s, "files_found": %s, "archives": %s}\n' \
    "$VERSION" "$(ls -ln "$W.tgz" | awk '{print $5}')" \
    "$(cat "$W/scan/found.lst" 2>/dev/null | wc -l | tr -d ' ')" \
    "$(cat "$W/scan/archives.lst" 2>/dev/null | wc -l | tr -d ' ')" >&2
exit 0
