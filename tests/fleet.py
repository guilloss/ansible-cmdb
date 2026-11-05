# -*- coding: utf-8 -*-
"""Parc fictif : collectes construites à la main, dans le format réel des collecteurs."""
import gzip
import json
import os

ORA_HOME = "/u01/app/oracle/product/19.0.0/dbhome_1"
ORA_OLD = "/u01/app/oracle/product/12.2.0/dbhome_1"


def doc(host, app, pf, ip, run, at, **kw):
    d = {"schema": "cmdb-collector/1",
         "meta": {"collector_version": "1.1.0", "started_at": at, "host_label": host, "run_id": run, "tags": {"app": app, "platform": pf},
                  "uid": 1000, "user": "ansible", "errors": [], "visibility": {"processes": 10}},
         "os": {"hostname": host.split(".")[0], "fqdn": host, "os_release": {"ID": "rhel", "VERSION_ID": "8.9", "PRETTY_NAME": "RHEL 8.9"},
                "uname": {"release": "4.18.0-513.el8.x86_64", "machine": "x86_64"}},
         "hardware": {"virtualization": "vmware", "lscpu_kv": {"Socket(s)": "2", "Core(s) per socket": "4", "Thread(s) per core": "2"}},
         "network": {"addresses": [{"ifname": "eth0", "family": "inet", "cidr": ip + "/24", "scope": "global"}], "interfaces": [],
                     "listening": [], "established": [], "hosts_file": ""},
         "processes": {"list": []}, "packages": {"managers": {"rpm": []}}, "filesystem": {}, "oracle": {}, "runtimes": {"list": []},
         "kernel": {"sysctl": "kernel.sysrq = 1\nkernel.dmesg_restrict = 1\n"}, "security": {}, "accounts": {}, "services": {}}
    for k, v in kw.items():
        if k in ("listening", "established"):
            d["network"][k] = v
        elif k == "processes":
            d["processes"]["list"] = v
        else:
            d[k] = v
    return d


def oracle_host(run="r2", at="2026-11-02T08:00:00Z", level="19.23.0.0.240416", patch="36233263"):
    patches = [{"id": patch, "description": "Database Release Update : %s (%s)" % (level, patch), "installed_at": "2024.Jun.10"},
               {"id": "36199232", "description": "OJVM RELEASE UPDATE: 19.23.0.0.240416 (36199232)"}]
    return doc("ora1.exemple.test", "APPDEMO", "prod", "10.0.0.10", run, at,
               oracle={"oratab": "PROD:%s:Y\nARCH:%s:N\n" % (ORA_HOME, ORA_OLD),
                       "homes": [{"home": ORA_HOME, "product": "database", "version": "19.0.0.0.0", "install_type": "EE", "visibility": "complet",
                                  "patches": patches, "opatch_version": "12.2.0.1.41", "sources": ["oratab"], "exists": True,
                                  "listeners": [{"name": "LISTENER", "host": "ora1", "port": 1521}], "tns_refs": []},
                                 {"home": ORA_OLD, "visibility": "aucun", "patches": [], "sources": ["oratab"], "exists": True, "listeners": [], "tns_refs": []}]},
               processes=[{"pid": 10, "ppid": 1, "comm": "ora_pmon_PROD", "cmdline": "ora_pmon_PROD", "user": "oracle"},
                          {"pid": 11, "ppid": 1, "comm": "tnslsnr", "cmdline": ORA_HOME + "/bin/tnslsnr LISTENER -inherit", "user": "oracle"}],
               listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 1521, "pid": 11, "process": "tnslsnr", "user": "oracle"}],
               established=[{"direction": "in", "local_port": 1521, "remote_addr": "10.0.0.20", "remote_port": None, "process": "tnslsnr", "count": 4},
                            {"direction": "in", "local_port": 1521, "remote_addr": "10.9.9.9", "remote_port": None, "process": "tnslsnr", "count": 1}])


def pg_host():
    return doc("pg1.exemple.test", "APPDEMO", "prod", "10.0.0.11", "r2", "2026-11-02T08:00:00Z",
               processes=[{"pid": 20, "ppid": 1, "comm": "postgres", "cmdline": "/usr/pgsql-14/bin/postgres -D /var/lib/pgsql/14/data", "user": "postgres"},
                          {"pid": 21, "ppid": 20, "comm": "postgres", "cmdline": "postgres: appuser appdb 10.0.0.20(45000) idle", "user": "postgres"},
                          {"pid": 22, "ppid": 20, "comm": "postgres", "cmdline": "postgres: walsender repl 10.0.0.12(46000) streaming 0/3000000", "user": "postgres"}],
               listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 5432, "pid": 20, "process": "postgres", "user": "postgres"}])


def pg_standby():
    return doc("pg2.exemple.test", "APPDEMO", "prod", "10.0.0.12", "r2", "2026-11-02T08:00:00Z",
               processes=[{"pid": 30, "ppid": 1, "comm": "postgres", "cmdline": "/usr/pgsql-14/bin/postgres -D /data", "user": "postgres"},
                          {"pid": 31, "ppid": 30, "comm": "postgres", "cmdline": "postgres: walreceiver streaming 0/3000000", "user": "postgres"}],
               listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 5432, "pid": 30, "process": "postgres", "user": "postgres"}])


def app_host(run="r2", at="2026-11-02T08:00:00Z"):
    return doc("app1.exemple.test", "APPDEMO", "prod", "10.0.0.20", run, at,
               filesystem={"db_refs": [{"engine": "postgresql", "host": "pg1.exemple.test", "port": 5432, "database": "appdb", "kind": "jdbc", "path": "/opt/app/application.properties"},
                                       {"engine": "postgresql", "host": "base-reporting", "port": None, "database": "rep", "kind": "jdbc", "path": "/opt/app/report.properties"},
                                       {"engine": "oracle", "host": None, "alias": "PRODTNS", "kind": "jdbc", "path": "/opt/app/ora.properties"},
                                       {"engine": "oracle", "host": "ora1.exemple.test", "port": 1521, "database": "prod.svc", "alias": "PRODTNS", "kind": "tnsnames", "path": "/etc/tnsnames.ora"},
                                       {"engine": "mysql", "host": "my9.exemple.test", "port": 3306, "database": "ext", "kind": "jdbc", "path": "/opt/app/ext.properties"}],
                           "db_refs_resolved": {"base-reporting": ["10.0.0.11"]},
                           "service_modules": [{"product": "apache", "module": "ssl_module", "value": "modules/mod_ssl.so", "path": "/etc/httpd/conf.modules.d/00.conf"}],
                           "endpoints": [{"product": "apache", "kind": "vhost", "address": "*", "port": 443, "server_name": "www.exemple.test", "aliases": ["a.exemple.test"], "root": "/var/www", "tls": True, "path": "/etc/httpd/conf.d/ssl.conf"},
                                         {"product": "apache", "kind": "proxy", "location": "/app", "backend": "http://127.0.0.1:8080/app", "path": "/etc/httpd/conf.d/ssl.conf"}],
                           "java_archives": [{"path": "/opt/tomcat/webapps/gestion.war"}, {"path": "/opt/tomcat/webapps/ROOT.war"}],
                           "crypto_files": [{"path": "/etc/pki/tls/private/www.key", "kind": "pem", "has_private_key": True, "encrypted": False, "key_type": "RSA", "mode": "0644", "owner": "root", "cert_count": 0, "certs": []},
                                            {"path": "/etc/pki/tls/certs/www.crt", "kind": "pem", "has_private_key": False, "mode": "0644", "owner": "root", "cert_count": 1,
                                             "certs": [{"subject": "CN=www.exemple.test", "cn": "www.exemple.test", "issuer": "CN=ca", "not_after": "2026-11-20T00:00:00Z", "is_ca": False, "sha256": "ab", "sans": ["www.exemple.test"]}]},
                                            {"path": "/opt/app/ks.p12", "kind": "pkcs12", "encrypted": True, "mode": "0600", "owner": "app", "cert_count": 0, "certs": [], "note": "protégé par un mot de passe : contenu non lu"}]},
               runtimes={"list": [{"probe": "php", "realpath": "/usr/bin/php", "outputs": [
                   {"args": ["-m"], "rc": 0, "output": "[PHP Modules]\nCore\nmbstring\n\n[Zend Modules]\nZend OPcache\n"},
                   {"args": ["-i"], "rc": 0, "output": "phpinfo()\nPHP Version => 8.1.2\n\nCore\n\nDirective => Local Value => Master Value\nexpose_php => On => On\n\nmbstring\n\nMultibyte Support => enabled\n"}]}]},
               processes=[{"pid": 40, "ppid": 1, "comm": "java", "exe": "/usr/lib/jvm/j17/bin/java", "user": "tomcat",
                           "cmdline": "/usr/lib/jvm/j17/bin/java -Xmx2g -Dcatalina.base=/opt/tomcat -cp /opt/tomcat/bin/bootstrap.jar org.apache.catalina.startup.Bootstrap start"}],
               listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 8080, "pid": 40, "process": "java", "user": "tomcat"}],
               established=[{"direction": "out", "local_port": None, "remote_addr": "10.0.0.10", "remote_port": 1521, "process": "java", "count": 4},
                            {"direction": "out", "local_port": None, "remote_addr": "10.0.0.11", "remote_port": 5432, "process": "java", "count": 2}])


def write_store(root, docs):
    for d in docs:
        m = d["meta"]
        path = os.path.join(root, m["tags"]["app"], m["tags"]["platform"], m["host_label"])
        os.makedirs(path, exist_ok=True)
        raw = gzip.compress(json.dumps(d).encode("utf-8"))
        with open(os.path.join(path, m["run_id"] + ".json.gz"), "wb") as f:
            f.write(raw)
    # latest : copie de la collecte la plus récente
    for dirpath, _dirs, files in os.walk(root):
        files = sorted(f for f in files if f.endswith(".json.gz") and f != "latest.json.gz")
        if files:
            with open(os.path.join(dirpath, files[-1]), "rb") as f, open(os.path.join(dirpath, "latest.json.gz"), "wb") as g:
                g.write(f.read())


def web_host():
    """Frontal : proxy vers le serveur d'applications ; deux instances jumelles sur app1/app2."""
    return doc("web1.exemple.test", "APPDEMO", "prod", "10.0.0.30", "r2", "2026-11-02T08:00:00Z",
               filesystem={"endpoints": [{"product": "nginx", "kind": "proxy", "location": "/", "backend": "http://app1.exemple.test:8080/", "path": "/etc/nginx/nginx.conf"}]},
               established=[{"direction": "out", "local_port": None, "remote_addr": "10.0.0.20", "remote_port": 8080, "process": "nginx", "count": 3},
                            {"direction": "out", "local_port": None, "remote_addr": "10.0.0.11", "remote_port": 22, "process": "ssh", "count": 1}])


def twin(host, ip, php="8.1.2", pf="prod", run="r2"):
    return doc(host, "APPDEMO", pf, ip, run, "2026-11-02T08:00:00Z",
               runtimes={"list": [{"probe": "php", "realpath": "/usr/bin/php", "outputs": [
                   {"args": ["-v"], "rc": 0, "output": "PHP %s (cli)\n" % php}]}]},
               processes=[{"pid": 50, "ppid": 1, "comm": "httpd", "cmdline": "/usr/sbin/httpd", "user": "apache"}],
               listening=[{"proto": "tcp", "address": "0.0.0.0", "port": 8081, "pid": 50, "process": "httpd", "user": "apache"}])
