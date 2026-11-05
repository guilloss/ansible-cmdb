#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_dossier.py - Un dossier d'application par couple (application, plate-forme).

Fichier HTML autonome, sans script, à imprimer ou enregistrer en PDF depuis le navigateur.
Il ne contient que le périmètre demandé : un serveur d'une autre application n'y apparaît
que s'il échange avec celui-ci. C'est ce qui permet de le remettre à un tiers, à la
différence du rapport, qui contient tout le parc.
"""
import datetime as dt
import html
import os

import cmdb_hardening

DEFAULT_MENTION = "Document interne : contient des informations sensibles sur le système d'information"
MAX_GRAPH_NODES = 60
KEY_FAMILIES = ("oracle-database", "oracle-grid", "postgresql", "mysql", "mariadb", "java", "tomcat", "httpd", "nginx", "php", "python",
                "node", "openssl", "websphere", "ihs")
EDGE_STYLE = {"base": ("#44535B", ""), "proxy": ("#1668A3", ""), "stockage": ("#2E7D5B", ""), "réplication": ("#B07F0E", "6 4"),
              "disque partagé": ("#2E7D5B", "6 4")}
CSS = """
:root { color-scheme: light; }
body { margin: 0 auto; max-width: 1100px; padding: 24px 32px; background: #fff; color: #1F2A30;
       font: 14px/1.45 "Segoe UI", system-ui, "Noto Sans", "DejaVu Sans", sans-serif; }
h1 { font-size: 28px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #1F2A30; }
h3 { font-size: 15px; margin: 20px 0 6px; }
p { margin: 6px 0; }
.mention { font-size: 12px; color: #B4322A; font-weight: 600; }
.sub, .note { color: #5A6871; font-size: 12.5px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 12.5px; }
th { text-align: left; background: #F0F3F5; }
th, td { padding: 4px 7px; border: 1px solid #D5DCE0; vertical-align: top; overflow-wrap: anywhere; }
.facts { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.fact { border: 1px solid #D5DCE0; padding: 6px 12px; min-width: 96px; }
.fact b { display: block; font-size: 20px; }
.fact span { font-size: 12px; color: #5A6871; }
.warn { color: #8A6100; font-weight: 600; }
.risk { color: #B4322A; font-weight: 600; }
.ok { color: #2E7D5B; }
ul.attention { padding-left: 18px; margin: 6px 0; }
svg { max-width: 100%; height: auto; display: block; margin: 8px 0; }
.toc { columns: 2; font-size: 13px; padding-left: 18px; }
@media (max-width: 700px) { body { padding: 16px; } .toc { columns: 1; } }
@media print {
  body { max-width: none; padding: 0; font-size: 11px; }
  h2 { break-after: avoid; }
  tr, svg, .fact { break-inside: avoid; }
  thead { display: table-header-group; }
  a { color: inherit; text-decoration: none; }
}
@page { margin: 14mm; @bottom-center { content: counter(page); } }
"""


def esc(v):
    return "" if v is None else html.escape(str(v), quote=True)


def table(headers, rows, empty="Rien à signaler."):
    """Les cellules déjà balisées arrivent sous la forme Raw."""
    if not rows:
        return '<p class="note">%s</p>' % esc(empty)
    head = "".join("<th>%s</th>" % esc(h) for h in headers)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % (c.html if isinstance(c, Raw) else esc(c)) for c in r) for r in rows)
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (head, body)


class Raw(object):
    def __init__(self, text):
        self.html = text


def tag(cls, text):
    return Raw('<span class="%s">%s</span>' % (cls, esc(text)))


def day(v):
    return (v or "")[:10]


def graph(flows):
    """Même disposition que la carte du rapport : colonnes par profondeur, sans script."""
    edges = [f for f in flows if f["kind"] != "réseau" and f["s"] != f["d"]]
    names = sorted(set(n for e in edges for n in (e["s"], e["d"])))
    if not names:
        return '<p class="note">Aucun flux déclaré dans ce périmètre.</p>'
    if len(names) > MAX_GRAPH_NODES:
        return '<p class="note">%d serveurs : schéma omis, voir la liste des flux.</p>' % len(names)
    rank = dict((n, 0) for n in names)
    flow = [e for e in edges if e["kind"] not in ("réplication", "disque partagé")]
    for _ in range(min(len(names), 12)):
        for e in flow:
            if rank[e["d"]] < rank[e["s"]] + 1:
                rank[e["d"]] = rank[e["s"]] + 1
    for e in edges:
        if e["kind"] == "réplication" and not any(e["s"] in (f["s"], f["d"]) for f in flow):
            rank[e["s"]] = rank[e["d"]]
    cols = {}
    for n in names:
        cols.setdefault(rank[n], []).append(n)
    W, H, GX, GY = 190, 42, 90, 18
    pos = {}
    for r, lst in cols.items():
        for i, n in enumerate(lst):
            pos[n] = (10 + r * (W + GX), 10 + i * (H + GY))
    width = 20 + (max(cols) + 1) * (W + GX) - GX + 50
    height = 20 + max(len(v) for v in cols.values()) * (H + GY) - GY
    out = ['<svg viewBox="0 0 %d %d" width="%d" role="img" aria-label="Schéma des flux" xmlns="http://www.w3.org/2000/svg">' % (width, height, width),
           '<defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L8 4L0 8z" fill="#6A7881"/></marker></defs>']
    for e in edges:
        (ax, ay), (bx, by) = pos[e["s"]], pos[e["d"]]
        same = ax == bx
        x1 = ax + W if same or ax < bx else ax
        x2 = bx + W if same or ax > bx else bx
        y1, y2, m = ay + H / 2, by + H / 2, (x1 + x2) / 2 + (40 if same else 0)
        color, dash = EDGE_STYLE.get(e["kind"], ("#6A7881", ""))
        arrow = "" if e["kind"] == "disque partagé" else ' marker-end="url(#a)"'
        out.append('<path d="M%s %s C%s %s %s %s %s %s" fill="none" stroke="%s" stroke-width="1.4"%s%s/>'
                   % (x1, y1, m, y1, m, y2, x2, y2, color, ' stroke-dasharray="%s"' % dash if dash else "", arrow))
    for n in names:
        x, y = pos[n]
        inside = flows_inside(flows, n)
        out.append('<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" stroke="#44535B"%s/>'
                   % (x, y, W, H, "#EAF2F8" if inside else "#FFFFFF", "" if inside else ' stroke-dasharray="4 3"'))
        out.append('<text x="%d" y="%d" font-size="12" font-weight="600" fill="#1F2A30">%s</text>' % (x + 8, y + 18, esc(n[:26])))
        out.append('<text x="%d" y="%d" font-size="10" fill="#5A6871">%s</text>' % (x + 8, y + 33, esc(side_label(flows, n))))
    out.append("</svg>")
    out.append('<p class="note">Fond bleu : serveurs du périmètre. Pointillés : autres applications ou hors inventaire. '
               'Noir : base ; bleu : proxy ; vert : stockage ; ambre tireté : réplication ; vert tireté : disque partagé.</p>')
    return "".join(out)


def flows_inside(flows, name):
    return any((f["s"] == name and f["s_in"]) or (f["d"] == name and f["d_in"]) for f in flows)


def side_label(flows, name):
    for f in flows:
        if f["s"] == name and f["s_label"]:
            return f["s_label"]
        if f["d"] == name and f["d_label"]:
            return f["d_label"]
    return "hors inventaire"


def app_flows(db, app, pf):
    rows = db.execute("""SELECT src_app, src_platform, src_host, src_addr, dst_app, dst_platform, dst_host, dst_addr, port, kind, detail, status
                         FROM app_flows WHERE (src_app = ? AND src_platform = ?) OR (dst_app = ? AND dst_platform = ?)""", (app, pf, app, pf)).fetchall()
    out = []
    for sa, sp, sh, saddr, da, dp, dh, daddr, port, kind, detail, status in rows:
        out.append({"s": sh or saddr or "inconnu", "d": dh or daddr or "inconnu", "s_in": (sa, sp) == (app, pf), "d_in": (da, dp) == (app, pf),
                    "s_label": "%s / %s" % (sa, sp) if sh else None, "d_label": "%s / %s" % (da, dp) if dh else None, "port": port, "kind": kind,
                    "detail": detail, "status": status})
    return out


def render(db, app, pf, mention, today=None):
    today = today or dt.date.today()
    K = (app, pf)

    def q(sql, *extra):
        return db.execute(sql, K + extra).fetchall()
    W = "app = ? AND platform = ?"
    hosts = q("""SELECT host, os_pretty, kernel, cpu_cores, mem_total_mb, ip_addresses, virtualization, collected_at, privileged, collect_errors
                 FROM hosts WHERE %s ORDER BY host""" % W)
    flows = app_flows(db, app, pf)
    instances = q("SELECT host, engine, instance, status, role, version, patch_level, ports FROM db_instances WHERE %s ORDER BY host, engine" % W)
    homes = q("""SELECT host, home, product, version, edition, patch_level, patch_date, patch_age_days, visibility, in_use, behind_fleet
                 FROM oracle_homes WHERE %s ORDER BY host, home""" % W)
    links = db.execute("""SELECT COALESCE(client_host, client_addr), COALESCE(server_host, server_addr), engine, port, database, status FROM db_links
                          WHERE (client_app = ? AND client_platform = ?) OR (server_app = ? AND server_platform = ?) ORDER BY 2, 1""", K + K).fetchall()
    eps = q("""SELECT host, product, kind, server_name, port, tls, location, backend, root FROM endpoints WHERE %s AND kind IN ('vhost', 'connector', 'frontend', 'context', 'proxy')
               ORDER BY host, product, kind, port""" % W)
    usage = q("SELECT host, server_name, port, cn, not_after, days_left, state, name_match FROM cert_usage WHERE %s ORDER BY days_left" % W)
    certs = q("SELECT host, cn, issuer, not_after, days_left, path FROM crypto_certs WHERE %s AND COALESCE(is_ca, 0) = 0 ORDER BY days_left" % W)
    keys = q("SELECT host, path, kind, encrypted, empty_password, mode, world_readable FROM crypto_files WHERE %s AND (has_private_key = 1 OR kind IN ('pkcs12', 'oracle-wallet', 'gskit-stash', 'gskit-kdb')) ORDER BY host, path" % W)
    marks = ",".join("?" * len(KEY_FAMILIES))
    comps = db.execute("SELECT host, family, GROUP_CONCAT(DISTINCT version) FROM software WHERE app = ? AND platform = ? AND category != 'os-package' AND family IN (%s) GROUP BY host, family ORDER BY family, host" % marks, K + KEY_FAMILIES).fetchall()
    eol = q("SELECT host, product, cycle, version, eol, extended, days_left, status, managed, location FROM eol_status WHERE %s AND status != 'supporté' ORDER BY days_left" % W)
    scores = q("SELECT host, level, score, ok, ko, unknown FROM hardening_scores WHERE %s ORDER BY host" % W)
    failing = q("""SELECT ref, level, title, COUNT(*) AS n FROM hardening_results WHERE %s AND status = 'non conforme' GROUP BY rule_id ORDER BY n DESC, ref LIMIT 25""" % W)
    drift = db.execute("""SELECT left_platform, right_platform, kind, item, left_value, right_value FROM drift WHERE scope = 'plates-formes' AND app = ?
                          AND (left_platform = ? OR right_platform = ?) ORDER BY kind, item LIMIT 200""", (app, pf, pf)).fetchall()
    twins = db.execute("""SELECT left_host, right_host, kind, item, left_value, right_value FROM drift WHERE scope = 'jumeaux' AND app = ? AND left_platform = ?
                          ORDER BY kind, item LIMIT 200""", K).fetchall()

    # Points d'attention, du plus urgent au moins urgent
    attention = []
    dead = [u for u in usage if u[6] == "expiré"]
    soon = [u for u in usage if u[6] == "à renouveler"]
    if dead:
        attention.append(("risk", "%d service(s) présentent un certificat expiré" % len(dead)))
    if soon:
        attention.append(("warn", "%d service(s) ont un certificat à renouveler sous 30 jours" % len(soon)))
    exposed = [k for k in keys if k[6] or k[4]]
    if exposed:
        attention.append(("risk", "%d clé(s) privée(s) exposée(s) : lisibles par tous ou sans mot de passe" % len(exposed)))
    late = [h for h in homes if h[10] or (h[7] or 0) >= 200]
    if late:
        attention.append(("warn", "%d ORACLE_HOME en retard de correctifs" % len(late)))
    blind = [h for h in homes if h[8] != "complet"]
    if blind:
        attention.append(("warn", "%d ORACLE_HOME dont le niveau de correctif n'est pas visible" % len(blind)))
    expired = [e for e in eol if e[7] == "expiré" and (not e[8] or e[9] == "système")]
    if expired:
        attention.append(("warn", "%d composant(s) ou système(s) en fin de support" % len(expired)))
    partial = [h for h in hosts if not h[8]]
    if partial:
        attention.append(("note", "%d serveur(s) collectés sans privilèges : certaines données peuvent manquer" % len(partial)))

    by_host = {}
    for host, level, score, ok, ko, unknown in scores:
        by_host.setdefault(host, {})[level] = score
        by_host[host]["unknown"] = unknown
    oldest = min((h[7] or "" for h in hosts), default="")
    title = "Dossier d'application : %s, %s" % (app, pf)
    S = []
    S.append('<p class="mention">%s</p><h1>%s</h1><p class="sub">Établi le %s. Collecte la plus ancienne du périmètre : %s. '
             "Document produit automatiquement à partir de l'inventaire : à relire avant diffusion.</p>"
             % (esc(mention), esc(title), today.strftime("%d/%m/%Y"), esc(day(oldest))))
    S.append('<div class="facts">' + "".join('<div class="fact"><b>%d</b><span>%s</span></div>' % (n, esc(l)) for n, l in (
        (len(hosts), "serveurs"), (len(instances), "instances de bases"), (len(links), "liens vers des bases"),
        (len([e for e in eps if e[2] == "vhost"]), "virtualhosts"), (len(certs), "certificats"), (len(keys), "clés et magasins"))) + "</div>")
    sections = [("attention", "Points d'attention"), ("serveurs", "Serveurs"), ("architecture", "Architecture et flux"), ("bases", "Bases de données"),
                ("services", "Points d'entrée"), ("certificats", "Certificats et clés"), ("composants", "Composants principaux"),
                ("support", "Fins de support"), ("durcissement", "Durcissement"), ("ecarts", "Écarts"), ("limites", "Limites de ce document")]
    S.append('<ol class="toc">' + "".join('<li><a href="#%s">%s</a></li>' % s for s in sections) + "</ol>")

    S.append('<h2 id="attention">1. Points d\'attention</h2>')
    S.append('<ul class="attention">%s</ul>' % "".join('<li class="%s">%s</li>' % (c, esc(t)) for c, t in attention) if attention else '<p class="ok">Rien à signaler sur les points contrôlés.</p>')

    S.append('<h2 id="serveurs">2. Serveurs</h2>')
    S.append(table(["Serveur", "Système", "Cœurs", "Mémoire (Go)", "Adresses", "Virtualisation", "Collecte"],
                   [(h[0], h[1], h[3], round(h[4] / 1024.0, 1) if h[4] else None, h[5], h[6], day(h[7])) for h in hosts]))

    S.append('<h2 id="architecture">3. Architecture et flux</h2>')
    S.append(graph(flows))
    ext = sorted(set((f["d"], f["d_label"] or "hors inventaire", f["kind"], f["port"]) for f in flows if f["s_in"] and not f["d_in"]), key=repr)
    inc = sorted(set((f["s"], f["s_label"] or "hors inventaire", f["kind"], f["port"]) for f in flows if f["d_in"] and not f["s_in"]), key=repr)
    S.append("<h3>Dépendances vers l'extérieur du périmètre</h3>" + table(["Cible", "Application", "Nature", "Port"], ext, "Aucune détectée."))
    S.append("<h3>Clients extérieurs au périmètre</h3>" + table(["Source", "Application", "Nature", "Port"], inc, "Aucun détecté."))
    S.append("<h3>Tous les flux</h3>" + table(["Source", "Destination", "Port", "Nature", "Détail", "État"],
                                               sorted(((f["s"], f["d"], f["port"], f["kind"], f["detail"], f["status"]) for f in flows), key=repr), "Aucun flux."))

    S.append('<h2 id="bases">4. Bases de données</h2>')
    S.append(table(["Serveur", "Moteur", "Instance", "État", "Rôle", "Version", "Correctif", "Ports"], instances, "Aucune instance."))
    if homes:
        S.append("<h3>ORACLE_HOME</h3>" + table(["Serveur", "Chemin", "Produit", "Version", "Édition", "Niveau de correctif", "Date", "Visibilité"],
                                                  [(h[0], h[1], h[2], h[3], h[4], h[5] or (tag("warn", "non visible") if h[8] != "complet" else "aucun"), h[6], h[8]) for h in homes]))
    S.append("<h3>Liens applicatifs</h3>" + table(["Client", "Serveur de base", "Moteur", "Port", "Base", "État"], links, "Aucun lien."))

    S.append('<h2 id="services">5. Points d\'entrée</h2>')
    S.append(table(["Serveur", "Produit", "Nature", "Nom", "Port", "TLS", "Chemin", "Vers", "Racine"],
                   [(e[0], e[1], e[2], e[3], e[4], "oui" if e[5] else "", e[6], e[7], e[8]) for e in eps], "Aucun point d'entrée relevé."))

    S.append('<h2 id="certificats">6. Certificats et clés</h2>')
    state = {"expiré": "risk", "à renouveler": "warn", "valide": "ok"}
    S.append("<h3>Certificats des services</h3>" + table(["Serveur", "Service", "Port", "CN", "Expiration", "Jours", "État"],
                                                           [(u[0], u[1], u[2], u[3], day(u[4]), u[5], tag(state.get(u[6], "note"), u[6])) for u in usage], "Aucun service ne déclare de certificat."))
    S.append("<h3>Tous les certificats</h3>" + table(["Serveur", "CN", "Émetteur", "Expiration", "Jours", "Fichier"], [(c[0], c[1], c[2], day(c[3]), c[4], c[5]) for c in certs], "Aucun certificat lu."))
    S.append("<h3>Clés et magasins</h3>" + table(["Serveur", "Fichier", "Format", "Protection", "Droits"],
                                                   [(k[0], k[1], k[2], tag("risk", "sans mot de passe") if k[4] else ("chiffrée" if k[3] else ("en clair" if k[3] == 0 else "")),
                                                     tag("risk", k[5]) if k[6] else k[5]) for k in keys], "Aucune clé repérée."))

    S.append('<h2 id="composants">7. Composants principaux</h2>')
    S.append(table(["Serveur", "Composant", "Versions"], [(c[0], c[1], (c[2] or "").replace(",", ", ")) for c in comps], "Aucun composant suivi."))

    S.append('<h2 id="support">8. Fins de support</h2>')
    S.append('<p class="note">Dates à confirmer auprès des éditeurs. Pour un paquet de distribution, le support suit celui du système.</p>')
    S.append(table(["Serveur", "Produit", "Cycle", "Version", "Fin", "Support étendu", "Jours"], [e[:7] for e in eol], "Aucune fin de support dépassée ou proche."))

    S.append('<h2 id="durcissement">9. Durcissement</h2>')
    S.append('<p class="note">Guide ANSSI-BP-028 v2.0. Contrôle partiel : une partie seulement des recommandations est couverte, ce n\'est pas un audit. '
             "Les contrôles non vérifiables sont exclus du score.</p>")
    S.append(table(["Serveur"] + [l.capitalize() for l in cmdb_hardening.LEVELS] + ["Non vérifiables"],
                   [[h] + [("%s %%" % v[l]) if v.get(l) is not None else "" for l in cmdb_hardening.LEVELS] + [v.get("unknown")] for h, v in sorted(by_host.items())],
                   "Aucun serveur Linux évalué."))
    S.append("<h3>Non-conformités les plus fréquentes</h3>" + table(["Reco.", "Niveau", "Contrôle", "Serveurs"], failing, "Aucune."))

    S.append('<h2 id="ecarts">10. Écarts</h2>')
    S.append("<h3>Avec les autres plates-formes</h3>" + table(["A", "B", "Nature", "Élément", "Valeur A", "Valeur B"], drift, "Aucun écart, ou plate-forme unique."))
    S.append("<h3>Entre serveurs jumeaux</h3>" + table(["A", "B", "Nature", "Élément", "Valeur A", "Valeur B"], twins, "Aucun écart."))

    S.append('<h2 id="limites">11. Limites de ce document</h2><ul class="attention">'
             "<li>Photographie de la dernière collecte de chaque serveur ; un flux peu fréquent peut ne pas y figurer.</li>"
             "<li>Une collecte sans privilèges ne voit pas tout : une absence dans ce dossier ne prouve pas une absence sur le serveur.</li>"
             "<li>Aucune connexion aux bases n'a été faite : le passage de datapatch et les options Oracle utilisées ne sont pas vérifiés.</li>"
             "<li>Les vulnérabilités ne sont pas évaluées ici.</li></ul>")
    return ('<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            "<title>%s</title><style>%s</style></head><body>%s</body></html>" % (esc(title), CSS, "".join(S)))


def write_all(db, outdir, safe_name, mention=DEFAULT_MENTION):
    """-> {"app|plate-forme": chemin relatif au rapport}"""
    os.makedirs(outdir, exist_ok=True)
    out = {}
    for app, pf in db.execute("SELECT DISTINCT app, platform FROM hosts ORDER BY 1, 2").fetchall():
        name = safe_name(app, pf) + ".html"
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            f.write(render(db, app, pf, mention))
        out["%s|%s" % (app, pf)] = "dossiers/" + name
    return out
