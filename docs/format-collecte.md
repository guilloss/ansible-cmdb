# Format de collecte v1 (`cmdb-collector/1`) — gelé le 10 novembre 2026

Des équipes collectent déjà avec ce projet. Ce qui suit ne change plus de façon incompatible : leurs
procédures, leurs inventaires et les collectes déjà faites restent valables avec toutes les versions
à venir. Les tests `tests/test_format_v1.py` le vérifient à chaque modification.

## Règles

1. **Ajouter est permis** : une nouvelle section, une nouvelle clé, une nouvelle option, une nouvelle
   variable avec une valeur par défaut qui ne change pas le comportement.
2. **Retirer, renommer ou changer le sens est interdit** : une clé du document, une option des
   collecteurs, une variable du rôle ou de `consolidate.yml`, une option de `cmdb_build.py`, un nom
   de fichier ou de répertoire du magasin ou des lots.
3. **La consolidation lit toutes les collectes v1**, quelle que soit la version du collecteur qui
   les a produites. Une clé ajoutée plus tard est donc toujours facultative à la lecture.
4. Une évolution incompatible, si un jour elle est inévitable, s'appellera `cmdb-collector/2`. La
   consolidation continuera alors à lire `cmdb-collector/1`. Une consolidation plus ancienne qui
   rencontre un format qu'elle ne connaît pas ignore la collecte et le signale (`ATTENTION : … format
   … inconnu`) : elle ne la lit jamais à moitié.

Les fichiers de `tests/fixtures/format_v1/` sont des collectes produites par les versions gelées
(Python 1.1.0, shell 1.2.0-sh, PowerShell 0.1.0-ps). Ils ne se modifient jamais.

## Ce qui est gelé

### Lancement

| Élément | Gelé |
|---|---|
| Playbooks | `collect.yml`, `collect_legacy.yml`, `consolidate.yml` |
| Étiquetage | `cmdb_app`, `cmdb_platform` (obligatoires), `cmdb_tags` ; valeurs `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` |
| Variables du rôle | toutes celles de `roles/cmdb_collect/defaults/main.yml` au 10/11/2026 |
| Variables de `consolidate.yml` | `cmdb_build_dir`, `cmdb_store_dirs`, `cmdb_lots`, `cmdb_filter_apps`, `cmdb_filter_platforms`, `cmdb_java_db`, `cmdb_platform_order`, `cmdb_report_exclude` |
| `cmdb_collector.py` | `--output/-o`, `--host-label`, `--tag`, `--run-id`, `--scan-root`, `--exclude`, `--extra-exclude`, `--scan-max-seconds`, `--no-scan-filesystem`, `--no-exec-probes`, `--no-hash-archives`, `--no-file-owners`, `--no-nice`, `--include-network-fs`, `--include-container-storage`, `--pending-updates`, et les autres options présentes (ajoutées depuis : `--no-container-content`, `--container-max-seconds`, `--container-max-images`) |
| `cmdb_collector.sh` | `--host-label`, `--tag`, `--run-id`, `--scan-max-seconds`, `--exec-max-seconds`, `--exec-timeout`, `--no-scan-filesystem`, `--no-exec-probes`, `--no-hash-archives`, `--extra-exclude` |
| `cmdb_collector.ps1` | `-App`, `-Platform`, `-HostLabel`, `-RunId`, `-Tag`, `-OutFile`, `-ScanMaxSeconds`, `-ArchiveMaxSeconds`, `-ScanPath`, `-ExcludePath`, `-NoScan`, `-NoHash` |
| `cmdb_build.py` | toutes ses options au 10/11/2026 (`--store`, `--lot`, `--out`, `--java-db`, `--platform-order`…) |

### Transport

- Collecteur Python avec `--output fichier` : JSON compressé gzip.
- Sortie « flux » (collecte sans module, Windows, lancement à la main) : base64 entre deux lignes
  `CMDB-B64-BEGIN` et `CMDB-B64-END`, texte avant et après ignoré. Le contenu est soit un JSON gzip
  (Python, PowerShell), soit une archive tar(.gz) de sorties brutes (shell, converties par le
  contrôleur). `tools/cmdb_unpack.py <sortie> <destination.json.gz>` décode les deux.

### Document

Un objet JSON. Clés de premier niveau : `schema` (`"cmdb-collector/1"`), `meta`, `os`, `hardware`,
`packages`, `processes`, `network`, `services`, `scheduled`, `accounts`, `security`, `kernel`,
`containers`, `oracle`, `software_dirs`, `filesystem`, `process_artifacts`, `runtimes`, `go_binaries`.
Ajouts depuis le gel (facultatifs à la lecture) : `container_content` (10/11/2026, contenu des
conteneurs en marche : `engines`, `images[]` avec `os_release`, `packages.managers`, `filesystem`, `stats`).
Le collecteur Windows produit `meta`, `os`, `hardware`, `processes`, `network`, `filesystem` et `windows`.

- `meta` : `collector_version`, `started_at`, `finished_at`, `host_label`, `run_id`, `tags` (dont
  `app` et `platform`), `user`, `errors` ; `collector` vaut `shell` ou `powershell` pour ces deux
  collecteurs (absent : Python).
- `os.os_release` : champs de `/etc/os-release` (`ID`, `VERSION_ID`, `PRETTY_NAME`…) ; `ID` vaut `aix`,
  `windows` ou `windows-server` pour ces systèmes.
- `filesystem` : `java_archives` (`path`, `size`, `sha1`, `manifest`, `maven`), `jdk_homes`,
  `python_packages`, `npm_packages`, `composer_installed`, `webapps`, `db_refs`, `crypto_files`,
  `endpoints`, `service_modules`, `stats`, etc. Chemins en barres obliques, y compris sous Windows.

### Magasin et lots

```
<store>/<app>/<pf>/<hôte>/<run_id>.json.gz          collecte (et latest.json.gz)
<store>/<app>/<pf>/<hôte>/<run_id>.ansible_facts.json  faits Ansible (facultatif)
<store>/<app>/<pf>/<hôte>/<run_id>.error.json       trace d'un échec
<store>/_runs/<run_id>/_run.json                    en-tête du passage
<store>/_runs/<run_id>/<app>__<pf>__<hôte>.json     statut de chaque hôte
<store>/_lots/<run_id>.tar.gz                       lot : les fichiers ci-dessus, chemins relatifs au magasin
```

Ajout depuis le gel (12/11/2026) : le lot porte aussi le nom `<app>__<pf>__<run_id>.tar.gz` (plusieurs
valeurs jointes par `+`, au-delà de trois `multi` ; `cmdb_lot_name` impose un nom). `<run_id>.tar.gz`
reste produit, en lien dur vers le même fichier (`cmdb_lot_keep_run_id_name: false` pour s'en passer).
La consolidation ne tire rien du nom d'un lot : tout nom est accepté, et un même fichier sous deux noms
n'est lu qu'une fois.

L'hôte, l'application et la plate-forme se lisent dans le document (`meta.host_label`, `meta.tags`),
pas dans le chemin : un fichier déplacé reste correctement rattaché.
