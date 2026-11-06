# CMDB maison — inventaire exhaustif de serveurs Linux et AIX pour croisement CVE

Playbooks Ansible qui collectent, sur chaque serveur Linux ou AIX, sans aucun privilège, **tout ce qui permet de savoir quel logiciel tourne dans quelle version** (paquets, JVM, PHP, Python, Node, bases de données, serveurs web, bibliothèques embarquées dans les applications…), puis consolide le tout en une base SQLite, des CSV, une matrice des versions et des **SBOM CycloneDX** directement exploitables par les scanners de vulnérabilités.

Chaque passage de collecte est **étiqueté par application et plate-forme** ; la consolidation est un traitement séparé, qui rassemble autant de passages que l'on veut (voir « Applications et plates-formes »).

Philosophie : **on entasse d'abord, on trie ensuite.** Le collecteur conserve les sorties brutes (manifestes, sorties de `--version`, fichiers de configuration utiles) ; l'interprétation (versions, familles, purl, CPE) est faite à la consolidation, qu'on peut relancer à volonté sans recollecter.

## Arborescence

```
cmdb-ansible/
├── ansible.cfg
├── collect.yml                 # collecte, Linux récents (rôle cmdb_collect)
├── collect_legacy.yml          # collecte sans module Ansible côté cible : AIX, Linux anciens (choix auto Python / shell)
├── consolidate.yml             # consolidation, indépendante des collectes
├── inventory/
│   ├── hosts.yml               # exemple d'inventaire
│   └── local.yml               # test sur la machine locale
├── roles/cmdb_collect/
│   ├── defaults/main.yml       # tous les paramètres
│   ├── files/cmdb_collector.py # collecteur principal (stdlib, Python 2.6 / 2.7 / 3.6+)
│   ├── files/cmdb_collector.sh # collecteur de secours en shell POSIX (systèmes très anciens)
│   └── tasks/                  # main.yml, context.yml (étiquetage, run_id), finish.yml (manifeste, lot)
└── tools/
    ├── cmdb_build.py           # consolidation : SQLite, CSV, matrice, SBOM, rapport HTML
    ├── cmdb_report.py          # génération du rapport HTML (appelé par cmdb_build.py)
    ├── cmdb_report_template.html # gabarit du rapport (HTML/CSS/JS sans dépendance)
    ├── cmdb_unpack.py          # décodage du mode « flux » (collect_legacy.yml)
    ├── cmdb_shell_parse.py     # conversion des collectes shell (Linux et AIX) au format JSON commun
    ├── cmdb_extras.py          # consolidation : Oracle, liens vers les bases, clés, évolutions, fins de support
    ├── cmdb_maps.py            # consolidation : carte des flux, écarts entre plates-formes et serveurs jumeaux
    ├── cmdb_hardening.py       # consolidation : contrôles de durcissement ANSSI
    ├── cmdb_dossier.py         # dossier d'application : un HTML autonome par application et plate-forme
    ├── cmdb_anssi_rules.csv    # règles de durcissement (éditable)
    ├── cmdb_anssi_recos.csv    # les 80 recommandations ANSSI-BP-028 et leur couverture
    ├── cmdb_drift_ignore.txt   # écarts à ne pas signaler (éditable)
    └── cmdb_eol.csv            # référentiel des fins de support (éditable)
tests/                          # python3 -m unittest discover -s tests -t .
```

## Prérequis

| Où | Quoi |
|---|---|
| Contrôleur | ansible-core, Python ≥ 3.8 (pour `cmdb_build.py`, bibliothèque standard uniquement) |
| Cibles | SSH avec un compte dédié **non privilégié** : aucune élévation (ni sudo, ni `become`) ; Python facultatif (voir ci-dessous) |

ansible-core 2.17 et suivants n'exécutent plus de modules sur des cibles en Python < 3.7. Tout ce qui est plus ancien, et AIX, passe par une collecte qui n'exécute aucun module Ansible sur la cible : **`collect.yml` y bascule tout seul, hôte par hôte** (faits en échec, système autre que Linux, Python hors limites, groupes `aix` et `legacy`, `cmdb_force_shell`, ou échec en cours de collecte moderne, dont la trace reste dans `<run_id>.error.json`), sans rien changer à l'inventaire, et `collect_legacy.yml` y va directement (voir « Systèmes anciens et très anciens »).

## Utilisation

```bash
# 1. Collecte : un passage par application et par plate-forme (étiquetage obligatoire)
#    collect.yml vise tout l'inventaire et choisit la méthode hôte par hôte (AIX et Linux
#    anciens compris) ; collect_legacy.yml vise directement les groupes "legacy" et "aix"
ansible-playbook collect.yml        -i inventaires/appdemo-prod.yml -e cmdb_app=APPDEMO -e cmdb_platform=prod
ansible-playbook collect_legacy.yml -i inventaires/appdemo-prod.yml -l aix -e cmdb_app=APPDEMO -e cmdb_platform=prod

# 2. Consolidation : quand on veut, sur tout ce qui a été collecté
ansible-playbook consolidate.yml
#    ou directement :
python3 tools/cmdb_build.py --store store --out build

# Essai local
ansible-playbook -i inventory/local.yml collect.yml -e cmdb_app=ESSAI -e cmdb_platform=local
```

Paramètres principaux (`roles/cmdb_collect/defaults/main.yml`) :

| Variable | Défaut | Rôle |
|---|---|---|
| `cmdb_app`, `cmdb_platform` | (obligatoires) | Application et plate-forme du passage (voir ci-dessous) |
| `cmdb_tags` | `{}` | Étiquettes libres recopiées dans chaque collecte, ex. `{"site": "Paris"}`. En ligne de commande : `-e cmdb_tags=site=Paris,squad=S3` |
| `cmdb_store` | `store/` | Magasin des collectes sur le contrôleur |
| `cmdb_lot` | false | Produire un lot transférable du passage (`store/_lots/<run_id>.tar.gz`) |
| `cmdb_scan_max_seconds` | 900 | Budget du parcours disque ; au-delà, résultat partiel signalé (`fs_scan_truncated`) |
| `cmdb_scan_roots` | `[]` (= `/`) | Limiter le parcours à certaines racines |
| `cmdb_scan_extra_excludes` | `[]` | Exclusions supplémentaires (gros volumes de données, maildirs…) |
| `cmdb_include_network_fs` | false | Parcourir aussi NFS/CIFS/GPFS… |
| `cmdb_include_container_storage` | false | Parcourir `/var/lib/docker`, `/var/lib/containers`… |
| `cmdb_exec_probes` | true | Exécuter les sondes de version (`java -version`, `php -v`…) |
| `cmdb_hash_archives` | true | SHA-1 des `.jar/.war/.ear` (identification exacte) |
| `cmdb_pending_updates` | false | `dnf/yum updateinfo --with-cve`, `apt-get -s`, `debsecan` (peut contacter les dépôts) |

## Applications et plates-formes : collecte et consolidation découplées

**Étiquetage.** Chaque passage indique l'application et la plate-forme, par `-e cmdb_app=… -e cmdb_platform=…` ou dans l'inventaire de l'application (`group_vars`). Un passage sans étiquetage valide est refusé avant toute connexion aux cibles. Valeurs autorisées : lettres, chiffres, `.`, `_`, `-`, sans espace (64 caractères au plus). Des étiquettes libres s'ajoutent par `cmdb_tags`, sous l'une de ces formes : `-e cmdb_tags=squad=S3,site=Paris`, `-e '{"cmdb_tags": {"squad": "S3"}}'`, ou dans l'inventaire. Pas d'espace dans `cmdb_tags=…` : Ansible couperait la valeur. Un `-e` remplace les étiquettes de l'inventaire au lieu de s'y ajouter. Dans le rapport, chaque clé d'étiquette devient une colonne triable de la liste des serveurs, et le sélecteur « Étiquette » restreint tout le rapport aux serveurs concernés ; un lien ou un flux reste affiché si l'un de ses deux côtés est retenu. Le dossier d'application les affiche aussi.

Les étiquettes sont **écrites dans chaque collecte** (`meta.tags`, avec l'identifiant de passage `meta.run_id`), pas seulement dans le chemin du fichier : un fichier déplacé, renommé ou transmis reste correctement rattaché. Toutes les tables de la base portent les colonnes `app` et `platform` ; un serveur est identifié par le triplet (application, plate-forme, hôte). Un serveur mutualisé collecté pour deux applications apparaît donc deux fois, une fois par application, et sa fiche dans le rapport renvoie vers l'autre.

**Magasin des collectes** (`store/` par défaut, `cmdb_store` pour le changer) :

```
store/
├── APPDEMO/prod/aixprd01/20261105T090000Z-1a2b.json.gz   # une collecte par passage (historique)
│                        /latest.json.gz                  # la plus récente
│                        /20261105T090000Z-1a2b.ansible_facts.json
├── APPDEMO/prod/aixprd01/…error.json                     # trace d'échec, le cas échéant
├── _runs/20261105T090000Z-1a2b/_run.json                 # manifeste du passage : en-tête…
│                              /APPDEMO__prod__aixprd02.json  # …et statut de chaque hôte
└── _lots/20261105T090000Z-1a2b.tar.gz                    # lot transférable (cmdb_lot=true)
```

Le manifeste du passage enregistre le statut de **chaque hôte visé**, y compris ceux qui étaient injoignables ou en échec (`ok`, `failed`, `unreachable`). Le rapport signale ainsi un serveur non collecté au dernier passage, dont la fiche affichée est plus ancienne. Un hôte en échec reste en échec dans le récapitulatif d'Ansible, après l'écriture du manifeste.

**Consolidation.** `consolidate.yml` (ou `tools/cmdb_build.py`) lit un ou plusieurs magasins et des lots, et garde pour chaque triplet la collecte la plus récente :

```bash
# Tout ce qui a été collecté depuis ce contrôleur, plus des lots reçus d'autres plates-formes
python3 tools/cmdb_build.py --store store --lot '/depot/lots/*.tar.gz' --out build

# Une application, ou une plate-forme (motifs glob, options répétables)
python3 tools/cmdb_build.py --store store --app APPDEMO --platform 'prod*' --out build-appdemo
```

Quand les plates-formes ne sont pas joignables depuis un même contrôleur, chaque passage lancé avec `-e cmdb_lot=true` produit une archive unique, que l'on transfère et que la consolidation lit sans l'extraire. Les anciennes collectes non étiquetées (`output/raw/<hôte>/`) restent lisibles : elles sont rangées sous l'application et la plate-forme `NA` (ou celles données par `--default-app` et `--default-platform`).

`collect.yml` et `collect_legacy.yml` n'enchaînent plus la consolidation, sauf demande explicite (`-e cmdb_build=true`).

## AIX

`collect_legacy.yml` reconnaît AIX (`uname -s`) et y emploie le collecteur shell, exécuté par `/bin/sh` (ksh), **sans root**. Aucun module Ansible ni Python n'est requis sur la cible. Ce qui est relevé :

| Domaine | Commandes (sans privilège) |
|---|---|
| Système | `oslevel -s` (niveau technologique et service pack), `uname -a/-L/-p`, `lparstat -i`, `prtconf`, `lsattr -El sys0`, `instfix -i` |
| Matériel | `lsdev -C`, `lscfg -vp` (emplacements, références, firmwares, WWPN), `lsattr -El` de chaque disque, carte et interface, `lspv`, `lsps -a` |
| Stockage | `df -k`, `mount` : points de montage, types (jfs2, nfs…), tailles |
| Logiciels | `lslpp -Lcq` (tous les filesets installp), `lslpp -f` (index fichier → fileset), RPM de l'AIX Toolbox, `emgr -lv3` (correctifs provisoires : souvent réservé à root, alors vide) ; produits IBM : WebSphere, IHS et greffons (`*.product`), Db2 (`db2ls`), MQ (`dspmqver`) |
| Processus, réseau | `ps -e -o`, `ifconfig -a`, `netstat -in/-rn/-an` (EtherChannel et VLAN via les attributs des cartes `ent`), `lssrc -a` (services SRC) |
| Fichiers | Même parcours que sur Linux (JDK IBM, jars, applications…) ; les binaires XCOFF sont reconnus |

Le contrôleur convertit ces sorties au format commun : système `aix` avec version (`7.3`) et niveau (`7300-02-01-2346`), matériel (modèle, numéro de série, firmware, partition), interfaces avec leur MAC, disques, HBA Fibre Channel, filesets en table `packages` (gestionnaire `lslpp`), etc. Sans root, les ports en écoute sont relevés sans le processus propriétaire.

**FLRTVC.** Pour chaque hôte AIX, la consolidation écrit `build/flrtvc/<app>__<pf>__<hôte>.lslpp.txt` (sortie de `lslpp -Lcq`) et, si la collecte a pu lire les correctifs provisoires, `….emgr.txt` (sortie de `emgr -lv3`). Ce sont les deux fichiers d'entrée de l'outil IBM FLRT Vulnerability Checker en ligne, qui en tire la liste des filesets vulnérables et des bulletins de sécurité correspondants. Sans `emgr.txt`, les correctifs provisoires installés ne sont pas pris en compte et le rapport FLRTVC peut signaler à tort des vulnérabilités déjà corrigées par un ifix.

**Validation.** La branche AIX a été mise au point dans un environnement simulé (commandes AIX reproduites d'après leurs formats de sortie usuels, exécution sous ksh93 et sous un compte non privilégié). Elle doit être validée sur un vrai serveur AIX avant généralisation, en particulier les formats de `lscfg -vp`, `netstat -an` et `lslpp -f` selon les niveaux 7.1 à 7.3.

## Systèmes anciens et très anciens

`collect_legacy.yml` ne fait exécuter aucun module Ansible sur la cible : le collecteur est transféré et lancé par le module `script`, qui n'a besoin que de SSH et d'un shell, et son résultat revient par stdout (gzip + base64). Le playbook choisit le collecteur hôte par hôte :

| Systèmes typiques | Python présent | Collecteur utilisé |
|---|---|---|
| RHEL 8 (`platform-python` 3.6), RHEL/CentOS 7, Debian 7 à 9, SLES 12 | 3.6 ou 2.7 | `cmdb_collector.py`, collecte complète |
| RHEL/CentOS 6, Debian 6, SLES 11 | 2.6 | `cmdb_collector.py`, collecte complète (repli optparse) |
| RHEL/CentOS 4 et 5, SLES 9 et 10, Debian ≤ 5, installations sans Python | 2.3 à 2.5, ou aucun | `cmdb_collector.sh` |

Debian 7 fournit Python 2.7.3 : elle relève donc du collecteur Python. `-e cmdb_force_shell=true` (ou la variable posée sur un hôte ou un groupe) impose le collecteur shell.

**Le collecteur shell** (`cmdb_collector.sh`) fonctionne avec bash 3, dash ou busybox et les seuls outils des systèmes des années 2000 (`find`, `sed`, `awk`, `grep`, `dd`, `tar`, `gzip`). Il ne fait aucune interprétation : il entasse les sorties de commandes et des copies tronquées des fichiers utiles (`METADATA`, `package.json`, `installed.json`, `version.php`, fichiers `release` des JDK, en-têtes des bibliothèques JS…). Le contrôleur (`cmdb_shell_parse.py`) rejoue ensuite dessus **les mêmes règles** que le collecteur Python. Le résultat a donc le même format et passe dans la même consolidation. Différences avec le collecteur Python :

- **Archives Java** : inspection complète, archives imbriquées et classes sentinelles comprises, si un Python 2 quelconque est présent (de 2.3 à 2.7 ; c'est toujours le cas sur RHEL/CentOS ≤ 7, dont `yum` est écrit en Python). Sinon, `unzip` lit le premier niveau seulement (les jars imbriqués sont listés et identifiés par leur nom de fichier). À défaut d'`unzip`, seuls le chemin, la taille et le SHA-1 sont relevés.
- **Sondes de version** : une quarantaine, sans les outils récents (Go, conteneurs, Kubernetes). Seuls les binaires ELF appartenant à root dans une arborescence non modifiable par d'autres sont exécutés ; les autres sont listés mais ignorés (pas d'exécution sous l'identité du propriétaire).
- **Non collectés** : binaires Go, conteneurs.
- **Délais** : chaque commande a un délai maximal sans dépendre de `timeout` (absent des vieux coreutils). Au-delà, toute l'arborescence de processus de la commande est tuée. `df` est limité aux systèmes de fichiers locaux. Un appel système bloqué sur un montage réseau figé ne peut en revanche être interrompu par personne : la tâche Ansible porte donc un `timeout` global (`cmdb_task_timeout`, 3 600 s par défaut).

**Connexion SSH.** Les clients OpenSSH récents refusent par défaut les algorithmes des vieux serveurs (OpenSSH 3.9 sur CentOS 4, 4.3 sur CentOS 5, 5.3 sur CentOS 6, 6.0 sur Debian 7) : échange de clés en SHA-1, clés RSA signées en SHA-1, chiffrements CBC. `inventory/hosts.yml` donne les options à ajouter par groupe (`ansible_ssh_common_args`). Deux points à vérifier sur le contrôleur :

- **Politique cryptographique.** Sur un contrôleur RHEL 9 ou équivalent, la politique cryptographique système peut refuser les signatures SHA-1 quelles que soient les options SSH. Prévoyez alors un contrôleur ou un bastion dédié à ces hôtes, plutôt que d'abaisser la politique du poste habituel.
- **Clé SSH du compte de collecte.** Elle doit être de type RSA : les clés ed25519 ne sont reconnues qu'à partir d'OpenSSH 6.5.

**Croisement CVE pour ces systèmes.** Les bases de vulnérabilités des scanners ne couvrent généralement plus les distributions en fin de vie depuis longtemps. Vérifiez la couverture de votre outil : à défaut, ces paquets ne peuvent être évalués qu'au regard des versions amont (CPE), avec le risque de faux positifs lié aux rétroportages. En pratique, l'inventaire sert surtout ici à prioriser : ce qui est exposé (`v_listening_detail`), ce qui tourne réellement, ce qui contient des composants critiques (`v_java_risky`).

## Collecte sans élévation de privilèges

Les playbooks n'utilisent ni sudo ni `become` : tout s'exécute sous le compte de connexion. Les collecteurs détectent seuls qu'ils ne sont pas root et s'adaptent. La table `hosts` indique pour chaque collecte le compte utilisé (`privileged`, `collect_user`) et ce qu'il a pu voir (`processes_visible`, `processes_exe_readable`, `fs_unreadable_dirs`).

| Information | Sans root | Remarque |
|---|---|---|
| Paquets rpm/dpkg/apk, index fichier → paquet | complète | Bases de paquets lisibles par tous |
| Noyau, OS, CPU (vulnérabilités matérielles comprises), mémoire, montages et occupation des systèmes de fichiers | complète | |
| Binaires et bibliothèques système, JDK, jars, paquets Python/npm/composer… | **répertoires lisibles uniquement** | Un répertoire applicatif en `750` d'un autre compte est invisible |
| Processus : ligne de commande, utilisateur, PID parent | complète | Sauf si `/proc` est monté avec `hidepid` (indiqué dans `meta.visibility`) |
| Processus : exécutable, bibliothèques chargées, fichiers ouverts, environnement | **processus du compte de collecte uniquement** | Restriction du noyau sur les processus des autres comptes |
| Ports en écoute | port et compte propriétaire | Sans le nom du processus |
| Numéro de série, `dmidecode`, `sshd -T`, règles de pare-feu, sudoers, crontabs des utilisateurs | non | Réservé à root |

**Installations hors des chemins standard** (une JVM dans `/XXXX/bin/java`, un Apache compilé maison, un Tomcat déposé à la main). Elles sont retrouvées par plusieurs voies indépendantes :

1. **Le parcours du disque**, qui ne se limite pas aux chemins connus. Tout fichier `release` de JDK, toute archive Java (`catalina.jar` donne la version de Tomcat), tout binaire portant un nom connu (`java`, `httpd`, `nginx`, `php`…), où qu'il soit, est relevé.
2. **Les processus en cours**, pour ce qui tourne mais échappe au parcours : montage NFS, répertoire exclu, budget de temps dépassé, binaire renommé. La ligne de commande, lisible pour tous les processus, donne :
   - le binaire lancé ; un lanceur `…/bin/monappli` mène à la JVM via son fichier `release` ou son `rt.jar` ;
   - les jars du classpath (y compris `lib/*`) ;
   - les répertoires `-Dcatalina.home`, `-Dcatalina.base`, `-Djboss.home.dir` et `-Djava.home`.

   Ces fichiers sont ensuite inspectés comme ceux du parcours, s'ils sont lisibles.
3. **Les empreintes statiques.** La version est lue dans le binaire sans l'exécuter : chaînes `Apache/2.4.x`, `nginx/1.x`, `X-Powered-By: PHP/x` (y compris un `mod_php` sans binaire `php`), OpenSSL compilé statiquement. C'est ce qui permet de dater un binaire qu'on refuse d'exécuter.
4. **En root ou pour les processus du compte de collecte seulement** : bibliothèque JVM chargée (lanceurs renommés sans répertoire `bin`), archives réellement ouvertes, binaire supprimé du disque mais encore en mémoire (lu via `/proc/PID/exe`), processus des conteneurs.

Ce qui reste hors de portée sans root : un binaire ou un répertoire applicatif illisible pour le compte de collecte, et un binaire supprimé du disque appartenant à un autre compte. Pour couvrir les répertoires applicatifs sans donner de droits d'administration, la piste habituelle est un droit de **lecture seule** pour le compte de collecte (groupe applicatif ou ACL `setfacl -R -m u:<compte>:rX`). C'est une décision à prendre avec les responsables des applications et la sécurité.

## Ce qui est collecté

Certaines informations ci-dessous exigent root et manquent donc en collecte non privilégiée (voir la section précédente).

| Domaine | Contenu | Utilité pour les CVE |
|---|---|---|
| Système | os-release, noyau, glibc, SELinux, machine-id, uptime, reboot requis, `needs-restarting -r` | Noyau en cours vs installé, redémarrage en attente |
| Systèmes de fichiers | Chaque point de montage : périphérique, type, options, taille totale, utilisée et libre (Go et %), occupation des inodes | Saturation, montages réseau |
| Matériel | Constructeur, modèle, BIOS, carte mère, châssis (DMI), série et barrettes mémoire (`dmidecode`, root), topologie CPU (sockets, cœurs, threads, `lscpu`), mémoire, périphériques PCI (`lspci`, avec pilote), disques (modèle, série, WWN, transport, rotatif/SSD), HBA Fibre Channel (WWPN/WWNN), montages, virtualisation | **`/sys/devices/system/cpu/vulnerabilities/*`** (Spectre, MDS…), firmwares et pilotes |
| Paquets | rpm (avec SOURCERPM, éditeur, signature), dpkg (avec paquet source), apk, pacman, snap, flatpak ; dépôts ; modules DNF ; alternatives | Base des correspondances avec les avis de sécurité de la distribution |
| Propriété des fichiers | Index fichier → paquet (rpm/dpkg/apk) | Distinguer ce qui est **géré par la distribution** de ce qui ne l'est pas |
| Sondes de version | Près de 80 sondes : java (`-XshowSettings`), python (+OpenSSL lié), php (`-v`, `-m`, `-i` filtré), php-fpm, node (`process.versions`), ruby, perl, go, dotnet, postgres, mysqld/mariadbd, mongod, redis, nginx (`-V`), httpd, haproxy, openssl, openssh, sudo, curl, docker, containerd, runc, kubelet, ImageMagick, Ghostscript, ffmpeg, exiftool, xz, polkit… | Toutes les installations trouvées, pas seulement celle du PATH |
| Java | Toutes les archives `.jar/.war/.ear` du disque, **y compris imbriquées** (WEB-INF/lib, BOOT-INF/lib, EAR) : MANIFEST, `pom.properties`, SHA-1 ; classes sentinelles (JndiLookup log4j même **ombragé**, JMSAppender, InvokerTransformer…) ; JDK/JRE via le fichier `release` ; Tomcat via `ServerInfo.properties` | log4shell & co., dépendances embarquées invisibles du gestionnaire de paquets |
| Python | Tous les `*.dist-info` / `*.egg-info` (site-packages système, venvs, conda) | Paquets pip hors distribution |
| Node | `node_modules/*/package.json` (parcours optimisé), `package-lock.json` sans `node_modules`, `package.json` applicatifs | Dépendances npm |
| PHP | `vendor/composer/installed.json`, `composer.lock` ; WordPress, Drupal, Joomla, GLPI, Moodle, MediaWiki, Nextcloud, phpMyAdmin, SPIP, Dolibarr, Roundcube, LimeSurvey, Matomo, CodeIgniter, Zend Framework 1, Smarty, PHPMailer | Applications et frameworks déposés à la main |
| Autres écosystèmes | Gems Ruby, `*.deps.json` .NET, binaires Go (section `.go.buildinfo` : version de Go et modules), bibliothèques JS en vrac (jQuery, Bootstrap, AngularJS, Moment, TinyMCE…), `.so` hors répertoires système (OpenSSL/curl/zlib embarqués) | Composants vendorisés |
| Données | Répertoires de données PostgreSQL (`PG_VERSION`) et MySQL/MariaDB, inventaire Oracle (`oratab`, `inventory.xml`, `comps.xml`) | Version réelle du cluster |
| Oracle | Pour chaque `ORACLE_HOME` (oratab, inventaire central, `olr.loc`, processus) : produit, version, édition, correctifs (`comps.xml`, `inventory/oneoffs`, `.patch_storage`), OPatch, listeners, `tnsnames.ora`, SID configurés | Niveau de correctif réel (voir « Oracle ») |
| Références de bases | Moteur, hôte, port et base trouvés dans les configurations applicatives. Jamais d'identifiant | Liens applicatifs (voir « Liens vers les bases ») |
| Modules | Directives de chargement d'Apache, IHS, nginx, PHP, PostgreSQL, Redis, MySQL ; `httpd -M`, `php -m`, `nginx -V` | Ce qui est réellement activé |
| Points d'entrée | Virtualhosts, connecteurs, contextes et proxys d'Apache, IHS, nginx, Tomcat, JBoss, HAProxy ; `.war` déployés | Ce que le serveur présente, et vers quoi il relaie |
| Clés et certificats | Tout fichier `.key`, `.pem`, `.crt`, `.p12`, `.jks`, `.keystore`, `.kdb`, `.sth`, `cwallet.sso`, `id_rsa`… : droits, propriétaire, protection ; DN, CN, SAN, dates, algorithmes des certificats | Voir « Clés et certificats » |
| Réglages PHP | `php -i` et `php-fpm -i` complets, sans l'environnement ni les secrets | Équivalent d'un `phpinfo()`, sans rien déposer sur le serveur |
| Processus | Ligne de commande (secrets masqués), exécutable et paquet propriétaire, utilisateur, unité systemd, conteneur, variables d'environnement utiles (liste blanche), bibliothèques chargées, **fichiers supprimés encore mappés**, archives Java ouvertes | Ce qui tourne réellement ; processus à redémarrer après correctif |
| Réseau | Interfaces avec MAC, MAC d'usine (même membre d'un agrégat), type (physique, bond, bridge, VLAN…), rattachements, débit, MTU, pilote, version et firmware (`ethtool -i`), carte PCI ; adresses **avec leur interface** et leurs alias ; routes, DNS, ports en écoute, connexions établies agrégées | Exposition, cartographie des flux, firmwares de cartes |
| Services | Unités systemd (ExecStart, utilisateur, état), timers, SysV, cron, `at` | |
| Sécurité | `sshd -T`, sudoers, iptables/nftables/firewalld, auditd, FIPS, politique crypto, lockdown | |
| Noyau | Modules chargés, `sysctl -a`, taint, livepatch (kpatch, Canonical) | Correctifs noyau appliqués à chaud |
| Conteneurs | docker/podman (info, conteneurs, images avec digests), crictl | Images à scanner séparément |
| Répertoires logiciels | Deux niveaux de `/opt`, `/usr/local`, `/srv`, `/app*`, `/u01`, `/var/www`… | Repérer à l'œil les installations manuelles |

## Sécurité et impact sur les serveurs

- **Lecture seule** : rien n'est modifié sur la cible hormis un répertoire temporaire supprimé en fin d'exécution. Le collecteur shell utilise `TMPDIR` s'il est défini. Sont en plus lus : les fichiers de configuration applicatifs (limités aux références de bases) et les fichiers de clés (seules les métadonnées sont retenues). Priorité basse (`nice 19`, `ionice` idle), budget de temps sur le parcours disque, pas de descente dans les systèmes de fichiers réseau ni dans les données de bases (PostgreSQL, MySQL), les dépôts Git ou les caches `.m2/.gradle/.npm`.
- **Exécution de binaires** : seuls les ELF (et une courte liste de scripts appartenant à un paquet) dont le nom correspond à une sonde connue sont exécutés, avec un environnement propre, et **seulement si le binaire et tous ses répertoires parents sont sous le contrôle de root** (ou du compte de collecte lui-même) et non modifiables par d'autres. Un binaire déposé par un autre compte n'est jamais exécuté, puisqu'il ferait tourner son code sous l'identité du compte de collecte ; sa version est alors lue par empreinte statique. Un lien symbolique homonyme vers un autre programme n'est pas suivi. (Si le collecteur est un jour lancé en root hors de ces playbooks, un binaire non fiable est exécuté sous l'identité de son propriétaire, jamais en root.)
- **Secrets** : les mots de passe, jetons et identifiants dans les URL sont masqués (`***`) dans les lignes de commande, `ExecStart`, crontabs, fichiers de dépôts et `profile.d`. Les variables d'environnement des processus sont filtrées par liste blanche (`JAVA_HOME`, `CATALINA_HOME`, `PATH`…). Le masquage est heuristique : **les fichiers produits restent sensibles** (comptes, sudoers, règles de pare-feu, cartographie réseau) et doivent être protégés et classifiés en conséquence.

## Oracle

Aucune connexion aux bases et aucune exécution d'`opatch` : il appartient au compte `oracle`, il échapperait donc à la règle d'exécution ci-dessus, et il écrit dans `cfgtoollogs`. Seuls des fichiers sont lus.

Le collecteur tourne sous un compte non privilégié : ce qu'il voit dépend des droits sur chaque serveur. La colonne `visibility` de `oracle_homes` l'indique :

| Valeur | Sens |
|---|---|
| `complet` | `comps.xml` lisible : liste complète des correctifs. Ajouter le compte de collecte au groupe `oinstall` donne en général ce niveau |
| `partiel` | Seuls les noms de répertoires des correctifs sont visibles : numéros connus, descriptions absentes |
| `aucun` | `ORACLE_HOME` illisible ; la version est déduite du chemin. Le rapport affiche « non visible » plutôt qu'un niveau faux |

- **Niveau de correctif** (`patch_level`) : la Release Update, le PSU ou le Bundle Patch le plus récent, avec sa date tirée du numéro de version. `behind_fleet` signale un home plus ancien qu'un autre de la même branche sur le parc. Oracle n'étant pas couvert par les scanners de SBOM, cette comparaison remplace le croisement CVE ; `famille:oracle-database <19.23` fonctionne dans la recherche du rapport.
- **Limite importante** : un binaire corrigé ne prouve pas que `datapatch` a été passé sur la base. Seule une requête SQL pourrait le vérifier, et l'outil n'en fait aucune.
- **Instances** (`db_instances`) : `oratab` confronté aux processus `*_pmon_*`, soit démarrée, arrêtée, ou démarrée hors `oratab`. Rôle standby déduit de `mrp0`/`pr00`, RAC de `lms0`, Grid de `ocssd`. Avec `hidepid`, l'état est « inconnu ». PostgreSQL, MySQL, MongoDB et Redis y figurent aussi.
- **Licences** (`oracle_licence`) : édition, cœurs, partitionnement, estimation avec les facteurs de cœur x86 (0,5) et POWER (1,0). **Purement indicatif** : les options utilisées ne sont pas visibles sans SQL, et une VM ne dit rien du cluster qu'Oracle peut exiger de licencier. L'édition est lue dans l'inventaire ; la vérifier.

## Liens vers les bases

La table `db_links` répond à « quels serveurs utilisent cette base ? » et « de quelles bases dépend cette application ? ». Elle couvre Oracle, PostgreSQL, MySQL/MariaDB, SQL Server, DB2, MongoDB, Redis, pgbouncer et pgpool, en combinant :

| Source | Apporte | Limite |
|---|---|---|
| Connexions établies, côté client et côté serveur | Ce qui se passe réellement, y compris les clients hors inventaire | Photo de l'instant de la collecte |
| Titres des processus PostgreSQL (`postgres: compte base 10.0.0.5(4500) idle`) | Base, compte et client, sans se connecter ; réplication via `walsender` | Invisible avec `hidepid` |
| Configurations applicatives | Les liens inactifs au moment du passage | Une configuration peut être obsolète |
| Alias TNS et `tnsnames.ora` | Résolution d'un `jdbc:oracle:thin:@ALIAS` | Le fichier doit être sur le serveur client |
| Lignes de commande | `-Dspring.datasource.url=jdbc:...` | |

`status` vaut `actif` si le lien a été observé, `configuré` s'il n'existe que dans un fichier. Un client ou un serveur hors de l'inventaire est conservé avec son adresse. Les noms sont résolus depuis la cible (`getent`, 40 noms et 30 secondes au plus, collecteur Python) ou par `/etc/hosts` ; le collecteur shell ne résout pas, et un alias DNS inconnu reste alors « hors inventaire ». Un même IP privé sur deux plates-formes est rattaché de préférence à la plate-forme du client.

Formats reconnus : JDBC (PostgreSQL, MySQL, MariaDB, Oracle sous toutes ses formes, SQL Server, DB2), URI (`postgres://`, SQLAlchemy, `mongodb://`, `redis://`), PDO, libpq, ADO.NET, `.env` et variables `DB_*`/`PG*`, WordPress, Rails, Django, ODBC, `pg_service.conf`, `my.cnf`, pgbouncer, `tnsnames.ora`, descripteurs Oracle en ligne.

**Secrets** : seuls moteur, hôte, port et base sortent du serveur. Le collecteur Python n'en retient rien d'autre ; le collecteur shell, qui n'interprète pas, expurge ces fichiers sur le serveur avant de les transmettre. Les tests vérifient qu'un mot de passe placé dans chaque format n'apparaît ni dans l'archive ni dans le JSON. Fichiers lus : 256 Ko au plus, 20 000 fichiers au plus ; les répertoires d'exemples, de tests et de dépendances sont ignorés.

## Services réseau

- **Points d'entrée** (`endpoints`) : virtualhosts, ports, TLS, certificat, racine, alias et cibles de proxy. `listening` indique si le port est réellement en écoute. Les directives `Include` ne sont pas suivies : les fichiers sont trouvés par leur emplacement habituel (`sites-enabled`, `conf.d`, `vhosts.d`).
- **Langages exposés** (`runtime_services`) : pour chaque port en écoute, le langage qui répond (Java, Python, Node, PHP, Ruby, Perl, .NET), sa version, l'application (classe principale, jar, script) et les options de JVM.
- **Modules** (`service_modules`) : `source` précise la configuration ou la commande. Les directives entourées de `<IfModule>` sont comptées comme actives.
- **Réglages PHP** (`runtime_settings`) : tout `php -i` et `php-fpm -i`. `php-fpm -i` reflète la configuration du service, là où `php -i` reflète celle de la ligne de commande. Une configuration propre à un virtualhost (`php_admin_value`, `.user.ini`) n'y figure pas : aucune page `phpinfo()` n'est déposée ni appelée.

## Clés et certificats

Tout fichier repéré figure dans `crypto_files`, même illisible, hors magasins de confiance du système (`/etc/ssl/certs`, `ca-trust`, `certifi`).

| Format | Sans mot de passe, on obtient |
|---|---|
| PEM, DER | Certificats complets ; présence d'une clé, type, chiffrée ou non |
| JKS, JCEKS | Alias et certificats (en clair dans ces formats) ; collecteur shell : uniquement si `keytool` est présent |
| PKCS#12 | **Mot de passe vide uniquement** via `openssl`, aucun autre n'est essayé. Un succès est une anomalie signalée. Sinon : « protégé par un mot de passe » |
| Clés OpenSSH, PuTTY | Type, chiffrée ou non |
| GSKit `.kdb`, `.sth`, portefeuille Oracle `.sso` | Mentionnés. `.sth` et `.sso` signalés : ils donnent accès sans mot de passe |

`cert_usage` relie chaque service (virtualhost Apache ou nginx, connecteur Tomcat, frontal HAProxy) à son certificat : état (`expiré`, `à renouveler` sous 30 jours, `valide`, `illisible`, `non inventorié`) et `name_match`, qui signale un certificat ne couvrant pas le nom du virtualhost. `v_certs_shared` liste les certificats présents sur plusieurs serveurs : leur clé y est donc aussi, et son renouvellement les concerne tous. Le rapprochement se fait par empreinte du certificat, jamais de la clé.

Le contenu d'une clé n'est jamais conservé ni transmis. Le collecteur shell n'en lit que l'en-tête et ne copie que les blocs `CERTIFICATE`. Alertes : `v_private_keys_exposed` (lisible par tous, ou PKCS#12 sans mot de passe), `v_certs_expiring` (moins de 90 jours). Une clé en clair lisible par son seul propriétaire n'est pas une alerte : c'est le cas normal d'un serveur web.

## Carte des flux

`app_flows` relie les serveurs entre eux, à partir des liens vers les bases (`base`, `réplication`), des proxys déclarés dans Apache, nginx et HAProxy (`proxy`), des montages NFS et CIFS (`stockage`), des disques SAN vus par plusieurs serveurs (`disque partagé`, d'après leur WWN) et des connexions observées (`réseau`, à l'exclusion des ports d'infrastructure : SSH, DNS, NTP, supervision…). Le rapport dessine la carte ; un clic sur un serveur montre ce qui est touché s'il s'arrête et ce dont il dépend. `build/graphes/<app>__<pf>.dot` donne le même graphe pour Graphviz (`dot -Tsvg`).

Un flux rare (traitement mensuel, sauvegarde) peut être absent d'une photo de l'instant : l'absence de flux ne prouve pas l'absence de dépendance. La réplication et les disques partagés n'entrent pas dans l'analyse d'impact : ils ne disent pas qui dépend de qui. Un serveur NFS hors inventaire reste visible. Un WWN vu par plus de 16 serveurs est ignoré, et un hyperviseur qui réutilise un même identifiant peut créer de faux partages. Au-delà de 150 serveurs, le rapport demande de choisir une application.

## Écarts

`drift` compare, sans nouvelle collecte, les versions de composants, le système, les niveaux de correctifs Oracle, les modules, les réglages PHP et les contrôles de durcissement :

- **entre plates-formes** d'une même application, deux à deux (par exemple prod et recette) ;
- **entre serveurs jumeaux** d'une même plate-forme : ceux qui ont les mêmes ports d'écoute et les mêmes moteurs. Au-delà de deux, un serveur est comparé à la majorité du groupe.

Les jumeaux sont déduits, pas déclarés : deux serveurs de rôles différents mais de même profil peuvent être rapprochés. `tools/cmdb_drift_ignore.txt` retire les écarts assumés.

## Durcissement

Contrôle des collectes selon le guide **ANSSI-BP-028 v2.0** (*Recommandations de configuration d'un système GNU/Linux*), sans rien exécuter de plus sur les serveurs.

**Ce n'est pas un audit de conformité.** Seules 18 recommandations sur 80 sont contrôlées, dont 9 entièrement : paramètres noyau (R8, R9, R11, R12, R14), partitionnement (R28), sudo (R39, R40, R42, R43), SELinux et AppArmor (R45, R46), mises à jour, services hérités, journalisation (R33, R61, R62, R71, R73, R74). Le mot de passe de démarrage, la politique de mots de passe, les droits des fichiers sensibles, les options de compilation du noyau et bien d'autres ne le sont pas, faute de données. L'onglet « Couverture du guide » du rapport le détaille pour les 80, comme `tools/cmdb_anssi_recos.csv`.

- **Score** : conformes / (conformes + non conformes), pour chaque niveau du guide (minimal, intermédiaire, renforcé, élevé), chaque niveau incluant les précédents. Le niveau à viser dépend du système : le guide ne demande pas à tous d'atteindre « élevé ».
- **Non vérifiable** : donnée absente, en général faute de droits (`sudoers` et `sshd -T` exigent souvent root ; le collecteur shell ne relève pas `hidepid`). Un tel contrôle est exclu du score et compté à part : une collecte non privilégiée peut donc afficher un score flatteur sur peu de contrôles. Regarder aussi cette colonne.
- **Faux positifs assumés** : `ip_forward=1` est normal sur un hôte de conteneurs ; une règle sudo `(ALL)` est fréquente pour les administrateurs ; `/proc` en `hidepid` rend les processus invisibles à la collecte elle-même. Écart à justifier, ou ligne à retirer de `tools/cmdb_anssi_rules.csv`.
- **AIX** : hors périmètre, ce guide ne concerne que Linux.
- **Provenance** : recommandations, niveaux et correspondance avec les contrôles relevés dans le projet ComplianceAsCode (`controls/anssi.yml`, 5 novembre 2026). Les valeurs attendues n'ont pas été comparées ligne à ligne au PDF de l'ANSSI, à faire avant tout usage officiel. Les réglages détaillés d'OpenSSH relèvent d'un autre guide ANSSI et ne sont pas contrôlés, hormis la connexion directe en root (R33).

## Dossier d'application

`build/dossiers/<app>__<pf>.html` : un fichier autonome et sans script par application et plate-forme, regroupant points d'attention, serveurs, schéma d'architecture, bases, points d'entrée, certificats et clés, composants, fins de support, durcissement et écarts. Il s'imprime ou s'enregistre en PDF depuis le navigateur. Le rapport y renvoie quand une application et une plate-forme sont choisies, à condition que le répertoire `dossiers/` soit resté à côté de lui.

À la différence du rapport, il **ne contient que son périmètre** : un serveur d'une autre application n'y figure que par son lien avec celui-ci. Il peut donc être remis à un tiers sans donner le reste du parc, après relecture : il reste sensible (chemins de clés, adresses, faiblesses). `--dossier-mention "Diffusion restreinte"` porte la mention de votre choix en tête de document ; `--no-dossiers` désactive leur production.

## Évolutions

Le magasin garde chaque collecte : `cmdb_build.py` compare les deux dernières de chaque serveur et alimente `changes` (paquets, composants, ports, comptes, correctifs Oracle, instances, modules, points d'entrée, clés). Ce qui apparaît avec une nouvelle version du collecteur n'est pas compté comme une évolution. `--no-history` désactive la comparaison.

## Fins de support

`tools/cmdb_eol.csv` donne les dates par produit et par cycle : `eol_status` les applique aux systèmes et composants, `v_eol_expired` liste les dépassements. Ce fichier est un relevé de <https://endoflife.date> du 5 novembre 2026, à tenir à jour et à confirmer auprès des éditeurs. Pour un composant issu d'un paquet de distribution (`managed = 1`), la date amont est indicative : le support suit celui du système, et le rapport n'en fait pas une alerte.

## Résultats de la consolidation (`build/`)

| Fichier | Contenu |
|---|---|
| `cmdb_rapport.html` | **Rapport consolidé interrogeable** : un fichier unique, hors ligne (voir ci-dessous) |
| `cmdb.sqlite` | Base complète, y compris les documents bruts (`raw_documents`, interrogeables avec `json_extract`) |
| `runtimes_matrix.csv` | Une ligne par (application, plate-forme, hôte), une colonne par composant (noyau, glibc, openssl, java, php, python, postgresql, nginx, tomcat, log4j-core, wordpress…). **`*` = installation hors paquet de la distribution** |
| `csv/*.csv` | Chaque table et vue (séparateur `;`) |
| `dossiers/<app>__<pf>.html` | Dossier d'application, autonome et limité à son périmètre |
| `graphes/<app>__<pf>.dot` | Carte des flux pour Graphviz |
| `flrtvc/<app>__<pf>__<hôte>.lslpp.txt` | AIX : entrée de l'outil IBM FLRTVC (voir « AIX ») |
| `sbom/<app>__<pf>__<hôte>.cdx.json` | SBOM CycloneDX 1.5 (propriétés `cmdb:app` et `cmdb:platform`) : paquets OS (purl avec qualificatif `distro`) + composants non gérés par la distribution (purl maven/pypi/npm/composer/gem/golang/nuget, CPE pour les runtimes) |

Toutes les tables commencent par les colonnes `app`, `platform`, `host`. Tables principales : `hosts` (dont `run_id`, `tags`, `ip_addresses` au format `eth0=10.1.2.3/24 bond0.100=10.9.0.4/24`, `mac_addresses`, CPU, BIOS, châssis), `interfaces`, `addresses` (adresse, interface, alias, MAC), **`filesystems`** (point de montage, périphérique, type, `size_gb`, `used_gb`, `free_gb`, `used_pct`, `free_pct`, `inodes_used_pct`, `network`), `disks`, `pci_devices`, `fc_hosts`, `memory_modules`, `packages`, **`software`** (vue unifiée de tout ce qui a une version : `category`, `ecosystem`, `family`, `name`, `version`, `location`, `owner_pkg`, `managed`, `purl`, `cpe`), `java_markers`, `processes`, `listening`, `connections`, `services`, `containers`, `cpu_vulnerabilities`, `kernel_modules`, `accounts`, `probe_outputs` (sorties brutes des sondes), `runs` (statut de chaque hôte à chaque passage). Vues : `v_applications` (synthèse par application et plate-forme), `v_filesystems_full` (occupation ou inodes ≥ 90 %), `v_unmanaged_software`, `v_runtimes`, `v_java_risky`, `v_restart_needed`, `v_listening_detail`.

### Exemples de requêtes

Les pourcentages des systèmes de fichiers suivent la convention de `df` : `used_pct` = utilisé / (utilisé + disponible), la réserve de root étant exclue de l'espace libre. `free_gb` est l'espace réellement disponible pour les applications ; `size_gb` peut donc dépasser la somme de `used_gb` et `free_gb`.

```sql
-- Où trouve-t-on log4j-core, y compris imbriqué dans des WAR/fat JAR ? (filtrer ensuite sur la version)
SELECT host, version, location FROM software
WHERE family = 'log4j-core' ORDER BY version, host;

-- JndiLookup présent, même ombragé (renommé) dans une autre archive
SELECT * FROM v_java_risky;

-- Toutes les JVM, gérées ou non par la distribution
SELECT host, version, managed, location, json_extract(extra, '$.vendor') AS vendor
FROM software WHERE family = 'java' AND category = 'runtime';

-- Versions de PHP sur le parc (paquets + binaires réellement présents)
SELECT version, COUNT(DISTINCT host) AS nb_hotes FROM software
WHERE family IN ('php', 'php-fpm') GROUP BY version ORDER BY nb_hotes DESC;

-- Écart entre binaires PostgreSQL et version des données
SELECT host, family, version, location FROM software
WHERE family IN ('postgresql', 'postgresql-datadir') ORDER BY host;

-- Services exposés dont l'exécutable n'appartient à aucun paquet
SELECT host, port, process, exe FROM v_listening_detail
WHERE exe_managed = 0 AND address NOT IN ('127.0.0.1', '::1');

-- Processus utilisant encore une bibliothèque supprimée (correctif appliqué, pas redémarré)
SELECT * FROM v_restart_needed;

-- Java par application et plate-forme
SELECT app, platform, version, COUNT(DISTINCT host) AS nb_hotes FROM software
WHERE family = 'java' AND category = 'runtime' GROUP BY app, platform, version;

-- Systèmes de fichiers à plus de 85 % : taille, utilisé, libre
SELECT app, platform, host, mountpoint, size_gb, used_gb, free_gb, used_pct, free_pct
FROM filesystems WHERE used_pct >= 85 ORDER BY used_pct DESC;

-- Hôtes non collectés au dernier passage de leur application
SELECT * FROM runs r WHERE status != 'ok' AND started_at = (SELECT MAX(started_at) FROM runs x
  WHERE x.app = r.app AND x.platform = r.platform AND x.host = r.host);

-- Quelles applications utilisent cette base ?
SELECT client_host, client_addr, database, db_user, status, sources FROM db_links
WHERE server_host = 'pg01.exemple.test' ORDER BY status, client_host;

-- De quelles bases dépend une application ?
SELECT DISTINCT client_host, engine, COALESCE(server_host, server_addr) AS serveur, port, database, status
FROM db_links WHERE client_app = 'APPDEMO' AND client_platform = 'prod';

-- Niveau de correctif Oracle du parc
SELECT product, patch_level, COUNT(*) AS homes FROM oracle_homes GROUP BY product, patch_level ORDER BY patch_level;

-- ORACLE_HOME dont on ne connaît pas le niveau (droits insuffisants)
SELECT * FROM v_oracle_patch_unknown;

-- Tous les virtualhosts en TLS
SELECT host, product, server_name, port, cert FROM endpoints WHERE kind = 'vhost' AND tls = 1;

-- Certificats par expiration
SELECT host, cn, not_after, days_left, path FROM crypto_certs WHERE is_ca = 0 ORDER BY days_left;

-- Ce qui a changé sur un serveur
SELECT to_at, kind, change, item, before, after FROM changes WHERE host = 'web01.exemple.test';

-- Services dont le certificat expire sous 30 jours
SELECT host, server_name, port, cn, not_after, days_left FROM cert_usage WHERE days_left <= 30 ORDER BY days_left;

-- Certificats présents sur plusieurs serveurs
SELECT cn, hosts, host_list, not_after FROM v_certs_shared;

-- Serveurs dépendant d'un partage NFS
SELECT src_host, dst_host, dst_addr, detail FROM app_flows WHERE kind = 'stockage';

-- Qui appelle ce serveur ?
SELECT COALESCE(src_host, src_addr) AS source, port, kind, detail, status FROM app_flows WHERE dst_host = 'app01.exemple.test';

-- Écarts de composants entre prod et recette
SELECT item, left_value, right_value FROM drift
WHERE scope = 'plates-formes' AND app = 'APPDEMO' AND left_platform = 'prod' AND right_platform = 'recette' AND kind = 'composant';

-- Serveurs les moins durcis au niveau intermédiaire
SELECT app, platform, host, score, ok, ko, unknown FROM hardening_scores WHERE level = 'intermédiaire' ORDER BY score;

-- Contrôles les plus souvent en échec sur le parc
SELECT ref, title, non_conformes, non_verifiables FROM v_hardening_by_rule LIMIT 20;

-- Une information brute non modélisée : recherche dans le document JSON d'origine
SELECT host, json_extract(document, '$.security.crypto_policy') FROM raw_documents;
```

## Rapport HTML

`build/cmdb_rapport.html` est régénéré à chaque consolidation. C'est un fichier unique, sans aucune ressource externe : il s'ouvre par un double clic, y compris sur un poste sans accès Internet, et se transmet comme une pièce jointe. Les données y sont embarquées compressées. Il faut un navigateur récent (Firefox 113 et plus, Chrome ou Edge 80 et plus, Safari 16.4 et plus).

- **Périmètre** : deux listes dans le bandeau de gauche restreignent tout le rapport à une application et/ou une plate-forme. Le périmètre est conservé dans l'adresse de la page, qu'on peut donc mettre en favori ou transmettre.
- **Accueil** : la recherche, les chiffres du parc, la synthèse par application et plate-forme (serveurs, composants hors paquet, ports exposés, alertes, serveurs non collectés), ce qui est à traiter, la répartition des systèmes et des versions.
- **Logiciels** : recherche dans tout l'inventaire (paquets, runtimes, jars, pip, npm, composer, applications web…), avec filtres par nature et par gestion (paquet de distribution ou non), vue « une ligne par installation » ou « regrouper par version », export CSV.
- **Versions** : la matrice serveur × composant ; les installations hors paquet apparaissent en étiquettes ambre ; un clic sur une version liste les serveurs concernés.
- **Serveurs** et **fiche serveur** : synthèse (application, plate-forme, passage, matériel, BIOS, série, visibilité de la collecte), réseau (interfaces, IP, MAC, MAC d'usine, pilotes et firmwares), stockage (systèmes de fichiers avec jauge d'occupation, disques) et matériel, composants, ports et services, alertes.
- **Bases de données** : instances, liens applicatifs, `ORACLE_HOME`, correctifs, licences. **Services réseau** : points d'entrée, langages exposés, modules, réglages PHP. **Carte des flux** et analyse d'impact, **Durcissement**, **Écarts**, **Clés et certificats**, **Fins de support**, **Évolutions**. La fiche serveur reprend ces vues pour le serveur affiché.
- **Exposition**, **Matériel** (interfaces, systèmes de fichiers triés par occupation, disques, PCI, Fibre Channel, mémoire de tout le parc) et **Alertes**.

Syntaxe de recherche : les mots se combinent (ET) ; `<2.17.1`, `<=`, `>`, `>=`, `=` comparent la version ; `serveur:`, `app:`, `pf:`, `famille:`, `cat:`, `chemin:`, `paquet:`, `purl:` restreignent un champ. Exemples : `log4j-core <2.17.1`, `famille:java <11`, `php <8 serveur:web`, `chemin:/opt =5.4.2`. Une adresse IP ou MAC tapée dans la recherche retrouve le serveur.

Ordres de grandeur mesurés : 300 000 composants donnent un fichier de quelques mégaoctets, qui s'ouvre en moins d'une seconde, avec des recherches en un dixième de seconde. Pour alléger un très grand parc : `cmdb_build.py --report-exclude-categories go-module,npm-package` (les données restent complètes dans la base et les CSV) ; `--no-report` désactive le rapport.

Le rapport contient tout l'inventaire (comptes, ports, chemins, numéros de série) : il se protège et se classifie comme la base elle-même.

## Croiser avec les CVE

La règle essentielle : **ne jamais comparer la version d'un paquet de distribution aux plages de versions amont d'une CVE.** Red Hat, Debian, Ubuntu ou SUSE rétroportent les correctifs : un `openssl-1.1.1k-12.el8_9` est corrigé de CVE postérieures à la 1.1.1k. Il faut donc séparer les deux mondes, ce que permet la colonne `managed` :

1. **Composants gérés par la distribution** (`managed = 1`) : à confronter aux avis de l'éditeur (OVAL/CSAF Red Hat, Debian Security Tracker, USN). C'est ce que font Grype, Trivy ou Dependency-Track à partir des purl `pkg:rpm/…?distro=rhel-8.9` / `pkg:deb/…?distro=ubuntu-24.04` des SBOM. Sur RHEL, `-e cmdb_pending_updates=true` remonte en plus directement `dnf updateinfo list --with-cve`, c'est-à-dire la liste des CVE corrigées par des mises à jour disponibles mais non appliquées.
2. **Composants hors distribution** (`managed = 0` : JDK dans `/opt`, jars, pip, npm, composer, binaires Go, applications PHP) : à confronter aux bases amont via leur purl (OSV, GitHub Advisory) ou, à défaut, leur CPE (NVD). Les CPE sont **indicatifs** : le dictionnaire NVD change (nginx est passé de `nginx:nginx` à `f5:nginx`, etc.) ; la table `CPE_MAP` de `cmdb_build.py` est à ajuster.

Commandes (outils à installer sur un poste d'analyse, non testées dans cet environnement) :

```bash
grype sbom:build/sbom/APPDEMO__prod__web01.cdx.json
trivy sbom build/sbom/APPDEMO__prod__web01.cdx.json

# Dependency-Track : un projet par serveur, mis à jour à chaque collecte
curl -X POST "https://dtrack.exemple/api/v1/bom" -H "X-Api-Key: $DT_API_KEY" \
     -F "autoCreate=true" -F "projectName=APPDEMO-prod-web01" -F "projectVersion=courant" \
     -F "bom=@build/sbom/APPDEMO__prod__web01.cdx.json"
```

Pour AIX, les paquets installp n'ont pas d'équivalent dans les bases des scanners de SBOM : utilisez FLRTVC (fichiers `build/flrtvc/`, voir « AIX »).

Les images de conteneurs (table `containers`) sont à scanner séparément (`trivy image`, `grype <image>`), comme les composants des conteneurs rootless, invisibles depuis root.

## Limites connues

- Les fonctions Oracle, liens, modules, points d'entrée et clés ont été validées sur des fichiers et des collectes fabriqués, pas sur de vrais serveurs Oracle, Tomcat ou AIX : les formats d'inventaire Oracle viennent de la documentation et d'exemples, à confronter à vos fichiers. Le collecteur shell a été exécuté sous dash, bash, `bash --posix` et busybox, pas sous ksh.
- Les binaires compilés statiquement (hors Go) et les bibliothèques C recopiées sous un autre nom ne sont pas identifiés ; OpenSSL, curl et zlib embarqués le sont par recherche de chaînes.
- Les versions issues de noms de fichiers (jars sans `pom.properties`, bibliothèques JS) sont des indices, pas des preuves ; le SHA-1 des archives permet une identification exacte a posteriori (recherche par empreinte sur Maven Central).
- Le format de buildinfo des binaires Go antérieurs à Go 1.18 n'est pas décodé (signalé comme tel).
- Les ports en écoute sont ceux de l'espace de noms réseau de l'hôte.
- AIX : validé en environnement simulé seulement (voir « AIX ») ; `df` y porte sur tous les systèmes de fichiers montés, réseau compris, sous le délai maximal de la commande.
- Testé de bout en bout sur Ubuntu 24.04, en root et sous un compte non privilégié (playbooks compris) : collecteur Python exécuté en 3.8 et 3.13 ; collecteur shell exécuté sous bash, `bash --posix`, dash et busybox (y compris dans un environnement réduit à busybox, sans Python, unzip ni base64). La compatibilité Python 2.6/2.7/3.6 du collecteur et Python 2.3 de l'inspecteur Java embarqué dans le shell est vérifiée par analyse statique (`vermin`) et, pour ce dernier, par un harnais simulant la sémantique des chaînes Python 2. À confirmer sur un hôte réel de chaque génération (CentOS 4/5/6/7, Debian 7) avant généralisation.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

Les collecteurs y sont réellement exécutés (Python, dash, bash, busybox) sur une arborescence fabriquée, les clés sont produites par `openssl`, et le JavaScript du rapport tourne sous Node sur chaque page si `node` est installé.

## Étendre

- **Nouvelle sonde de version** : ajouter une ligne à `PROBES` dans `cmdb_collector.py` (nom, regex du nom de binaire, arguments) et, si besoin, une regex dans `PROBE_VERSION_RX` de `cmdb_build.py`.
- **Nouvelle application PHP** : une ligne dans `WEBAPP_RULES` (fichier, suffixe de répertoire, produit, regex).
- **Nouveau format de chaîne de connexion** : `extract_db_refs` dans `cmdb_collector.py`, plus un cas dans `tests/test_db_refs.py` (`Secrets` pour vérifier qu'aucun identifiant ne sort). Le collecteur shell doit laisser passer les lignes utiles : voir `grab_dbcfg`.
- **Nouveau produit web** : `parse_endpoints` ; **nouveau type de module** : `parse_modules`. Ajouter les fichiers à `grab_mod` côté shell.
- **Fin de support** : une ligne dans `tools/cmdb_eol.csv`.
- **Contrôle de durcissement** : une ligne dans `tools/cmdb_anssi_rules.csv` (types `sysctl`, `mount`, `sshd`, `sudo_default`, `service`, `package_absent`), ou une fonction dans `BUILTIN` de `cmdb_hardening.py` pour le type `check`.
- **Nouvelle colonne de matrice** : ajouter la famille à `MATRIX_FAMILIES` ; pour la rattacher à des paquets OS, compléter `PKG_FAMILIES`.
- Les règles de parsing étant côté consolidation, une amélioration s'applique à tout l'historique en relançant `cmdb_build.py`, sans recollecter.

## Sources

- Trivy, scan de SBOM : <https://trivy.dev/latest/docs/target/sbom/>
- Grype, cibles de scan et qualificatif `distro` des purl : <https://oss.anchore.com/docs/guides/vulnerability/scan-targets/>
- Dependency-Track, envoi de BOM par l'API : <https://docs.dependencytrack.org/usage/cicd/>
- IBM FLRT Vulnerability Checker en ligne (entrées `lslpp -Lcq`, obligatoire, et `emgr -lv3`, facultative) : <https://esupport.ibm.com/customercare/flrt/vc>
- Module Ansible `ibm.power_aix.flrtvc` (relance `emgr` par sudo quand le compte ne peut l'exécuter) : <https://ansible-aix.github.io/ansible-power-aix/modules/flrtvc.html>
