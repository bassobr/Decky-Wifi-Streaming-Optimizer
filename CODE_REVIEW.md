# Code-Review & Security-Audit — WiFi Optimizer Streaming (Decky-Plugin)

**Stand:** 2026-09-05 · **Commit:** `7621555` (main) · **Version:** 0.12.2
**Art der Analyse:** rein lesend (keine Codeänderungen, keine Installationen)

> ## Umsetzungsstatus (2026-09-05, Branch `fix/code-review-findings`)
>
> Alle Befunde wurden im Branch `fix/code-review-findings` adressiert. Verifiziert durch: 36 neue pytest-Tests (grün), `tsc --noEmit` (sauber), Rollup-Build, `bash -n` auf Template/gerendertem Dispatcher/install.sh, `pnpm audit` (0 Schwachstellen, vorher 6 × High in der Dev-Kette).
>
> **Vollständig behoben:** SEC-01, SEC-02, SEC-04, SEC-05, SEC-06, SEC-07, FUNC-01 bis FUNC-12, REL-01, REL-02, MAINT-01, MAINT-03, MAINT-04, TEST-01, DEP-01, DEP-02.
>
> **SEC-03 — abgeschlossen (Checksummen + Signaturen, „Variante A"):** Installer und Stable-Updater installieren den CI-gebauten Release-Zip und prüfen ihn gegen `SHA256SUMS`. Zusätzlich signiert der Release-Job die `SHA256SUMS` im minisign-Format (Ed25519, Seed als GitHub-Secret `MINISIGN_SEED`); der Updater verifiziert `SHA256SUMS.minisig` gegen den im Plugin gepinnten Public Key (`minisign.pub`, Key-ID `72A411FD74FD614A`) und lehnt unsignierte Stable-Releases ab. Sign/Verify laufen über eine vendored Pure-Python-Ed25519-Implementierung (RFC-8032-Testvektoren in der Suite), da weder SteamOS noch Deckys Python ein minisign-Binary bzw. Ed25519 mitbringen; die Signaturen sind mit dem offiziellen `minisign -Vm` kompatibel. Der CI-Sign-Step verweigert das Signieren, wenn Seed und committeter Public Key nicht zusammenpassen (verhindert Releases, die kein Client akzeptiert). **Dokumentierte Grenzen der Variante A:** Der Schlüssel liegt in GitHub-Secrets — eine vollständige Konto-Übernahme mit Workflow-Änderung könnte weiterhin gültig signieren (Schutzwirkung: Asset-Manipulation, TOFU-Pinning für Bestandsinstallationen). Beta-Kanal (Branch-Tarball) und Erstinstallation bleiben TLS-/Repo-Vertrauen; minisign kennt keine Revocation — bei Schlüsselkompromittierung ist Out-of-band-Rotation nötig (Seed-Backup: `~/.wifi-optimizer-minisign.secret` beim Maintainer, in Passwortmanager überführen).
>
> **MAINT-02 — vollständig abgeschlossen (drei Stufen):** (1) risikoarme Teile: Parser als reine, getestete Helfer; nmcli-Abfragen gebatcht 12→9 Subprozesse/Tick; `_revert_runtime_state`/`_remove_plugin_files` dedupliziert. (2) **Modularisierung nach `py_modules/wifioptimizer`** (v0.14.0): 14 Domänen-Module, `main.py` von ~3050 auf ~300 Zeilen reduziert (nur Plugin-Komposition + Lifecycle); alle Auslieferungswege (Release-Zip, install.sh, Update-Handoff) kopieren das Paket mit, und ein Selbstheilungs-Shim in `main.py` stellt es aus dem verifizierten Release-Zip wieder her, falls ein Alt-Updater (≤ 0.13.0) es beim Update nicht mitkopiert hat. (3) **Zusammenführung der Backend-Switch-Worker:** Phasen, Reconnect-Warteschleife, Laufzeit-Verifikation und Fehler-/Cancel-Behandlung liegen in einem gemeinsamen Rahmen (`_run_backend_switch`); SteamOS- und Generic-Pfad sind nur noch schlanke Step-Methoden, der Rahmen ist erstmals unit-getestet (7 Tests).

---

## Scope & Methodik

Analysiert wurde das gesamte Repository: Python-Backend (`main.py`, 2 537 Zeilen, läuft als **root** im `plugin_loader`), React/TypeScript-Frontend (`src/`, ~1 600 Zeilen), NetworkManager-Dispatcher-Template (`defaults/dispatcher.sh.tmpl`), Installer (`install.sh`), CI-Workflow (`.github/workflows/release.yml`) sowie Manifeste und Konfiguration.

Ausgeführte Read-only-Werkzeuge:

| Werkzeug | Ergebnis |
|---|---|
| Python-AST-Parse (`ast.parse` auf `main.py`) | OK, keine Syntaxfehler |
| `bash -n` (dispatcher.sh.tmpl, install.sh) | OK |
| `pnpm audit --prod` | **0 Schwachstellen** in Laufzeit-Abhängigkeiten |
| `pnpm audit` (inkl. dev) | 6 × High, alle `brace-expansion` in der Build-Kette (→ DEP-01) |
| Lizenzabfrage (npm registry) | @decky/ui + @decky/api: LGPL-2.1; Rest: MIT/BSD/0BSD (→ DEP-02) |

Nicht ausgeführt: `tsc --noEmit` (kein `node_modules` vorhanden; Installation war ausgeschlossen). Die TypeScript-Analyse erfolgte manuell; `strict` ist aktiviert (tsconfig.json:15).

**Angenommenes Bedrohungsmodell** (Annahme, explizit gekennzeichnet): Decky-Plugins mit `"flags": ["root"]` laufen designbedingt als root; der Deck-Nutzer hat das Plugin bewusst installiert. Die relevante Vertrauensgrenze ist daher nicht „Plugin vs. Nutzer", sondern **unprivilegierter Code mit Home-Verzeichnis-Zugriff (z. B. ein Flatpak mit `--filesystem=home`, ein Spiel-Mod) vs. root**. Befunde sind gegen diese Grenze bewertet.

---

## 1. Management Summary

Das Projekt ist für ein Hobby-/Community-Plugin überdurchschnittlich sorgfältig gebaut: durchgängig `subprocess` mit Argument-Listen und absoluten Binärpfaden statt Shell-Strings, atomare Settings-Writes, ein dokumentiertes Gate-Konzept für den Streaming-Modus, Fehlerbehandlung mit nutzerfreundlichen Meldungen und ein Frontend ohne XSS-Flächen (React-Escaping, kein `dangerouslySetInnerHTML`). Die Laufzeit-Abhängigkeiten sind minimal und laut Audit frei von bekannten CVEs.

Die größten Risiken liegen an der **Privilegiengrenze zwischen Deck-Nutzer und root**: Der root-laufende Backend-Prozess und der root-laufende NM-Dispatcher schreiben Dateien in nutzerkontrollierte Verzeichnisse ohne Symlink-Schutz (SEC-01), und das Selbst-Update schreibt ein Root-ausgeführtes Skript unter einem festen, vorhersagbaren `/tmp`-Pfad (SEC-02) — beides klassische lokale Privilege-Escalation-Vektoren. Das Selbst-Update vertraut außerdem allein TLS und dem GitHub-Konto, ohne Integritätsprüfung (SEC-03). Funktional fallen vor allem blockierende Aufrufe im asyncio-Event-Loop (bis hin zu `time.sleep(3)`), Systemzustands-Mutationen im 3-Sekunden-Status-Poll und ein UI-Bug auf, der Nutzereingaben im DNS-Feld überschreibt. Automatisierte Tests fehlen vollständig; die CI prüft nur Syntax. Insgesamt: solide Basis, aber vor dem nächsten Release sollten die beiden Hoch-Befunde und die Release-Prozess-Lücke (Tag ≠ package.json-Version → endlose Update-Schleife) geschlossen werden.

---

## 2. Befundübersicht

| ID | Titel | Kategorie | Schweregrad | Fundstelle |
|---|---|---|---|---|
| SEC-01 | Root schreibt in nutzerkontrollierte Verzeichnisse (Symlink/TOCTOU) | Sicherheit | **Hoch** | dispatcher.sh.tmpl:73,124; main.py:237–240,1098 |
| SEC-02 | Update-Skript unter festem `/tmp`-Pfad, als root ausgeführt | Sicherheit | **Hoch** | main.py:2185–2197 |
| SEC-03 | Selbst-Update ohne Integritätsprüfung (Supply Chain) | Sicherheit | Mittel | main.py:2147–2200; install.sh:56–59 |
| SEC-04 | `eval`-Brücke: Nutzer-Settings → Root-Shell im Dispatcher | Sicherheit | Mittel | dispatcher.sh.tmpl:34–51 |
| SEC-05 | CI: `contents: write` bei `pull_request`-Trigger | Sicherheit | Mittel | release.yml:7,13–14 |
| SEC-06 | Remote-Versionsstring in Root-Bash-Skript interpoliert | Sicherheit | Niedrig | main.py:2150–2184 |
| SEC-07 | Diagnose-Export enthält SSID/BSSID/MAC | Datenschutz | Info | main.py:1059–1103 |
| FUNC-01 | `get_status` mutiert Systemzustand im 3-s-Poll | Logik/Konsistenz | Mittel | main.py:1280–1282,1302–1304,1152–1163 |
| FUNC-02 | Event-Loop-Blockaden (`time.sleep`, synchrone subprocess-Ketten) | Korrektheit/Performance | Mittel | main.py:1514,1107–1338,598–608 |
| FUNC-03 | DNS-Eingabefeld wird alle 3 s vom Status-Poll überschrieben | Korrektheit (UI) | Mittel | src/index.tsx:162–165,774–789 |
| FUNC-04 | Backend-Switch-„Verifikation" liest Konfig statt Laufzeitzustand | Logik/Konsistenz | Niedrig | main.py:2288,2300,2402–2404 |
| FUNC-05 | Boot-Race: veraltetes `streaming_active` + Dispatcher → Fixes ohne Revert | Korrektheit | Niedrig | dispatcher.sh.tmpl:43–44; main.py:685–697,811–816 |
| FUNC-06 | „Restore" überschreibt Fremd-/Distro-Tuning mit hartkodierten Defaults | Korrektheit | Niedrig | main.py:157–166,490,896–901,1964–1969 |
| FUNC-07 | `_load_settings` verschluckt Parse-Fehler stumm | Fehlerbehandlung | Niedrig | main.py:230–231 |
| FUNC-08 | `set_dns(disable)` ignoriert nmcli-Fehler; keine DNS-Drift-Erkennung | Fehlerbehandlung | Niedrig | main.py:1582–1583 |
| FUNC-09 | `dict(DEFAULT_SETTINGS)` — Shallow-Copy mit geteiltem Unterobjekt | Korrektheit (latent) | Niedrig | main.py:1995 |
| FUNC-10 | „Reset Settings" ohne Bestätigungsdialog | UI/Robustheit | Niedrig | src/index.tsx:411–422 |
| FUNC-11 | Streaming-Erkennung: Substring-Matching spoofbar, Custom-Patterns unvalidiert | Korrektheit | Niedrig | main.py:610–644,1751–1761 |
| FUNC-12 | „Update Now" ohne Re-Entrancy-Guard | Korrektheit (UI) | Info | src/index.tsx:473–481 |
| REL-01 | Kein Tag↔`package.json`-Versionsabgleich → endlose Update-Schleife möglich | Konfiguration/Betrieb | Mittel | release.yml:48,60–67; main.py:2104–2113 |
| REL-02 | `dist/` eingecheckt; Installer nutzt Quell-Tarball statt gebautem Zip | Konfiguration/Betrieb | Niedrig | release.yml:57–59; install.sh:82; main.py:2178 |
| MAINT-01 | Tuning-Logik dreifach dupliziert (main.py ↔ Dispatcher) | Wartbarkeit | Mittel | main.py:145–154,579–582,47–70 ↔ dispatcher.sh.tmpl:100–107,115,81–86 |
| MAINT-02 | `main.py` monolithisch, Setter-Boilerplate, `get_status` ~230 Zeilen | Wartbarkeit | Mittel | main.py (gesamt) |
| MAINT-03 | Toter Code (ERROR_MESSAGES-Einträge, Badge-Varianten, ungenutzte live-Felder) | Wartbarkeit | Info | src/types.ts:142,148,150; main.py:1261,1279,1300 |
| MAINT-04 | Namens-/Link-Inkonsistenzen Fork ↔ Upstream | Dokumentation | Niedrig | plugin.json:2; src/index.tsx:93,908; PanelFooter.tsx:58; README.md:114–130 |
| TEST-01 | Keine automatisierten Tests; CI prüft nur Syntax | Tests | Mittel | release.yml:33–37 |
| DEP-01 | 6 High-CVEs in Dev-Build-Kette (`brace-expansion`) | Abhängigkeiten | Niedrig | pnpm-lock.yaml |
| DEP-02 | LGPL-2.1-Abhängigkeiten werden in `dist/index.js` gebündelt | Lizenzen | Info | package.json:13,21 |

---

## 3. Detailbefunde

### SEC-01 — Root schreibt in nutzerkontrollierte Verzeichnisse (Symlink/TOCTOU)

- **Kategorie:** Sicherheit (lokale Privilege Escalation) · **Schweregrad: Hoch** · **Aufwand: M**
- **Fundstellen:**
  - `defaults/dispatcher.sh.tmpl:73` und `:124` — `date +%s > "$SETTINGS_DIR/last_enforced"` (läuft als root via NetworkManager-Dispatcher)
  - `main.py:237–240` — `_save_settings` schreibt `settings.json.tmp` + `os.replace` (root)
  - `main.py:1098` — `save_diagnostic_info` schreibt `diagnostics.json` (root)

**Beschreibung:** `SETTINGS_DIR` liegt unter `~/homebrew/settings/…` und ist vom unprivilegierten Deck-Nutzer beschreibbar. Sowohl der Dispatcher (root) als auch das Plugin-Backend (root) öffnen dort Dateien mit `open(path, "w")` bzw. Shell-Redirect — beides folgt Symlinks. Ein unprivilegierter Prozess mit Home-Zugriff (z. B. ein Flatpak mit `--filesystem=home`) kann `last_enforced` oder `settings.json.tmp` durch einen Symlink auf eine beliebige root-eigene Datei ersetzen.

**Auswirkung:**
- Via `last_enforced`-Symlink: Bei jedem WiFi-Reconnect überschreibt/trunkiert root die Zieldatei mit einem Zeitstempel — z. B. `/etc/shadow` truncaten (System-Lockout, DoS) oder beliebige Konfigurationsdateien zerstören.
- Via `settings.json.tmp`-Symlink: root schreibt JSON mit **teilweise angreiferkontrollierten Strings** (der Angreifer kann `settings.json` direkt editieren, z. B. `streaming_custom_patterns` auf `"x $(curl … | sh)"` setzen; das Plugin lädt und re-persistiert diese Werte). Wird das Ziel z. B. auf `/root/.bashrc` gelenkt, führt Bash bei einer root-Login-Shell die `$(…)`-Substitution in der JSON-Zeile aus → **Root-Codeausführung**.

**Empfehlung:**
1. `last_enforced` in ein root-eigenes Verzeichnis verlegen (z. B. `/run/wifi-optimizer/`), das der Dispatcher per `install -d -m 0755 -o root` anlegt; im Plugin von dort lesen.
2. In Python Symlink-sicher öffnen:
   ```python
   fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
   with os.fdopen(fd, "w") as f:
       json.dump(data, f, indent=2)
   ```
   plus vor `os.replace` prüfen, dass das Zielverzeichnis kein Symlink ist (`os.path.realpath`-Vergleich) — oder Settings komplett in ein root-eigenes Verzeichnis verlegen und dem Dispatcher nur Leserechte geben.
3. Im Dispatcher-Shell-Code Redirects vermeiden bzw. vorher `[ -L "$f" ] && rm -f "$f"` (mindert, verhindert Races aber nicht vollständig — das root-eigene Verzeichnis ist die saubere Lösung).

---

### SEC-02 — Update-Skript unter festem `/tmp`-Pfad, als root ausgeführt

- **Kategorie:** Sicherheit (lokale Privilege Escalation, TOCTOU) · **Schweregrad: Hoch** · **Aufwand: S**
- **Fundstelle:** `main.py:2185–2197`

**Beschreibung:**
```python
script_path = "/tmp/wifi-optimizer-update.sh"
with open(script_path, "w") as f:
    f.write(script)
os.chmod(script_path, 0o700)
subprocess.Popen(["/bin/bash", script_path], ...)
```
Der Pfad ist fest und vorhersagbar in einem world-writable Verzeichnis. Legt ein unprivilegierter Prozess die Datei **vorab** an (oder als Symlink), gehört sie ihm weiter, nachdem root sie per `open("w")` nur trunkiert und neu befüllt hat. Der Eigentümer kann den Inhalt zwischen Schreiben und (inkrementellem) Einlesen durch Bash beliebig ersetzen.

**Auswirkung:** Beliebige Codeausführung als root, ausgelöst durch einen normalen In-App-Update-Vorgang; Symlink-Variante erlaubt zusätzlich Root-Writes an beliebige Pfade.

**Empfehlung:** Kein Intermediate-File in `/tmp`, oder mit `tempfile` + `O_EXCL` in einem root-eigenen Verzeichnis arbeiten. Am einfachsten: Skript über stdin einspeisen —
```python
subprocess.Popen(["/bin/bash", "-s"], stdin=subprocess.PIPE, start_new_session=True, env=clean_env).stdin.write(script.encode())
```
oder `tempfile.NamedTemporaryFile(dir="/run", delete=False)` (root-only) verwenden. `mktemp -d` innerhalb des Skripts ist bereits korrekt — nur die Skriptdatei selbst ist das Problem.

---

### SEC-03 — Selbst-Update ohne Integritätsprüfung (Supply Chain)

- **Kategorie:** Sicherheit · **Schweregrad: Mittel** · **Aufwand: M**
- **Fundstellen:** `main.py:2147–2200` (In-App-Update), `install.sh:35–59` (Installer)

**Beschreibung:** Update und Installation laden Tarballs von GitHub (`archive/refs/tags/…`, `archive/refs/heads/beta.tar.gz` bzw. `…/main.tar.gz`) und installieren sie als root — ohne Checksumme, Signatur oder Pinning. Einziger Schutz ist TLS plus das Vertrauen in ein einzelnes GitHub-Konto. Ein kompromittiertes Konto/Repo bedeutet Root-Codeausführung auf allen Installationen beim nächsten Update-Klick. (Pfad-Traversal beim Entpacken ist durch moderne GNU-tar-Defaults gemindert — Annahme, nicht verifiziert für alle Ziel-Distros.)

**Auswirkung:** Single Point of Trust; kein Erkennen manipulierter Artefakte.

**Empfehlung:** Mindestens: im Release-Workflow eine `SHA256SUMS` als Release-Asset erzeugen, im Updater vor der Installation verifizieren (`sha256sum -c`). Besser: signierte Checksummen (z. B. `gh attestation`/Sigstore oder minisign mit im Plugin eingebettetem Public Key). Zusätzlich 2FA/Branch-Protection auf dem Repo (organisatorisch).

---

### SEC-04 — `eval`-Brücke: Nutzer-Settings → Root-Shell im Dispatcher

- **Kategorie:** Sicherheit (Defense in Depth) · **Schweregrad: Mittel** · **Aufwand: S–M**
- **Fundstelle:** `defaults/dispatcher.sh.tmpl:34–51`

**Beschreibung:** Der root-laufende Dispatcher parst die **nutzer­beschreibbare** `settings.json` per eingebettetem Python und führt dessen Ausgabe mit `eval` aus. Aktuell ist das dicht: Booleans werden hart auf `True/False` gemappt, und `driver` wird saniert (`v.isalnum() or v.replace("_","").isalnum()`, sonst `unknown` — blockiert alle Shell-Metazeichen; verifiziert). Es gibt also **derzeit keinen Injection-Pfad**. Das Muster ist aber fragil: Jedes künftig hinzugefügte Feld, das diese Sanitisierung nicht repliziert, wird sofort zu einer Root-Shell-Injection aus einer nutzerkontrollierten Datei.

**Auswirkung:** Kein akuter Exploit; hohes Regressionsrisiko an einer root-Grenze.

**Empfehlung:** `eval` eliminieren. Das Python-Snippet kann die Werte zeilenweise ausgeben und die Shell liest sie positional:
```bash
read -r POWER_SAVE BUFFER_TUNING DRIVER CAKE VOLATILE_GATE < <(python3 - "$SETTINGS_FILE" <<'EOF'
import json, sys
try: d = json.load(open(sys.argv[1]))
except Exception: d = {}
drv = d.get("driver", "unknown")
if not drv.replace("_", "").isalnum(): drv = "unknown"
print("True" if d.get("power_save_disabled", True) else "False",
      "True" if d.get("buffer_tuning_enabled", False) else "False",
      drv,
      "True" if d.get("cake_enabled", False) else "False",
      "True" if (not d.get("streaming_mode_enabled", False)) or d.get("streaming_active", False) else "False")
EOF
)
```
Damit ist die Klasse „vergessene Sanitisierung → eval-Injection" strukturell ausgeschlossen. Zusätzlich den Settings-Pfad per `sys.argv` statt String-Interpolation übergeben (siehe Snippet).

---

### SEC-05 — CI: `contents: write` bei `pull_request`-Trigger

- **Kategorie:** Sicherheit (CI/CD) · **Schweregrad: Mittel** · **Aufwand: S**
- **Fundstelle:** `.github/workflows/release.yml:7` (Trigger `pull_request`), `:13–14` (`permissions: contents: write`), `:27–31` (`pnpm install` + Build)

**Beschreibung:** Der Workflow läuft auch für Pull Requests, mit `contents: write` auf Job-Ebene, und führt `pnpm install` (Lifecycle-Skripte der Abhängigkeiten) sowie den Build aus. `actions/checkout@v4` persistiert das Token standardmäßig in `.git/config`. Für Fork-PRs stuft GitHub das Token automatisch auf read-only herab (Mitigation), aber für Branch-PRs im selben Repo — und falls das Repo je `pull_request_target` o. Ä. erhält — steht einem via PR eingeschleusten bösartigen Build-/Postinstall-Skript ein schreibfähiges Token zur Verfügung.

**Auswirkung:** Erhöhte Angriffsfläche für Repo-Manipulation über die Build-Pipeline (Supply-Chain-Verstärker für SEC-03).

**Empfehlung:**
```yaml
permissions:
  contents: read          # Workflow-Default
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      …
      - name: Create GitHub release
        if: startsWith(github.ref, 'refs/tags/v')
        permissions:      # nur hier erhöhen (bzw. eigener Release-Job)
          contents: write
```
(Step-Level-`permissions` gibt es nicht — praktisch: Release in separaten Job mit eigenem `permissions:`-Block auslagern.)

---

### SEC-06 — Remote-Versionsstring in Root-Bash-Skript interpoliert

- **Kategorie:** Sicherheit / Robustheit · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstelle:** `main.py:2150–2184` (`label`, `src_dir`, `download_url` per f-String in das Update-Skript)

**Beschreibung:** `latest` stammt aus der GitHub-API (Tag-Name bzw. `package.json`-`version` des beta-Branches) und landet unquotiert-interpoliert in `logger -t wifi-optimizer "Updated to {label} …"`. Ein Versionsstring mit `$(…)`/Backticks würde als root ausgeführt. Da ein Angreifer mit Kontrolle über das Repo ohnehin `main.py` kontrolliert (siehe SEC-03), entsteht **keine neue Vertrauensgrenze** — aber ein exotischer, gutartiger Tag-Name (Quote, Backtick) bricht das Update-Skript.

**Empfehlung:** Versionsstring vor Interpolation validieren: `re.fullmatch(r"[0-9A-Za-z_.-]+", latest)`; sonst Update ablehnen. (Ein Zeichen-Whitelist-Check, S-Aufwand.)

---

### SEC-07 — Diagnose-Export enthält SSID/BSSID/MAC

- **Kategorie:** Datenschutz · **Schweregrad: Info** · **Aufwand: S**
- **Fundstelle:** `main.py:1059–1103` (`get_diagnostic_info` inkl. `iw dev`-Rohausgabe; `save_diagnostic_info` schreibt `diagnostics.json`)

**Beschreibung:** Der Docstring sagt „Sanitized (no passwords)" — Passwörter fehlen tatsächlich, aber `iw dev` liefert SSID, Interface-MAC und (via `iw dev link` im Status) die AP-BSSID. Das sind identifizierende Daten (Geolokalisierbarkeit von BSSIDs über öffentliche Datenbanken). Der Export erfolgt nur auf explizite Nutzeraktion (Clipboard/Datei) — akzeptabel, sollte aber transparent sein.

**Empfehlung:** Im UI-Button-Text oder Tooltip erwähnen, dass Netzwerkkennungen (SSID/MAC) enthalten sind; optional SSID/BSSID im Export maskieren (`aa:bb:cc:…` → OUI behalten, Rest schwärzen). Kein Löschkonzept nötig — Datei liegt nur lokal und wird bei `reset_settings`/`_uninstall` nicht entfernt: `diagnostics.json` dort in die Lösch-Liste aufnehmen (main.py:902–907).

---

### FUNC-01 — `get_status` mutiert Systemzustand im 3-s-Poll

- **Kategorie:** Logik & Konsistenz · **Schweregrad: Mittel** · **Aufwand: M**
- **Fundstellen:** `main.py:1280–1282` (IPv6-Auto-Heal), `:1302–1304` (Band-Auto-Heal), `:1152–1163` (Settings-Writes + `nmcli con mod autoconnect-priority`)

**Beschreibung:** Der Status-Endpunkt — vom Frontend alle 3 s gepollt (src/index.tsx:42,217–240) — ist kein reiner Read: Bei erkannter IPv6-/Band-Drift ruft er sofort `nmcli con mod` auf und schreibt damit das NM-Verbindungsprofil auf Disk. Da ohne Reconnect die *Live*-Werte unverändert bleiben, bleibt die Drift-Bedingung bestehen → der Schreibvorgang wiederholt sich **bei jedem 3-s-Tick**, solange das Panel offen ist. Zusätzlich inkonsistent: power_save/buffer/cake-Drift wird nur gemeldet, IPv6/Band dagegen still „geheilt" — zwei verschiedene Verhaltensmodelle für dasselbe Konzept. Ein Getter mit Seiteneffekten unterläuft außerdem die Erwartung aller Aufrufer (z. B. Statuspoll während der Nutzer gerade manuell per nmcli experimentiert).

**Auswirkung:** Wiederholte unnötige Disk-Writes (NM persistiert Profile unter `/etc/NetworkManager/system-connections/`), überraschendes Verhalten, erschwerte Fehlersuche.

**Empfehlung:** Auto-Heal aus `get_status` entfernen. Drift nur melden; Heilung gehört in den bestehenden „Fix now"-Pfad (`handleOptimize`/`reapply_all`) oder in einen expliziten `auto_heal`-Aufruf mit Once-Semantik. Risikoarm umsetzbar, Verhalten bleibt über den Drift-Banner erhalten.

---

### FUNC-02 — Event-Loop-Blockaden: `time.sleep(3)` und synchrone subprocess-Ketten

- **Kategorie:** Funktionale Korrektheit / Performance · **Schweregrad: Mittel** · **Aufwand: S (sleep) + M (vollständig)**
- **Fundstellen:**
  - `main.py:1514` — `time.sleep(3)` in `async set_band_preference` (blockiert den gesamten Event-Loop 3 s)
  - `main.py:1107–1338` — `get_status`: ~12 synchrone `subprocess.run`-Aufrufe direkt im Event-Loop; Worst Case laut eigenem Kommentar ~20 s (Zeile 1108–1109)
  - `main.py:598–608` — `_apply_streaming_profile` ruft unter gehaltenem `_detect_lock` synchron `sysctl`×8, `tc`, `ip`, `iw`, `modprobe` auf
  - `main.py:435–440` — `_hard_reconnect`: bis zu 20 s Timeout-Budget synchron

**Beschreibung:** Nur die `/proc`-Scans und einige Backend-Switch-Aufrufe sind in `asyncio.to_thread` ausgelagert; der Rest läuft synchron im Loop. Hängt NetworkManager/`iw` (genau das Szenario nach Sleep/Wake, das dieses Plugin adressiert), frieren **alle** IPC-Aufrufe ein — das UI zeigt dann veraltete Toggles, der Streaming-Watcher verpasst Polls, und der Backend-Switch-Statuspoll staut sich.

**Auswirkung:** UI-Freezes und verzögerte Streaming-Erkennung genau in den degradierten Situationen, für die das Plugin gebaut ist.

**Empfehlung:**
1. Sofort (S): `time.sleep(3)` → `await asyncio.sleep(3)`.
2. Strukturell (M): `_run_cmd` um eine async-Variante ergänzen (`await asyncio.to_thread(self._run_cmd, …)` an allen Aufrufstellen in async-Methoden, oder `asyncio.create_subprocess_exec`), beginnend mit `get_status` und `_apply_streaming_profile`.

---

### FUNC-03 — DNS-Eingabefeld wird alle 3 s vom Status-Poll überschrieben

- **Kategorie:** Funktionale Korrektheit (UI) · **Schweregrad: Mittel** · **Aufwand: S**
- **Fundstellen:** `src/index.tsx:162–165` (Poll setzt `customDnsInput` aus Settings), `:774–789` (TextField mit `onChange`/`onBlur`)

**Beschreibung:** `refreshStatus` läuft alle 3 s und setzt bei `dns_provider === "custom"` das lokale Eingabefeld hart auf den gespeicherten Wert. Tippen auf dem Steam-Deck-OSK dauert typischerweise länger als 3 s — die Eingabe des Nutzers wird mitten im Tippen durch den alten gespeicherten Wert ersetzt; gespeichert wird erst bei `onBlur`. Das Custom-Patterns-Feld in `StreamingSection.tsx` hat dieses Problem bewusst nicht (nur Initialwert) — die beiden Felder verhalten sich also auch noch unterschiedlich.

**Auswirkung:** Eingabeverlust; „Custom DNS" ist auf dem Gerät praktisch kaum bedienbar.

**Empfehlung:** Wie bei `StreamingSection` nur initial befüllen, oder ein `isEditingRef`/Focus-Flag setzen und den Sync unterdrücken, solange das Feld fokussiert ist:
```tsx
if (s.settings.dns_provider === "custom" && !dnsFieldFocusedRef.current) {
  setCustomDnsInput(s.settings.dns_servers || "");
}
```

---

### FUNC-04 — Backend-Switch-„Verifikation" liest Konfig statt Laufzeitzustand

- **Kategorie:** Logik & Konsistenz · **Schweregrad: Niedrig** · **Aufwand: S–M**
- **Fundstellen:** `main.py:2288` und `:2402` (`final_backend = _get_current_backend()`), `:347–384` (`_get_current_backend` liest zuerst Konfig-Dateien)

**Beschreibung:** Nach dem Switch wird der „finale Backend-Zustand" über `_get_current_backend()` geprüft — diese Funktion liest aber zuerst genau die Konfig-Datei, die der Switch gerade selbst geschrieben hat (`GENERIC_BACKEND_CONF` bzw. die vom SteamOS-Helper geschriebene Datei). Der Vergleich `final_backend != target` kann daher praktisch nie fehlschlagen: Die Prüfung bestätigt die eigene Schreiboperation, nicht den tatsächlich laufenden Dienst. Schlägt z. B. `systemctl start wpa_supplicant` fehl (Paket fehlt auf einer Nicht-SteamOS-Distro — wird vorher nicht geprüft, main.py:2365–2371), meldet der generische Worker dennoch `success: True`, lediglich abgeschwächt durch `reconnect_timed_out`.

**Auswirkung:** „Erfolgreich gewechselt"-Meldung bei tatsächlich totem WLAN-Backend; Nutzer erhält irreführendes Feedback.

**Empfehlung:** Verifikation gegen die Laufzeit: `systemctl is-active <target>` und/oder `nmcli -t -f RUNNING,VERSION general` bzw. `nmcli device show` heranziehen; im generischen Worker vor dem Umschalten prüfen, ob die Ziel-Unit existiert (`systemctl cat <target>`), analog zur bestehenden iwd-Prüfung in `_get_backend_method` (main.py:340).

---

### FUNC-05 — Boot-Race: veraltetes `streaming_active` + Dispatcher → Fixes bleiben ohne Revert aktiv

- **Kategorie:** Funktionale Korrektheit · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstellen:** `dispatcher.sh.tmpl:43–44` (Gate liest `streaming_active` aus Datei), `main.py:811–816` (Reset erst beim Plugin-Start), `main.py:685–697` (Revert nur bei `was_active`)

**Beschreibung:** Stürzt das System während eines Streams ab (oder wird hart ausgeschaltet), bleibt `streaming_active: true` in `settings.json` persistiert. Beim nächsten Boot verbindet WLAN typischerweise **bevor** `plugin_loader` das Plugin lädt: Der Dispatcher sieht das offene Gate und wendet die volatilen Fixes an. Das Plugin setzt anschließend `streaming_active = False` (main.py:814) — der Watcher sieht dann `was_active == False` und nimmt **keinen Revert** vor (Zeile 696–697). Die Fixes bleiben aktiv, obwohl das Gate geschlossen ist; die Drift-Anzeige unterdrückt den Zustand zusätzlich, weil sie bei geschlossenem Gate nicht meldet (main.py:1171,1316,1322). Selbstheilung erst beim nächsten Stream-Start/-Ende-Zyklus.

**Auswirkung:** Batterie-/Verhaltens-Erwartung des Streaming-Modus temporär verletzt; kein Schaden darüber hinaus.

**Empfehlung:** In `_main` nach dem Reset von `streaming_active` einmalig `await self._apply_streaming_profile(False)` ausführen, wenn `streaming_mode_enabled` gesetzt ist und vorher `streaming_active` true war (den Alt-Wert vor dem Überschreiben merken).

---

### FUNC-06 — „Restore" überschreibt Fremd-/Distro-Tuning mit hartkodierten Defaults

- **Kategorie:** Funktionale Korrektheit · **Schweregrad: Niedrig** · **Aufwand: M**
- **Fundstellen:** `main.py:157–166` (`SYSCTL_DEFAULTS` hartkodiert), `:490` (ASPM-Revert schreibt pauschal `"1"`), `:896–901` und `:1964–1969` (Uninstall/Reset setzen Defaults bedingungslos)

**Beschreibung:** Beim Deaktivieren/Deinstallieren werden sysctl-Werte, `txqueuelen` (1000) und ASPM-Zustände auf **angenommene** Kernel-Defaults gesetzt statt auf die tatsächlichen Vorwerte. Distros wie Bazzite oder Nutzer mit eigener `sysctl.d`-Konfiguration verlieren dadurch ihr Tuning (bis zum Reboot). `_uninstall`/`reset_settings` setzen die Werte sogar zurück, wenn Buffer-Tuning nie aktiviert war. Die Annahme „212992/1000/…" stimmt für aktuelle Kernel, ist aber nirgends abgesichert (Annahme, gekennzeichnet).

**Auswirkung:** Stilles Überschreiben fremder Systemkonfiguration; Support-Rauschen („nach Deinstallation ist mein Netzwerk anders").

**Empfehlung:** Beim erstmaligen Aktivieren die Ist-Werte snapshotten (`sysctl -n <key>` je Parameter, ASPM-Dateiinhalte) und in den Settings ablegen; Revert stellt den Snapshot wieder her. Uninstall/Reset nur zurücksetzen, was laut Settings aktiv war.

---

### FUNC-07 — `_load_settings` verschluckt Parse-Fehler stumm

- **Kategorie:** Fehlerbehandlung · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstelle:** `main.py:230–231`

**Beschreibung:** Jede Exception (defekte JSON-Datei, Berechtigungsproblem) führt kommentarlos zu Default-Settings. Der nächste Setter-Aufruf persistiert die Defaults und **überschreibt damit die Nutzereinstellungen endgültig** — ohne jeglichen Log-Eintrag. Der Frontend-Fehlertext `parse_error: "Settings were reset to defaults."` (src/types.ts:150) existiert, wird aber vom Backend nie ausgelöst — das war offenbar mal anders vorgesehen.

**Empfehlung:** `except`-Zweig differenzieren: `FileNotFoundError` still, alles andere per `decky.logger.error(...)` loggen; optional die defekte Datei als `settings.json.corrupt` sichern, bevor Defaults geschrieben werden.

---

### FUNC-08 — `set_dns(disable)` ignoriert nmcli-Fehler; keine DNS-Drift-Erkennung

- **Kategorie:** Fehlerbehandlung / Konsistenz · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstelle:** `main.py:1582–1583`; DNS fehlt in der Drift-Logik von `get_status` (main.py:1256–1261 liest DNS nur als Live-Wert)

**Beschreibung:** Beim Deaktivieren werden die Rückgaben von `nmcli con mod ipv4.dns ""` und `ipv4.ignore-auto-dns no` nicht geprüft (im Enable-Pfad dagegen schon, Zeile 1564–1580). Schlägt der Aufruf fehl, speichert das Plugin `dns_enabled = False`, während das Profil weiter die Override-DNS nutzt. Da `get_status` für DNS keine Drift prüft (im Gegensatz zu Band/IPv6/BSSID), bleibt die Diskrepanz unsichtbar.

**Empfehlung:** Rückgaben wie im Enable-Pfad prüfen; optional DNS in die Drift-Prüfung aufnehmen (Vergleich `live.dns` gegen Erwartung).

---

### FUNC-09 — `dict(DEFAULT_SETTINGS)`: Shallow-Copy mit geteiltem Unterobjekt

- **Kategorie:** Funktionale Korrektheit (latent) · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstelle:** `main.py:1995` (`fresh = dict(DEFAULT_SETTINGS)`)

**Beschreibung:** `DEFAULT_SETTINGS["streaming_apps"]` ist ein Dict; die Shallow-Copy teilt dieses Objekt mit der Modul-Konstante. Aktuell mutiert kein Codepfad `fresh["streaming_apps"]` in place (verifiziert: `_load_settings` deep-copied, `set_streaming_app` kopiert vor der Mutation) — es ist also **kein aktiver Bug**, aber eine Falle: Die erste künftige In-place-Mutation vergiftet die globalen Defaults prozessweit bis zum Plugin-Reload.

**Empfehlung:** `fresh = copy.deepcopy(DEFAULT_SETTINGS)` — konsistent mit `_load_settings:231`.

---

### FUNC-10 — „Reset Settings" ohne Bestätigungsdialog

- **Kategorie:** UI/Robustheit · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstellen:** `src/index.tsx:411–422` (`handleResetSettings`), `src/components/ActionsSection.tsx:27–31`

**Beschreibung:** Ein einzelner (auch versehentlicher) Tap auf „Reset Settings" löscht sofort alle Einstellungen, revertiert Laufzeit-Tuning und entfernt Konfig-Dateien (`reset_settings`, main.py:1958–2011) — ohne Rückfrage und ohne Undo. Im Gamepad-UI mit Fokus-Navigation ist ein Fehl-Tap realistisch.

**Empfehlung:** Decky-üblichen Bestätigungsdialog (`showModal`/`ConfirmModal` aus `@decky/ui`) vorschalten.

---

### FUNC-11 — Streaming-Erkennung: Substring-Matching spoofbar, Custom-Patterns unvalidiert

- **Kategorie:** Funktionale Korrektheit · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstellen:** `main.py:610–644` (`_detect_streaming_app`), `:620–622` (Custom-Patterns), `:1751–1761` (Setter ohne Validierung)

**Beschreibung:** Die Erkennung matcht Lowercase-Substrings gegen jede `/proc/<pid>/cmdline`. Folgen:
1. Jeder lokale Prozess kann einen Stream vortäuschen oder auslösen (`grep moonlight foo` hält die Fixes aktiv) — sicherheitlich harmlos (nur Netz-Tuning), aber eine False-Positive-Quelle, die der generische Pattern `chiaki`/`greenlight` verstärkt.
2. Custom-Patterns werden ungeprüft übernommen: Ein einzelnes Zeichen wie `a` matcht praktisch immer → Streaming-Modus dauerhaft „aktiv", was den Zweck des Modus unbemerkt aushebelt.

**Empfehlung:** Mindestlänge (z. B. ≥ 3 Zeichen) für Custom-Patterns erzwingen und im UI zurückmelden; optional in der UI anzeigen, welcher Prozess gematcht hat (Label existiert bereits), damit False Positives diagnostizierbar sind.

---

### FUNC-12 — „Update Now" ohne Re-Entrancy-Guard

- **Kategorie:** Funktionale Korrektheit (UI) · **Schweregrad: Info** · **Aufwand: S**
- **Fundstelle:** `src/index.tsx:473–481` (`handleApplyUpdate` prüft `busyRef` nicht)

**Beschreibung:** Anders als alle anderen Handler nutzt `handleApplyUpdate` den `busyRef`-Guard nicht; Schutz ist nur das `updating`-Rendering. Ein Doppel-Tap vor dem Re-Render kann zwei Update-Skripte parallel starten, die konkurrierend in das Plugin-Verzeichnis kopieren (`cp`-Races → potenziell inkonsistente Installation, heilbar durch erneutes Update).

**Empfehlung:** `if (busyRef.current) return; setBusy(true);` analog zu `handleToggle` ergänzen (Backend-seitig zusätzlich ein `_update_in_progress`-Flag).

---

### REL-01 — Kein Tag↔`package.json`-Versionsabgleich → endlose Update-Schleife möglich

- **Kategorie:** Konfiguration & Betrieb (Release-Prozess) · **Schweregrad: Mittel** · **Aufwand: S**
- **Fundstellen:** `.github/workflows/release.yml:48` (liest Version nur für den Zip-Namen), `:60–67` (Release aus Tag); `main.py:2104–2113` (Update-Entscheid vergleicht Tag-Version mit installierter `package.json`-Version)

**Beschreibung:** Der Updater vergleicht die installierte Version (`DECKY_PLUGIN_VERSION` ← `package.json` der Installation) mit dem neuesten Release-**Tag**. Installiert wird anschließend der **Quell-Tarball des Tags**. Vergisst der Maintainer beim Taggen den `package.json`-Bump (nichts erzwingt ihn), gilt nach dem Update weiterhin `latest > current` → das UI bietet dasselbe Update endlos wieder an; jeder Klick lädt und installiert erneut als root.

**Auswirkung:** Update-Endlosschleife für alle Nutzer bis zu einem Korrektur-Release; unnötige Root-Installationsläufe.

**Empfehlung:** Guard im Workflow (Quick Win):
```yaml
- name: Verify tag matches package.json
  if: startsWith(github.ref, 'refs/tags/v')
  run: |
    V=$(python3 -c "import json;print(json.load(open('package.json'))['version'])")
    [ "v$V" = "$GITHUB_REF_NAME" ] || { echo "Tag $GITHUB_REF_NAME != package.json $V"; exit 1; }
```

---

### REL-02 — `dist/` eingecheckt; Installer/Updater nutzen Quell-Tarball statt gebautem Zip

- **Kategorie:** Konfiguration & Betrieb · **Schweregrad: Niedrig** · **Aufwand: M**
- **Fundstellen:** `.github/workflows/release.yml:57–59` (Kommentar bestätigt das Design), `install.sh:82`, `main.py:2178` (beide kopieren `dist/index.js` aus dem Source-Archiv)

**Beschreibung:** CI baut `dist/` frisch und hängt ein Zip an das Release an — installiert wird aber (Installer und Self-Updater) der **Quell-Tarball** mit dem *eingecheckten* `dist/index.js`. Zwei Artefakte pro Release, die auseinanderlaufen können: Ein Commit, der `src/` ändert, aber `dist/` nicht neu baut, liefert Nutzern stillschweigend veraltetes Frontend, obwohl CI grün ist und das Zip korrekt wäre. Kein CI-Check stellt sicher, dass eingechecktes `dist/` dem Quellstand entspricht.

**Empfehlung:** Entweder (a) Installer/Updater auf das Release-Zip-Asset umstellen (dann kann `dist/` aus dem Repo entfernt werden), oder (b) CI-Check ergänzen: nach `pnpm run build` per `git diff --exit-code dist/` sicherstellen, dass das eingecheckte Artefakt aktuell ist.

---

### MAINT-01 — Tuning-Logik dreifach dupliziert (main.py ↔ Dispatcher)

- **Kategorie:** Wartbarkeit / Konsistenz · **Schweregrad: Mittel** · **Aufwand: M**
- **Fundstellen:** sysctl-Werte: `main.py:145–154` ↔ `dispatcher.sh.tmpl:100–107`; CAKE-Kommando: `main.py:579–582` ↔ `dispatcher.sh.tmpl:115`; Treiber-sysfs-Pfade: `main.py:47–70` ↔ `dispatcher.sh.tmpl:81–86`; txqueuelen-Konstanten (256/1000/2000) an 6+ Stellen

**Beschreibung:** Dieselben Tuning-Parameter existieren zweimal in zwei Sprachen (Python-Konstanten und hartkodierte Shell-Zeilen im Template) plus verstreute Magic Numbers. Eine Wertänderung an einer Stelle divergiert leise: Plugin wendet X an, Dispatcher nach dem nächsten Wake Y — genau die Drift, die das Plugin bekämpfen soll. (Aktuell sind die Werte konsistent; verifiziert.)

**Empfehlung (risikoarm):** Dispatcher generieren statt duplizieren — `_install_dispatcher` (main.py:733–747) ersetzt bereits Platzhalter; die sysctl-Zeilen, das CAKE-Kommando und die Treiber-sysfs-Blöcke ebenfalls aus `SYSCTL_PARAMS`/`DRIVER_PROFILES` rendern (z. B. Platzhalter `__SYSCTL_CMDS__`, `__DRIVER_FIXES__`). Vorher/Nachher-Skizze:
```python
# vorher: Werte stehen fest im Template
script = script.replace("__SETTINGS_PATH__", SETTINGS_FILE)
# nachher: eine Quelle der Wahrheit
sysctl_lines = "\n".join(
    f'    /usr/bin/sysctl -w {k}={v} >/dev/null 2>&1' for k, v in SYSCTL_PARAMS.items())
script = script.replace("__SYSCTL_CMDS__", sysctl_lines)
```

---

### MAINT-02 — `main.py` monolithisch; Setter-Boilerplate; `get_status` ~230 Zeilen

- **Kategorie:** Wartbarkeit · **Schweregrad: Mittel** · **Aufwand: L**
- **Fundstelle:** `main.py` gesamt (2 537 Zeilen, eine Klasse); `get_status` main.py:1107–1338; ~11 nahezu identische `nmcli_failed`-Fehlerblöcke; zwei Backend-Switch-Worker mit ~60 % Strukturgleichheit (main.py:2207–2447)

**Beschreibung:** Decky verlangt `main.py` als Einstieg, aber `py_modules/` existiert bereits (leer) und ist der vorgesehene Ort für Module. Wiederkehrende Muster: try/except-Hülle + Fehler-Dict in jedem Setter, dreifach ähnliche „Werte anwenden"-Blöcke (`_uninstall`, `reset_settings`, `_apply_buffer_tuning_now`), Copy-Paste zwischen den beiden Switch-Workern. Das erhöht die Wahrscheinlichkeit, dass künftige Änderungen eine der Kopien vergessen (siehe FUNC-08, wo Enable- und Disable-Pfad bereits divergieren).

**Empfehlung:**
- **Risikoarm:** `get_status` in benannte Parser-Helfer zerlegen (`_parse_link_info`, `_read_profile_field`, …); die drei nmcli-Profilabfragen (BSSID/IPv6/Band, main.py:1221–1304) zu **einem** `nmcli -t -f 802-11-wireless.bssid,ipv6.method,802-11-wireless.band con show uuid <uuid>` zusammenfassen (spart 2 Subprozesse pro Tick, siehe auch FUNC-02); Fehler-Dict-Fabrik `def _err(code, msg, detail=None)`.
- **Risikoreicher (nur mit Tests, siehe TEST-01):** Aufteilung in `py_modules/` (hardware.py, nmcli.py, streaming.py, updates.py, backend_switch.py); die zwei Switch-Worker über gemeinsame Phasen-Helfer zusammenführen.

---

### MAINT-03 — Toter Code

- **Kategorie:** Wartbarkeit · **Schweregrad: Info** · **Aufwand: S**
- **Fundstellen & Belege:**
  - `src/types.ts:148` (`timeout`) und `:150` (`parse_error`): Das Backend erzeugt nachweislich nur die Fehlercodes `iw_failed`, `nmcli_failed`, `no_wifi`, `unexpected`, `write_failed` (grep über alle `"error":`-Literale in main.py) — die beiden Einträge sind unerreichbar.
  - `src/types.ts:142`: Badge-Varianten `"locked"` und `"set"` werden nirgends erzeugt (nur `error/drifted/active/off/unknown`).
  - `main.py:1261,1279,1300`: `live.dns`, `live.ipv6_method`, `live.band` werden berechnet und übertragen, aber vom UI nie angezeigt (`connected_bssid`/`bssid_lock` ebenso, dienen aber intern der Drift-Logik).
  - `src/types.d.ts`: `*.svg/png/jpg`-Moduldeklarationen ohne ein einziges Asset im Repo.

**Empfehlung:** Entfernen bzw. — falls `parse_error` gewollt war — in FUNC-07 tatsächlich verdrahten.

---

### MAINT-04 — Namens-/Link-Inkonsistenzen Fork ↔ Upstream

- **Kategorie:** Dokumentation · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstellen:**
  - `plugin.json:2` nennt das Plugin „WiFi Optimizer Streaming", `src/index.tsx:908–909` registriert es als „WiFi Optimizer" (Name/TitleView).
  - Bug-Report-Links zeigen auf Upstream statt Fork: `src/index.tsx:93` (ErrorBoundary), `src/components/PanelFooter.tsx:58`.
  - `README.md:114–123`: Uninstall-Anleitung löscht `~/homebrew/plugins/WiFi\ Optimizer` — der Fork installiert aber nach `…/WiFi Optimizer Streaming` (install.sh:7,24); der Befehl entfernt das falsche/kein Verzeichnis.
  - `README.md:130`: „Building from source" klont das Upstream-Repo.
  - Toolchain-Versionen: README.md:127 „pnpm v9", `.vscode/tasks.json:9` installiert `pnpm@9`, CI nutzt pnpm 11 (release.yml:20). `pnpm audit` warnt zudem, dass der `pnpm.peerDependencyRules`-Block in package.json:25–29 von aktuellen pnpm-Versionen nicht mehr gelesen wird.

**Auswirkung:** Fork-Nutzer melden Bugs im falschen Repo, deinstallieren das falsche Verzeichnis, bauen aus dem falschen Quellstand.

**Empfehlung:** Fork-URLs/Namen konsequent durchziehen; Uninstall-Abschnitt für den Fork ergänzen; eine pnpm-Version festlegen (z. B. `packageManager`-Feld in package.json).

---

### TEST-01 — Keine automatisierten Tests; CI prüft nur Syntax

- **Kategorie:** Tests & Testbarkeit · **Schweregrad: Mittel** · **Aufwand: L (Grundgerüst: M)**
- **Fundstelle:** Repo-weit; CI-„Tests" sind `py_compile`/`bash -n` (release.yml:33–37)

**Beschreibung:** Null Testabdeckung für ein Root-Plugin mit nicht-trivialer Logik. Besonders testwürdig (und ohne Systemzugriff testbar):
- Versionsvergleich `check_for_update` (main.py:2102–2113) — Tuple-Parsing, `-beta`-Sonderfälle;
- Gate-Logik `_volatile_gate_open` + Watcher-Hysterese (main.py:525–529, 652–697);
- Settings-Merge/-Migration inkl. `streaming_apps`-Teilmerge (main.py:210–231);
- Parser für `iw`/`nmcli`-Ausgaben (Kanal-/BSSID-/IP-Parsing, main.py:1174–1304);
- Dispatcher-Python-Snippet (Gate-/Driver-Sanitisierung).

Die Architektur erschwert Tests: Alle Methoden rufen `subprocess` direkt und lesen globale Pfade. Ein injizierbarer Command-Runner (`self._run_cmd` ist bereits die einzige Engstelle — im Test ersetzbar) und Settings-Pfad-Parameter würden reichen.

**Empfehlung:** pytest-Suite für die o. g. reinen Funktionen; `_run_cmd` im Test monkeypatchen (Fixture mit aufgezeichneten iw/nmcli-Ausgaben). In CI vor dem Packaging ausführen.

---

### DEP-01 — 6 High-CVEs in der Dev-Build-Kette (`brace-expansion`)

- **Kategorie:** Abhängigkeiten · **Schweregrad: Niedrig** · **Aufwand: S**
- **Fundstelle:** `pnpm-lock.yaml` (Pfad: `@decky/rollup > rollup-plugin-delete > del > rimraf > glob > minimatch > brace-expansion`)

**Beschreibung:** `pnpm audit` meldet 6 × High (ReDoS/DoS in `brace-expansion` < 1.1.18 bzw. 2.x < 2.1.4; u. a. GHSA-rgw5-rvv9-x895). Betroffen ist ausschließlich die **Build-Zeit** (Rollup-Cleanup-Plugin); ins ausgelieferte `dist/index.js` gelangt davon nichts, und `pnpm audit --prod` ist sauber. Praktisches Risiko: minimal (DoS des eigenen Builds).

**Empfehlung:** `pnpm.overrides`/`overrides` auf `brace-expansion@^1.1.18` bzw. `^2.1.4` setzen oder auf ein @decky/rollup-Update warten; in CI `pnpm audit --prod --audit-level=high` als Gate aufnehmen.

---

### DEP-02 — LGPL-2.1-Abhängigkeiten werden in `dist/index.js` gebündelt

- **Kategorie:** Lizenzen (Hinweis, keine Rechtsberatung) · **Schweregrad: Info** · **Aufwand: S**
- **Fundstelle:** `package.json:13,21` (`@decky/ui`, `@decky/api` — Registry-Lizenz: LGPL-2.1); Projektlizenz BSD-3-Clause (LICENSE)

**Beschreibung:** Rollup bündelt die LGPL-Bibliotheken statisch in das ausgelieferte `dist/index.js`. Da das Plugin selbst quelloffen (BSD-3-Clause) ist und die Quellen samt Build-Anleitung verfügbar sind, sind die LGPL-Anforderungen (Relink-/Modifikationsmöglichkeit) praktisch erfüllt — im gesamten Decky-Ökosystem ist das das übliche Muster. Erwähnenswert ist nur, dass weder README noch Release die LGPL-Komponenten attribuieren.

**Empfehlung:** Kurzen „Third-party licenses"-Hinweis in README/Release-Notes aufnehmen. Keine weitere Aktion nötig, solange das Projekt quelloffen bleibt.

---

## 4. Quick Wins (hoher Nutzen, geringer Aufwand)

| # | Befund | Maßnahme | Aufwand |
|---|---|---|---|
| 1 | SEC-02 | Update-Skript via stdin an bash übergeben statt fester `/tmp`-Datei | S |
| 2 | REL-01 | CI-Guard „Tag == package.json-Version" | S |
| 3 | SEC-05 | Workflow auf `contents: read` + `persist-credentials: false`; Release-Step in eigenen Job mit `contents: write` | S |
| 4 | FUNC-02 (Teil) | `time.sleep(3)` → `await asyncio.sleep(3)` (main.py:1514) | S |
| 5 | FUNC-03 | DNS-Feld nicht überschreiben, solange fokussiert/editiert | S |
| 6 | FUNC-07 | Parse-Fehler in `_load_settings` loggen, defekte Datei sichern | S |
| 7 | FUNC-09 | `dict(DEFAULT_SETTINGS)` → `copy.deepcopy(DEFAULT_SETTINGS)` | S |
| 8 | FUNC-10 | ConfirmModal vor „Reset Settings" | S |
| 9 | MAINT-03 | Tote ERROR_MESSAGES-/Badge-Einträge entfernen | S |
| 10 | MAINT-04 | Fork-Links/-Namen und Uninstall-Doku korrigieren | S |
| 11 | SEC-06 | Regex-Whitelist für Remote-Versionsstrings | S |

## 5. Priorisierte Maßnahmenliste

1. **SEC-02** — `/tmp`-Update-Skript eliminieren (Hoch, S). Größter Risikoabbau pro Aufwand.
2. **SEC-01** — Root-Writes aus nutzerkontrollierten Verzeichnissen entfernen: `last_enforced` nach `/run`, `O_NOFOLLOW|O_EXCL` für Settings-Writes (Hoch, M).
3. **SEC-05 + REL-01** — CI härten: Permissions minimieren, `persist-credentials: false`, Tag/Version-Guard (Mittel, S). Zusammen in einem Workflow-PR machbar.
4. **FUNC-02** — Event-Loop entblocken: sofort den `time.sleep`-Fix, dann `_run_cmd`-Aufrufe in async-Methoden nach `asyncio.to_thread` verschieben, beginnend mit `get_status` (Mittel, S+M).
5. **FUNC-03 + FUNC-10** — UI-Fixes: DNS-Eingabe-Clobbering, Reset-Bestätigung (Mittel/Niedrig, S).
6. **FUNC-01** — Auto-Heal aus `get_status` in den expliziten Fix-Pfad verlagern (Mittel, M).
7. **SEC-03** — Checksummen-/Signaturprüfung für Self-Update und Installer (Mittel, M).
8. **SEC-04** — Dispatcher-`eval` durch positionsbasiertes `read` ersetzen (Mittel, S–M).
9. **MAINT-01** — Dispatcher aus den Python-Konstanten generieren (Mittel, M). Reduziert künftige Drift-Bugs strukturell.
10. **TEST-01** — pytest-Grundgerüst für Versionsvergleich, Gate-Logik, Parser, Settings-Merge; in CI verankern (Mittel, M–L). Voraussetzung für Punkt 11.
11. **MAINT-02** — Modularisierung nach `py_modules/`, `get_status`-Zerlegung, nmcli-Batching (Mittel, L). Erst nach Testabdeckung angehen.
12. **Rest** — FUNC-04/05/06/08/11, REL-02, DEP-01, SEC-07, MAINT-04-Restpunkte nach Gelegenheit.

---

## Anhang: Positivbefunde (zur Einordnung)

- Kein `shell=True`, keine String-Konkatenation in Kommandos; alle Binärpfade absolut (verhindert PATH-Hijacking).
- Atomare Settings-Writes (`tmp` + `os.replace`, main.py:236–240) und mtime-basierter Settings-Cache mit Deep-Copy-Isolation (main.py:207–231).
- Der Watcher/Setter-Race wurde bereits erkannt und korrekt behoben (Reload nach `await`, main.py:664–670; Commit `7621555`).
- Frontend: React-Escaping durchgängig, ErrorBoundary, Sichtbarkeits-gesteuerte Poll-Pausen, Re-Entrancy-Guards (`busyRef`), GitHub-API-Dedupe.
- `.vscode/settings.json` (mit Deck-Passwort) ist gitignoriert; `defsettings.json` enthält nur Platzhalter — keine hartcodierten Secrets im Repo gefunden.
- Log-Rotation mit Schutz der aktiven Logdatei (main.py:758–791); Fehler-Logging ratenbegrenzt (main.py:708–714).
