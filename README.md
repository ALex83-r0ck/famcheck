# FamCheck

Prüft die Android-Handys der Familie per ADB auf Stalkerware und gefährliche Einstellungen
und zeigt den Verlauf in einem lokalen Dashboard.

- **CLI** (`scan`): liest das Gerät aus. Nur lesend, es wird nichts auf dem Handy verändert
  (ein Test prüft das).
- **Beheben** (`fix`): getrennter Befehl, ändert nur mit Rückfrage und nur Umkehrbares.
- **Dashboard** (`serve`): Übersicht aller Geräte, Befunde, Änderungen seit dem letzten Scan.
  Läuft nur auf `127.0.0.1`, ist also nicht aus dem Netzwerk erreichbar.
- **Nachvollziehbar:** jede Rohausgabe des Geräts wird einzeln mit Zeitstempel und SHA-256 protokolliert.

> Hinweis: Die Familienmitglieder sollten wissen, dass ihr Handy geprüft wird.

## Schnellstart Windows (Plug & Play)

1. [Python](https://www.python.org/downloads/) installieren (Haken bei „Add python.exe to PATH“).
2. **`FamCheck.bat` doppelklicken.** Beim ersten Start wird alles eingerichtet, inklusive `adb`
   (dabei wird einmal die Zustimmung zur Android SDK-Lizenz abgefragt).
3. Der Browser öffnet das Dashboard. Jetzt nacheinander die Handys anstecken:
   - Handy entsperren (Fingerabdruck/PIN) und **„USB-Debugging zulassen“** tippen.
   - **„Von diesem Computer immer zulassen“ NICHT anhaken.** Dann muss der Besitzer bei jedem
     Anstecken neu zustimmen. Das ist die eigentliche Freigabe per Fingerabdruck/PIN.
   - Der Scan startet von selbst. Ist das Handy gesperrt, wartet FamCheck, bis es entsperrt wird.
4. Kabel abziehen, nächstes Handy. Danach am Handy **USB-Debugging wieder ausschalten.**

Vorher einmalig je Handy: Einstellungen → Telefoninfo → 7× auf „Build-Nummer“ tippen →
Entwickleroptionen → USB-Debugging an.

**Handy wird nicht erkannt?** Unter Windows fehlt oft der USB-Treiber:
Samsung → „Samsung Android USB Driver“, Pixel → „Google USB Driver“.
Außerdem: Kabel muss Daten übertragen können (manche Kabel laden nur).

## Installation von Hand (alle Systeme)

```bash
git clone https://github.com/ALex83-r0ck/famcheck.git
cd famcheck
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m famcheck setup                              # lädt adb herunter (oder eigenes adb im PATH)
```

Unter Windows bei „Ausführung von Skripts ist deaktiviert“ einmalig:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## Befehle

| Befehl | Zweck |
|---|---|
| `python -m famcheck watch` | Plug & Play: Dashboard + automatischer Scan beim Anstecken |
| `python -m famcheck scan [--label "Handy Papa"] [--all]` | Einmal-Scan der angeschlossenen Geräte |
| `python -m famcheck serve` | Nur das Dashboard (http://127.0.0.1:8765) |
| `python -m famcheck diff cases/<alt> cases/<neu>` | Zwei Scans im Terminal vergleichen |
| `python -m famcheck update-ioc` | Indikatorlisten (Echap + MVT) aktualisieren, braucht `pyyaml` |
| `python -m famcheck setup` | adb herunterladen |
| `python -m famcheck fix [--dry-run]` | Befunde am Handy beheben, mit Rückfrage (siehe unten) |
| `python -m famcheck fix --undo cases/<fix-ordner>` | einen fix-Durchlauf rückgängig machen |

`adb` wird in dieser Reihenfolge gesucht: Umgebungsvariable `FAMCHECK_ADB` → Ordner
`platform-tools` im Projektordner oder direkt daneben → von `setup` installiert (`%LOCALAPPDATA%\famcheck\platform-tools`, sonst `~/.famcheck/platform-tools`) → `PATH`.

**Tipp:** Regelmäßig scannen (z. B. monatlich). Das Dashboard zeigt neu installierte Apps,
neue Berechtigungen und neue Bedienungshilfen seit dem letzten Mal. Genau so fällt
nachträglich installierte Stalkerware auf. Ein Gerät behält den Namen aus seinem letzten
Scan, nach einem `scan --label "Handy Papa"` erkennt `watch` es also wieder.

## Was wird geprüft

| Prüfung | Warum |
|---|---|
| Paketnamen gegen die Indikatoren von [Echap](https://github.com/AssoEchap/stalkerware-indicators) und [MVT](https://github.com/mvt-project/mvt-indicators) | bekannte Stalker- und Spyware (mSpy, TheTruthSpy, BTMOB, NoviSpy, …) |
| App-Dateien aus fremder Quelle: SHA-256 und Signaturzertifikat gegen dieselben Listen | erkennt auch **umbenannte** Spyware an ihrer Signatur |
| Store-Apps: SHA-256, auf dem Handy berechnet, gegen dieselben Listen; VirusTotal-Link im Bericht | Türöffner (falsche PDF-Reader, QR-Scanner) kommen oft aus dem Play Store |
| Aktive Bedienungshilfen von Dritt-Apps | Bildschirm mitlesen / Keylogging |
| Benachrichtigungszugriff, Geräteadministratoren | Nachrichten mitlesen, Deinstallationsschutz |
| Apps ohne App-Symbol mit Kamera/Mikrofon/SMS/Standort | typisches Versteckverhalten |
| Apps außerhalb eines Stores installiert | Stalkerware kommt fast immer als APK |
| Bootloader entsperrt, Root, Proxy, Always-on-VPN | Manipulation des Systems bzw. Datenverkehrs |
| Alter des Sicherheitspatches, (kabelloses) Debugging | Angriffsfläche |
| Hochgeladene Datenmenge pro App (gesamt / im Hintergrund) | heimliches Hochladen von Fotos und Daten |
| Anzahl der Konten (nur Anzahl, Namen werden schon in den Rohdaten geschwärzt) | ein fremdes Google-Konto bekommt die Fotosicherung |
| Fremde Geräteverwaltung (Device Owner), Arbeitsprofile | fast volle Kontrolle über das Gerät |
| Keine Displaysperre | jeder kann in Minuten Stalkerware installieren |
| Sonderrechte: über anderen Apps einblenden, Apps installieren, Zugriff auf alle Dateien | Banking-Trojaner, Nachladen weiterer Apps |
| Vom Akkusparen ausgenommene Apps aus fremder Quelle | Spyware hält sich so dauerhaft am Laufen |
| Fremde Standard-SMS-App | SMS und Bestätigungscodes abfangen |
| Inoffizielle WhatsApp-Mods (GB/Yo/FMWhatsApp), Messenger außerhalb eines Stores | Mods enthalten häufig Schadcode |
| Aktive VPN-Verbindung, Privates DNS | gesamter Datenverkehr läuft über fremde Stelle |
| Play Protect aus, ungeprüfte USB-Installationen | Schutz von Google umgangen |

### Kann FamCheck das Gerät überhaupt lesen?

Jeder Scan prüft, ob er plausibel ist. Ist er es nicht, zeigt FamCheck nie „Alles in Ordnung“:

- **Hoch: „Scan unvollständig: …“**, wenn Grundlegendes fehlt: weniger als 20 Pakete (echte Geräte haben
  mehrere Hundert), keine lesbaren App-Rechte, keine Geräteeigenschaften, Zeitüberschreitungen, oder das
  Gerät meldet USB-Debugging nicht als eingeschaltet, obwohl die Verbindung genau darüber läuft.
- **Niedrig: „Teilprüfung nicht möglich: …“**, wenn einzelne Prüfungen ausfallen (Uploads, Konten,
  Displaysperre, Geräteverwaltung, versteckte Apps).

Das ist kein Hinweis auf Spyware, sondern auf eine Lücke beim Auslesen. Die Rohausgabe liegt unter `raw/`.
Ist eine Lücke bei einem Modell normal, ordnest du sie einmal als „Bekannt“ ein.

## Ergebnisordner

Liegt unter `cases/` und ist per `.gitignore` vom Repo ausgeschlossen.

```
cases/20261024-101500_Handy_Papa_<serial>/
  raw/            jede Geräteausgabe einzeln
  manifest.csv    Befehl, Zeit, Exit-Code, SHA-256 je Rohdatei
  caselog.txt     Ablauf + Hashes der Ergebnisdateien
  data.json       ausgewertete Gerätedaten (Basis für Vergleiche)
  findings.json   Befunde
  report.html     Einzelbericht
```

## Projektstruktur

```
famcheck/
  adb.py        ADB-Zugriff, protokolliert jede Ausgabe mit Hash
  collect.py    liest Eigenschaften, Einstellungen, Apps, Rechte aus
  analyze.py    Heuristiken → Befunde
  report.py     HTML-Einzelbericht, Vergleich zweier Scans
  web.py        lokales Dashboard: Status-Kacheln, Verlauf, Gerätedetails (nur Standardbibliothek)
  static/app.js Filter, Suche, Auf-/Zuklappen, Live-Update, Einordnen ohne Neuladen
  style.py      gemeinsames Design von Dashboard und Bericht
  guides.py     Schritt-für-Schritt-Anleitungen und Aufräum-Checkliste je Hersteller
  decisions.py  Einordnung von Befunden (Bekannt/Erledigt/Beobachten) mit Protokoll
  fix.py        Befunde beheben: Plan aus dem Live-Zustand, Rückfrage, Protokoll, Undo
  watch.py      Plug & Play: wartet auf Freigabe am Handy, scannt automatisch
  apk.py        Signaturzertifikat aus APKs lesen (v1/v2/v3), ohne Zusatzprogramme
  iocs.py       Indikator-Datenbank bauen/laden (Echap + MVT)
  online.py     optionaler MalwareBazaar-Abgleich (nur Hashes)
  data/iocs.json Indikator-Datenbank (Paketnamen, Zertifikate, APK-Hashes)
tests/
  fake_adb.py   simuliert ein sauberes und ein infiziertes Handy
  test_smoke.py    End-to-End-Test: python -m unittest discover tests
  test_plugplay.py Watch-Modus, adb-Setup, Geräteerkennung
  test_online.py   MalwareBazaar gegen lokalen Fake-Server
  test_decisions.py Einordnung: Regeln, Dashboard-Formular, Schutz gegen gefälschte Anfragen
  test_fix.py      Beheben: Scan schreibt nichts, Trockenlauf, Ablehnen, gesperrtes Handy, Undo
  test_ui.py       App-Tabelle, Ortszeit, Umbenennen
  fixtures/        zwei winzige signierte Test-APKs (v1 und v2)
FamCheck.bat    Doppelklick-Start für Windows
```

## Geplant

Siehe [ROADMAP.md](ROADMAP.md).

## Dashboard bedienen

- **Befunde aufklappen:** Ein Klick auf einen Befund zeigt Details, Hinweise zum Beheben und das Einordnen.
  Mit „Alle auf“ und „Alle zu“ geht es für alle auf einmal.
- **Filtern und suchen:** Die Schwere-Chips blenden Stufen ein und aus. Die Suche findet App-Namen
  und Befundtexte, die Sortierung geht nach Schwere, Titel oder App. Die Auswahl bleibt erhalten,
  solange der Tab offen ist.
- **Live:** Ist ein neuer Scan fertig (z. B. über `watch`) oder hat sich eine Einordnung geändert,
  aktualisiert sich die Seite von selbst. Aufgeklappte Befunde, Filter und Scrollposition bleiben dabei
  erhalten. Tippst du gerade eine Notiz, erscheint stattdessen ein Hinweis „Neue Scan-Daten sind da“.
- **Einordnen ohne Neuladen:** Speichern bestätigt ein kurzer Hinweis unten rechts.
- **Apps im Bericht:** Neueste zuerst, „neu“ = in den 14 Tagen vor dem Scan installiert. Quelle im Klartext
  („Google Play“, „Galaxy Store“, „fremde Quelle“), vorinstallierte Apps als „ab Werk“. Filter: Neu,
  Fremde Quelle, Ohne App-Symbol, Mit heiklen Rechten. „Play Store“ zeigt Name, Entwickler und Bewertungen.
- **Umbenennen:** Auf der Geräteseite unter „Umbenennen“ (z. B. „moto_g06“ → „Handy Alex“). Gilt für alle
  Scans des Geräts und für neue Scans im `watch`-Modus. Die Scans selbst bleiben unverändert.
- **Vergleichen:** Auf der Geräteseite unter „Alle Scans“ zwei beliebige Scans auswählen, oder bei einem
  Scan auf „Vergleich“ klicken (mit dem Scan davor). Zeigt neue und entfernte Apps mit Datum, neue heikle
  Rechte, Konten und welche Befunde dazugekommen oder verschwunden sind. Ersetzt `famcheck diff`.
- **Schritt für Schritt:** Viele Befunde zeigen beim Aufklappen eine nummerierte Anleitung mit dem Menüpfad
  des Herstellers (Samsung bzw. Standard-Android wie Pixel und Motorola) und einem Suchbegriff für die Suche in
  den Einstellungen. Bei Apps mit kritischem Befund (Stalkerware) bewusst keine Anleitung.
- **Aufräumen:** Unter dem Gerätenamen steht „Nach dem Scan: Handy aufräumen“, eine Checkliste von
  Kabel abziehen bis Entwicklermodus aus (bei Samsung zusätzlich: Automatische Sperre wieder an).
- **Zeiten** stehen in deutscher Ortszeit; in den Daten (`data.json`, Logs) bleibt UTC.

Alles funktioniert auch ohne JavaScript, dann ohne Filter und ohne Live-Update.

## Befunde einordnen

Auf der Geräteseite im Dashboard lässt sich jeder Befund über „Einordnen …“ markieren, optional mit Notiz:

| Einordnung | Wirkung |
|---|---|
| **Bekannt, in Ordnung** | zählt nicht mehr zur Ampel, **bis sich der Befund verändert** (höhere Stufe oder neuer Inhalt, z. B. neue Rechte). Geänderte Zahlen wie MB-Mengen zählen nicht als Veränderung. |
| **Erledigt** | zählt nicht mehr bis zum nächsten Scan. Ist der Befund dann noch da, erscheint er als „wieder offen“. |
| **Beobachten** | bleibt in der Ampel, ist nur markiert. |

Einordnen ändert **nichts am Handy**. Gespeichert wird in `cases/decisions.json`, jede Änderung
zusätzlich in `cases/decisions_log.jsonl` (wer hat wann was als in Ordnung erklärt).
Die Scan-Historie bleibt unverändert, so wie gescannt.

## Befunde beheben (`fix`)

```powershell
python -m famcheck fix --dry-run     # erst ansehen, was passieren würde
python -m famcheck fix               # dann wirklich
```

Das Handy muss angesteckt und **entsperrt** sein. FamCheck liest den aktuellen Zustand, zeigt eine
nummerierte Liste mit den genauen ADB-Befehlen und fragt **vor jeder Änderung** einzeln nach (`j`).

| Automatisch (umkehrbar) | Nur als Anleitung |
|---|---|
| Kabelloses Debugging, Proxy, Privates DNS, Prüfung von USB-Installationen | Fremdverwaltung, Arbeitsprofil, Geräteadministrator |
| Bedienungshilfe oder Benachrichtigungszugriff einer App abschalten | Displaysperre (die Person setzt ihre PIN selbst) |
| Sonderrechte entziehen (Einblenden, Apps installieren, alle Dateien) | Standard-SMS-App, Messenger-Mods (Chats erst sichern) |
| Kamera-/Mikrofon-/Standort-/SMS-Rechte entziehen, Akku-Ausnahme aufheben | Updates, Play Protect, unbekannte Konten |
| App **deaktivieren** (bleibt installiert, Daten bleiben) | |
| USB-Debugging aus (immer zuletzt, trennt die Verbindung, nur am Handy umkehrbar) | |

**Nie:** deinstallieren oder Daten löschen. **Und nichts für Apps mit kritischem Befund** (bekannte
Spyware): Wer sie installiert hat, merkt das Entfernen. FamCheck zeigt dann stattdessen einen
Sicherheitshinweis.

Jeder Durchlauf bekommt einen eigenen Ordner `cases/<zeit>_fix_<name>_<serial>/` mit Rohdaten,
`manifest.csv` und `fixlog.json` (inklusive der Befehle zum Rückgängigmachen). Behobene Befunde werden
im Dashboard als „Erledigt“ eingeordnet. Der nächste Scan zeigt, ob es wirklich geklappt hat.

## App-Dateien und MalwareBazaar

Bei jedem Scan werden die App-Dateien (APKs) von Apps **aus fremder Quelle** kurz auf den PC
kopiert, ihr SHA-256 und Signaturzertifikat berechnet und die Datei sofort wieder gelöscht.
Im `manifest.csv` steht jeder Kopiervorgang mit Hash. Ausschalten mit `--no-apk-check`.
Schlägt der Virenschutz auf dem PC dabei an, ist das bereits ein Hinweis.

Apps aus einem Store werden **nicht** kopiert: Das Handy berechnet ihre SHA-256 selbst (`sha256sum`).
Im Bericht steht bei jeder geprüften App ein Link „VirusTotal“. Er überträgt nur den Fingerabdruck,
keine Datei.

Optional zusätzlich online prüfen, nur die Hashes werden gesendet:

1. Kostenlosen Schlüssel holen: https://auth.abuse.ch/
2. `$env:FAMCHECK_ABUSECH_KEY = "<schlüssel>"` (PowerShell) bzw. `export FAMCHECK_ABUSECH_KEY=...`
3. `python -m famcheck scan --malwarebazaar` oder `watch --malwarebazaar`

Jede gesendete Prüfsumme steht im `caselog.txt`.

## Sicherheit von FamCheck selbst

FamCheck verarbeitet Daten von Geräten, die manipuliert sein könnten. Deshalb:

- **Gerätedaten gelten als feindlich:** Seriennummern werden vor der Verwendung in Ordnernamen bereinigt,
  alles Angezeigte wird escaped, APKs werden vor dem Kopieren auf ihre Größe geprüft und nie aufbewahrt.
- **Dashboard:** nur `127.0.0.1`, Host- und Origin-Prüfung (gegen DNS-Rebinding), Token gegen gefälschte
  Formulare, darf nicht in fremde Seiten eingebettet werden (Clickjacking), JavaScript nur als eigene Datei
  (`script-src 'self'`, kein eingebetteter Code), kein Cache.
- **`fix --undo`** führt nur die Befehlsarten aus, die `fix` selbst schreibt. Eine manipulierte
  `fixlog.json` wird abgelehnt.
- `tests/test_security.py` spielt diese Angriffe nach.

- **Anmeldung per Link:** `serve` und `watch` öffnen das Dashboard über einen Link mit Schlüssel, der bei
  jedem Start neu erzeugt wird, und setzen damit ein Cookie (`HttpOnly`, `SameSite=Strict`). Ohne Cookie
  zeigt das Dashboard nur einen Hinweis, auch anderen Windows-Konten auf demselben PC nicht.
  Den Link zeigt das Terminal an, falls sich der Browser nicht von selbst öffnet.

**Noch offen:** Die Ordner `cases/` liegen unverschlüsselt auf der Festplatte (BitLocker empfohlen).

## Grenzen

- Das sind Heuristiken: „Kein Befund“ heißt nicht „garantiert sauber“. Staatstrojaner wie Pegasus
  findet FamCheck nicht. Bei solchem Verdacht: [MVT](https://github.com/mvt-project/mvt) mit
  [AndroidQF](https://github.com/mvt-project/androidqf).
- Das Signaturzertifikat wird nur für Apps aus fremder Quelle geprüft, bei Store-Apps nur der Hash.
  Ein Hash erkennt nur exakt bekannte Dateien; neu gebaute Schadsoftware erkennt nur die Heuristik.
- Upload-Mengen kommen aus der Android-Statistik und reichen meist nur einige Tage bis Wochen zurück.
- Die Displaysperre wird erst ab Android 11 erkannt, auf älteren Geräten fehlt diese Prüfung.
- Die Ausgaben von `dumpsys` unterscheiden sich je nach Hersteller und Android-Version.
  Bisher nur mit simulierten Geräten getestet.
- **Bei einem echten Fund nicht sofort löschen.** Wer Stalkerware installiert hat, merkt das Entfernen.
  Zuerst die Sicherheit der betroffenen Person klären (Hilfetelefon Gewalt gegen Frauen: 116 016).
