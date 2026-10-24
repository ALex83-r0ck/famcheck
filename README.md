# FamCheck

Prüft die Android-Handys der Familie per ADB auf Stalkerware und gefährliche Einstellungen
und zeigt den Verlauf in einem lokalen Dashboard.

- **CLI** (`scan`): liest das Gerät aus. Nur lesend, es wird nichts auf dem Handy verändert.
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
  decisions.py  Einordnung von Befunden (Bekannt/Erledigt/Beobachten) mit Protokoll
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
  fixtures/        zwei winzige signierte Test-APKs (v1 und v2)
FamCheck.bat    Doppelklick-Start für Windows
```

## Geplant

Siehe [ROADMAP.md](ROADMAP.md).

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

## App-Dateien und MalwareBazaar

Bei jedem Scan werden die App-Dateien (APKs) von Apps **aus fremder Quelle** kurz auf den PC
kopiert, ihr SHA-256 und Signaturzertifikat berechnet und die Datei sofort wieder gelöscht.
Im `manifest.csv` steht jeder Kopiervorgang mit Hash. Ausschalten mit `--no-apk-check`.
Schlägt der Virenschutz auf dem PC dabei an, ist das bereits ein Hinweis.

Optional zusätzlich online prüfen, nur die Hashes werden gesendet:

1. Kostenlosen Schlüssel holen: https://auth.abuse.ch/
2. `$env:FAMCHECK_ABUSECH_KEY = "<schlüssel>"` (PowerShell) bzw. `export FAMCHECK_ABUSECH_KEY=...`
3. `python -m famcheck scan --malwarebazaar` oder `watch --malwarebazaar`

Jede gesendete Prüfsumme steht im `caselog.txt`.

## Grenzen

- Das sind Heuristiken: „Kein Befund“ heißt nicht „garantiert sauber“. Staatstrojaner wie Pegasus
  findet FamCheck nicht. Bei solchem Verdacht: [MVT](https://github.com/mvt-project/mvt) mit
  [AndroidQF](https://github.com/mvt-project/androidqf).
- Signatur und Hash werden nur für Apps aus fremder Quelle geprüft (Apps aus dem Play Store
  werden nicht vom Handy kopiert). Neu signierte Spyware erkennt nur noch die Heuristik.
- Upload-Mengen kommen aus der Android-Statistik und reichen meist nur einige Tage bis Wochen zurück.
- Die Displaysperre wird erst ab Android 11 erkannt, auf älteren Geräten fehlt diese Prüfung.
- Die Ausgaben von `dumpsys` unterscheiden sich je nach Hersteller und Android-Version.
  Bisher nur mit simulierten Geräten getestet.
- **Bei einem echten Fund nicht sofort löschen.** Wer Stalkerware installiert hat, merkt das Entfernen.
  Zuerst die Sicherheit der betroffenen Person klären (Hilfetelefon Gewalt gegen Frauen: 116 016).
