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
| `python -m famcheck update-ioc` | Stalkerware-Liste aktualisieren |
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
| Paketnamen gegen die [Echap Stalkerware-Indikatoren](https://github.com/AssoEchap/stalkerware-indicators) | bekannte Stalkerware (mSpy, TheTruthSpy, …) |
| Aktive Bedienungshilfen von Dritt-Apps | Bildschirm mitlesen / Keylogging |
| Benachrichtigungszugriff, Geräteadministratoren | Nachrichten mitlesen, Deinstallationsschutz |
| Apps ohne App-Symbol mit Kamera/Mikrofon/SMS/Standort | typisches Versteckverhalten |
| Apps außerhalb eines Stores installiert | Stalkerware kommt fast immer als APK |
| Bootloader entsperrt, Root, Proxy, Always-on-VPN | Manipulation des Systems bzw. Datenverkehrs |
| Alter des Sicherheitspatches, (kabelloses) Debugging | Angriffsfläche |

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
  web.py        lokales Dashboard (nur Python-Standardbibliothek)
  watch.py      Plug & Play: wartet auf Freigabe am Handy, scannt automatisch
  data/ioc.yaml Stalkerware-Indikatoren (Echap)
tests/
  fake_adb.py   simuliert ein sauberes und ein infiziertes Handy
  test_smoke.py    End-to-End-Test: python -m unittest discover tests
  test_plugplay.py Watch-Modus, adb-Setup, Geräteerkennung
FamCheck.bat    Doppelklick-Start für Windows
```

## Grenzen

- Das sind Heuristiken: „Kein Befund“ heißt nicht „garantiert sauber“. Staatstrojaner wie Pegasus
  findet FamCheck nicht. Bei solchem Verdacht: [MVT](https://github.com/mvt-project/mvt) mit
  [AndroidQF](https://github.com/mvt-project/androidqf).
- Stalkerware wird nur über den Paketnamen erkannt, nicht über das Signaturzertifikat.
  Umbenannte Varianten fallen meist trotzdem über die Heuristiken auf.
- Die Ausgaben von `dumpsys` unterscheiden sich je nach Hersteller und Android-Version.
  Bisher nur mit simulierten Geräten getestet.
- **Bei einem echten Fund nicht sofort löschen.** Wer Stalkerware installiert hat, merkt das Entfernen.
  Zuerst die Sicherheit der betroffenen Person klären (Hilfetelefon Gewalt gegen Frauen: 116 016).
