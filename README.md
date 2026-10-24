# FamCheck

Prüft die Android-Handys der Familie per ADB auf Stalkerware und gefährliche Einstellungen
und zeigt den Verlauf in einem lokalen Dashboard.

- **CLI** (`scan`): liest das Gerät aus. Nur lesend, es wird nichts auf dem Handy verändert.
- **Dashboard** (`serve`): Übersicht aller Geräte, Befunde, Änderungen seit dem letzten Scan.
  Läuft nur auf `127.0.0.1`, ist also nicht aus dem Netzwerk erreichbar.
- **Nachvollziehbar:** jede Rohausgabe des Geräts wird einzeln mit Zeitstempel und SHA-256 protokolliert.

> Hinweis: Die Familienmitglieder sollten wissen, dass ihr Handy geprüft wird.

## Installation

```bash
git clone https://github.com/ALex83-r0ck/famcheck.git
cd famcheck
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Außerdem nötig: die [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools),
damit `adb` im PATH liegt (oder Pfad über die Umgebungsvariable `FAMCHECK_ADB` setzen).

## Benutzung

1. Handy: Entwickleroptionen → **USB-Debugging an**, per USB anstecken, „Zulassen“ bestätigen.
2. Scannen:

   ```bash
   python -m famcheck update-ioc                    # Stalkerware-Liste aktualisieren
   python -m famcheck scan --label "Handy Papa"     # ein Gerät
   python -m famcheck scan --all                    # alle angeschlossenen Geräte
   ```

3. Dashboard öffnen:

   ```bash
   python -m famcheck serve                         # → http://127.0.0.1:8765
   ```

4. Handy: **USB-Debugging wieder ausschalten.**

Zwei Scans im Terminal vergleichen: `python -m famcheck diff cases/<alt> cases/<neu>`

**Tipp:** Regelmäßig scannen (z. B. monatlich). Das Dashboard zeigt dann neu installierte Apps,
neue Berechtigungen und neue Bedienungshilfen seit dem letzten Mal. Genau so fällt
nachträglich installierte Stalkerware auf.

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
  data/ioc.yaml Stalkerware-Indikatoren (Echap)
tests/
  fake_adb.py   simuliert ein sauberes und ein infiziertes Handy
  test_smoke.py End-to-End-Test: python -m unittest discover tests
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
