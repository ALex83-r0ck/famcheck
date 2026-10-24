# Roadmap

## Erledigt

- Scan per ADB, nur lesend, mit Hash-Protokoll
- Plug & Play (`watch`) mit Freigabe am Handy per Fingerabdruck/PIN
- Dashboard: Status-Kacheln, Verlauf, Gerätedetails
- Stufe 1: Uploads pro App, Kontenanzahl, Geräteverwaltung, Displaysperre,
  Sonderrechte, Akku-Ausnahmen, Standard-SMS-App
- Stufe 2: Indikatoren von Echap + MVT (Paketnamen, Signaturen, APK-Hashes), Prüfung der
  App-Dateien aus fremder Quelle, optional MalwareBazaar, Messenger-Mods, VPN, Privates DNS,
  Play Protect
- Hinweis in Dashboard und CLI, wenn die Indikatorliste fehlt oder älter als 30 Tage ist

## Als Nächstes

- [ ] Erster Abgleich mit echten Geräten (Samsung, Xiaomi, Pixel): dumpsys-Formate prüfen

## feat: Begleit-App auf dem Handy

Kleine, sparsame Android-App, die zwischen den PC-Scans selbst auswertet,
was ADB nicht sehen kann: welche App wann wohin Daten schickt.

Offene Fragen, bevor wir anfangen:

- **Technik:** Live-Netzwerkdaten ohne Root gehen nur über die VPN-Schnittstelle
  von Android (wie PCAPdroid). Dann kann keine andere VPN-App gleichzeitig laufen,
  und Android zeigt dauerhaft ein Schlüssel-Symbol an.
- **Akku/Platz:** Nur Metadaten (App, Ziel-Domain, Datenmenge), keine Inhalte.
  Lokale Speicherung mit fester Obergrenze.
- **Vertrauen:** Eine App, die den Datenverkehr der Familie sieht, ist selbst
  heikel. Sie muss sichtbar, abschaltbar und ohne Internetzugang zu einem Server sein.
  Die Auswertung holt sich FamCheck beim nächsten Anstecken per USB.
- **Alternative prüfen:** Reicht PCAPdroid (Open Source) mit Export, den FamCheck
  einliest? Das spart eine eigene App.
