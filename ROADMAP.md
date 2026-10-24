# Roadmap

## Erledigt

- Scan per ADB, nur lesend, mit Hash-Protokoll
- Plug & Play (`watch`) mit Freigabe am Handy per Fingerabdruck/PIN
- Dashboard: Status-Kacheln, Verlauf, Gerätedetails
- Stufe 1: Uploads pro App, Kontenanzahl, Geräteverwaltung, Displaysperre,
  Sonderrechte, Akku-Ausnahmen, Standard-SMS-App

## Als Nächstes: Stufe 2 (breitere Erkennung)

- [ ] Zusätzliche Indikatorlisten von MVT (Pegasus, Predator, …)
- [ ] APKs von Apps aus fremder Quelle per SHA-256 mit MalwareBazaar abgleichen
      (nur der Hash verlässt den PC, nie die App selbst)
- [ ] Modifizierte Messenger erkennen (GB WhatsApp, WhatsApp Plus, …)
- [ ] Private DNS, VPN-Apps, abgeschaltetes Play Protect

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
