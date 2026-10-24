# Test-APKs

Winzige APKs nur zum Testen der Signaturauswertung. Sie enthalten keinen ausführbaren Code.

| Datei | Inhalt | Erwartetes Zertifikat (SHA-1) | Gegengeprüft mit |
|---|---|---|---|
| `v1-signed.apk` | mit `jarsigner` signiert (Schema v1, Testschlüssel „CN=FamCheck Test“) | `073e7ff2c484fd14d28b5c18880394d2552093cc` | `keytool -printcert -jarfile` |
| `v2-signed.apk` | Mini-ZIP mit dem v2-Signaturblock aus `settings_apk-debug.apk` (npm-Paket `io.appium.settings` 8.4.3, Apache-2.0). Die Signatur passt nicht zum Inhalt, FamCheck liest aber nur das Zertifikat. | `8604d19f51ab170a6781666b2c8ec51237b5a788` | androguard 4.1.4 |
