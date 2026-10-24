"""Plug & play: waits for phones, scans each one once the owner has unlocked it and allowed USB debugging."""

import json
import time
import webbrowser
from pathlib import Path

from .adb import AdbError, is_locked, list_devices

POLL_SECONDS = 2


def _known_label(cases_root: Path, serial: str) -> str | None:
    """Reuses the label of the last scan of this device (e.g. 'Handy Papa')."""
    for case in sorted(cases_root.glob(f"*_{serial}"), reverse=True):
        try:
            return json.loads((case / "findings.json").read_text(encoding="utf-8"))["meta"]["label"]
        except (OSError, KeyError, ValueError):
            continue
    return None


def watch(cases_root: Path, port: int | None, scan_device) -> None:
    if port:
        from .web import start_background
        url = f"http://127.0.0.1:{port}"
        try:
            start_background(cases_root, port)
            print(f"Dashboard: {url}")
        except OSError:
            print(f"Port {port} ist belegt (läuft das Dashboard schon?). Öffne {url}")
        webbrowser.open(url)

    print("\nWarte auf Handys. Einfach per USB anstecken. (Beenden: Strg+C)\n")
    done: set[str] = set()      # scanned while plugged in; rescanned after replugging
    told: dict[str, str] = {}   # last hint per device, so it is printed only once

    def hint(serial, key, text):
        if told.get(serial) != key:
            told[serial] = key
            print(text)

    try:
        while True:
            try:
                devices = {d["serial"]: d for d in list_devices()}
            except AdbError:
                raise
            except Exception as e:  # adb hiccup, e.g. daemon restarting
                print(f"  (adb: {e})")
                time.sleep(POLL_SECONDS)
                continue

            for serial in list(done | set(told)):
                if serial not in devices:
                    if serial in done:
                        print(f"[{serial}] abgezogen.")
                    done.discard(serial)
                    told.pop(serial, None)

            for serial, d in devices.items():
                if serial in done:
                    continue
                name = _known_label(cases_root, serial) or d["model"] or serial
                if d["state"] == "unauthorized":
                    hint(serial, "auth", f"[{name}] Bitte am Handy entsperren (Fingerabdruck/PIN) und "
                         "„USB-Debugging zulassen“ tippen.\n"
                         "         Tipp: „Immer zulassen“ NICHT anhaken, dann wird jedes Mal gefragt.")
                elif d["state"] != "device":
                    hint(serial, d["state"], f"[{name}] Status: {d['state']}. Kabel/USB-Modus prüfen.")
                elif is_locked(serial):
                    hint(serial, "locked", f"[{name}] Handy ist gesperrt. Bitte mit Fingerabdruck/PIN entsperren.")
                else:
                    print(f"\n[{name}] Freigegeben, Scan startet ...")
                    scan_device(serial, name, cases_root)
                    print(f"[{name}] Fertig. Kabel abziehen und danach USB-Debugging am Handy ausschalten.\n")
                    done.add(serial)
                    told.pop(serial, None)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nBeendet.")
