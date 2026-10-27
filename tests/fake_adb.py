#!/usr/bin/env python3
"""Fake adb for tests: SAUBER01 = clean phone, INFIZIERT01 = phone with stalkerware.

FAKE_ADB_NEWAPP=1 adds an extra sideloaded app and a second Google account to SAUBER01
(simulates a change between scans).
FAKE_ADB_STATE=<file.json> makes it stateful: setting writes are remembered and every writing
command is logged under "writes", so tests can check exactly what was changed on the "phone".
FAKE_ADB_LOCKED=1 reports a locked screen.
FAKE_ADB_HUGE=1 reports every APK as ~1 TB (size check before pulling).
FAKE_ADB_BROKEN=1 returns empty output for properties, package lists and settings (unreadable device).
FAKE_ADB_NO_NETSTATS=1 returns no data usage statistics.
FAKE_ADB_SDK=<n> overrides the Android API level (default 33, INFIZIERT01 31).
FAKE_ADB_CRLF=1 ends lines with \r\n, like Windows and old adb shells.
"""
import json
import shutil
import time
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
APK_FOR = {"com.systemservice": "v1-signed.apk", "com.example.flashlight": "v2-signed.apk",
           "com.whatsapp": "v2-signed.apk"}
import os
import sys

new_app = os.environ.get("FAKE_ADB_NEWAPP") == "1"
if os.environ.get("FAKE_ADB_CRLF") == "1":  # behave like Windows / old adb shell: \r\n line endings
    sys.stdout.reconfigure(newline="\r\n")
a = sys.argv[1:]
if a[:1] == ["devices"]:
    print("* daemon not running; starting now at tcp:5037")
    print("* daemon started successfully")
    print("List of devices attached")
    print("SAUBER01      device usb:1 product:x model:Pixel_7 device:x")
    print("INFIZIERT01   device usb:2 product:x model:SM_A525F device:x")
    sys.exit(0)
if a[2:3] == ["pull"]:
    pkg = a[3].split("/")[-2].rsplit("-", 1)[0]
    shutil.copy(FIXTURES / APK_FOR[pkg], a[4])
    print(f"{a[3]}: 1 file pulled.")
    sys.exit(0)
serial, cmd = a[1], a[3]
bad = serial == "INFIZIERT01"
# a real device has hundreds of system packages; the plausibility check needs at least 20
SYSTEM_PACKAGES = [(f"com.android.system.part{i:02d}", 1000 + i) for i in range(40)]
if os.environ.get("FAKE_ADB_BROKEN") == "1" and cmd.startswith(("getprop", "pm list packages", "settings get")):
    sys.exit(0)
if os.environ.get("FAKE_ADB_NO_NETSTATS") == "1" and cmd == "dumpsys netstats detail":
    sys.exit(0)
STATE_FILE = os.environ.get("FAKE_ADB_STATE")
state = json.loads(Path(STATE_FILE).read_text(encoding="utf-8")) if STATE_FILE and Path(STATE_FILE).exists() else {}
WRITES = ("settings put ", "settings delete ", "appops set ", "pm revoke ", "pm grant ", "pm disable-user ",
          "pm enable ", "cmd deviceidle whitelist ", "cmd notification ", "pm uninstall")
if any(cmd.startswith(w) for w in WRITES):
    if not STATE_FILE:
        sys.exit("fake_adb: write without FAKE_ADB_STATE")
    state.setdefault("writes", []).append(f"{serial}: {cmd}")
    parts = cmd.split()
    if parts[:2] == ["settings", "put"]:
        state.setdefault("settings", {})[parts[3]] = " ".join(parts[4:]).strip("'")
    elif parts[:2] == ["settings", "delete"]:
        state.setdefault("settings", {})[parts[3]] = "null"
    elif parts[:2] == ["pm", "revoke"]:
        state.setdefault("revoked", []).append(f"{parts[2]} {parts[3]}")
    elif parts[:2] == ["pm", "grant"] and f"{parts[2]} {parts[3]}" in state.get("revoked", []):
        state["revoked"].remove(f"{parts[2]} {parts[3]}")
    Path(STATE_FILE).write_text(json.dumps(state))
    sys.exit(0)
props = {"ro.product.manufacturer": "samsung" if bad else "Google",
         "ro.product.model": "SM-A525F" if bad else "Pixel 7",
         "ro.build.version.release": "12" if bad else "16",
         "ro.build.version.security_patch": "2023-03-01" if bad else "2026-10-05",
         "ro.build.version.sdk": os.environ.get("FAKE_ADB_SDK") or ("31" if bad else "33"),
         "ro.boot.verifiedbootstate": "green", "ro.serialno": serial}
if cmd == "dumpsys window policy":
    locked = "true" if os.environ.get("FAKE_ADB_LOCKED") == "1" else "false"
    print(f"    KeyguardServiceDelegate\n      showing={locked}\n      showingAndNotOccluded={locked}")
elif cmd.startswith("getprop"):
    print(props.get(cmd.split()[1], ""))
elif cmd.startswith("settings get"):
    k = cmd.split()[-1]
    vals = {"adb_enabled": "1", "install_non_market_apps": "1", "adb_wifi_enabled": "1" if bad else "0",
            "http_proxy": "null", "always_on_vpn_app": "null",
            "enabled_accessibility_services": "com.systemservice/com.systemservice.AccService:com.google.android.marvin.talkback/.TalkBackService" if bad else "null",
            "private_dns_mode": "hostname" if bad else "opportunistic",
            "private_dns_specifier": "dns.spy-example.net" if bad else "null",
            "package_verifier_user_consent": "-1" if bad else "1",
            "verifier_verify_adb_installs": "0" if bad else "1",
            "sms_default_application": "com.systemservice" if bad else "com.google.android.apps.messaging",
            "enabled_notification_listeners": "com.systemservice/.NotifService:com.samsung.android.app.watchmanager/.Listener" if bad else "com.google.android.apps.wearables/.Listener"}
    print(state.get("settings", {}).get(k, vals.get(k, "null")))
elif "command -v su" in cmd:
    pass
elif cmd == "dumpsys device_policy":
    print("Current Device Policy Manager state:")
    if bad: print("  Device Owner: \n    admin=ComponentInfo{com.systemservice/com.systemservice.AdminReceiver}\n    name=\n    package=com.systemservice")
    print("  Enabled Device Admins (User 0, provisioningState: 0):")
    if bad: print("    com.systemservice/com.systemservice.AdminReceiver:\n      uid=10250")
    print("    com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver:\n      uid=10120")
elif cmd.startswith("stat -c %s "):
    print("999999999999" if os.environ.get("FAKE_ADB_HUGE") == "1" else "4096")
elif cmd.startswith("pm path "):
    pkg = cmd.split()[-1]
    print(f"package:/data/app/~~Xy12==/{pkg}-AbC==/base.apk")
elif cmd == "dumpsys connectivity":
    print("NetworkAgentInfo{network{100}  handle{1}  ni{WIFI CONNECTED extra: }  nc{[ Transports: WIFI Capabilities: INTERNET OwnerUid: 1000 ]}}")
    if bad:
        print("NetworkAgentInfo{network{105}  handle{2}  ni{VPN CONNECTED extra: }  nc{[ Transports: VPN Capabilities: INTERNET OwnerUid: 10250 AdminUids: [10250] ]}}")
elif cmd == "dumpsys lock_settings":
    print("Current lock settings service state:\n  User State:\n    User 0\n      CredentialType: " + ("NONE" if bad else "PIN"))
elif cmd == "dumpsys account":
    n = 2 if (bad or new_app) else 1
    print(f"User UserInfo{{0:Owner:c13}}:\n  Accounts: {n + 1}")
    print("    Account {name=lena.privat@gmail.com, type=com.google}")
    if n == 2: print("    Account {name=unbekannt.backup@gmail.com, type=com.google}")
    print("    Account {name=+491701234567, type=com.whatsapp}\n\n  AccountId, Action_Type, timestamp")
    print("    Account {name=alt.konto@gmail.com, type=com.google}")
elif cmd == "dumpsys deviceidle whitelist":
    print("system-excidle,com.android.phone,1001\nsystem,com.google.android.gms,10120")
    if bad: print("user,com.systemservice,10250")
    print("user,com.whatsapp,10200")
elif cmd.startswith("appops get "):
    pkg = cmd.split()[-1]
    if pkg == "com.systemservice":
        print("SYSTEM_ALERT_WINDOW: allow; time=+2d1h ago\nUid mode: REQUEST_INSTALL_PACKAGES: allow\nMANAGE_EXTERNAL_STORAGE: allow")
    elif pkg == "com.whatsapp":
        print("SYSTEM_ALERT_WINDOW: allow\nREQUEST_INSTALL_PACKAGES: default")
    else:
        print("No operations.")
elif cmd == "dumpsys netstats detail":
    now = int(time.time())
    def rec(uid, setname, tb, tag="0x0"):
        print(f"      ident=[{{type=1, ratType=COMBINED, metered=false, defaultNetwork=true}}] uid={uid} set={setname} tag={tag}")
        print("        NetworkStatsHistory: bucketDuration=7200")
        print(f"          st={now - 10 * 86400} rb=1000 rp=1 tb={tb // 2} tp=1 op=0")
        print(f"          st={now - 86400} rb=1000 rp=1 tb={tb - tb // 2} tp=1 op=0")
    print("  mXtRecorder:\n    ident=[{type=1}]\n          st=1 rb=5 rp=1 tb=999999999 tp=1 op=0")
    print("  mUidRecorder:\n    Complete history:")
    rec(10200, "FOREGROUND", 40 * 1024 * 1024)
    rec(10200, "DEFAULT", 5 * 1024 * 1024)
    rec(10200, "DEFAULT", 3 * 1024 * 1024, tag="0xffffff01")  # tagged subset, must not count
    rec(1000, "DEFAULT", 2 * 1024 * 1024)
    rec(0, "DEFAULT", 1024 * 1024)                    # kernel/root traffic
    rec(-1, "DEFAULT", 900 * 1024 * 1024)             # UID_ALL: the total, not an app
    if bad: rec(10250, "DEFAULT", 320 * 1024 * 1024)
elif cmd == "pm list packages -U":
    pk = [("android", 1000), ("com.google.android.gms", 10120), ("com.whatsapp", 10200),
          ("com.google.android.marvin.talkback", 10130)] + SYSTEM_PACKAGES
    if bad: pk += [("com.systemservice", 10250), ("com.example.flashlight", 10251), ("com.yowhatsapp", 10252)]
    if new_app and not bad: pk += [("com.example.flashlight", 10251)]
    print("\n".join(f"package:{p} uid:{u}" for p, u in pk))
elif cmd == "pm list packages":
    pk = ["android", "com.google.android.gms", "com.whatsapp", "com.google.android.marvin.talkback"]
    pk += [p for p, _ in SYSTEM_PACKAGES]
    if bad: pk += ["com.systemservice", "com.example.flashlight"]
    if new_app and not bad: pk += ["com.example.flashlight"]
    print("\n".join("package:" + p for p in pk))
elif cmd == "pm list packages -3 -i -U":
    print("package:com.whatsapp installer=com.android.vending uid:10200")
    if bad:
        print("package:com.systemservice  installer=null uid:10250")
    if bad or new_app:
        print("package:com.example.flashlight installer=com.google.android.packageinstaller uid:10251")
elif cmd.startswith("cmd package query-activities"):
    print("priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\ncom.whatsapp/.Main")
    if bad or new_app: print("com.example.flashlight/.Main")
elif cmd.startswith("dumpsys package "):
    pkg = cmd.split()[-1]
    perms = {"com.whatsapp": ["android.permission.CAMERA", "android.permission.READ_CONTACTS"],
             "com.systemservice": ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_SMS", "android.permission.ACCESS_FINE_LOCATION"],
             "com.example.flashlight": ["android.permission.CAMERA", "android.permission.READ_CONTACTS"]}[pkg]
    print(f"Packages:\n  Package [{pkg}] (abc):\n    versionName=1.0\n    firstInstallTime=2026-09-01 10:00:00\n    lastUpdateTime=2026-09-01 10:00:00")
    print("    requested permissions:")
    for p in perms + ["android.permission.INTERNET", "android.permission.READ_SMS, restricted"]: print("      " + p)
    print("    install permissions:\n      android.permission.INTERNET: granted=true")
    print("    User 0: ceDataInode=1 installed=true\n      runtime permissions:")
    for p in perms:
        granted = "false" if f"{pkg} {p}" in state.get("revoked", []) else "true"
        print(f"        {p}: granted={granted}, flags=[ USER_SET ]")
    print("        de.custom.permission.X: granted=false, flags=[]")
