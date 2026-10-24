#!/usr/bin/env python3
"""Fake adb for tests: SAUBER01 = clean phone, INFIZIERT01 = phone with stalkerware.

FAKE_ADB_NEWAPP=1 adds an extra sideloaded app to SAUBER01 (simulates a change between scans).
"""
import os
import sys

new_app = os.environ.get("FAKE_ADB_NEWAPP") == "1"
a = sys.argv[1:]
if a[:1] == ["devices"]:
    print("* daemon not running; starting now at tcp:5037")
    print("* daemon started successfully")
    print("List of devices attached")
    print("SAUBER01      device usb:1 product:x model:Pixel_7 device:x")
    print("INFIZIERT01   device usb:2 product:x model:SM_A525F device:x")
    sys.exit(0)
serial, cmd = a[1], a[3]
bad = serial == "INFIZIERT01"
props = {"ro.product.manufacturer": "samsung" if bad else "Google",
         "ro.product.model": "SM-A525F" if bad else "Pixel 7",
         "ro.build.version.release": "12" if bad else "16",
         "ro.build.version.security_patch": "2023-03-01" if bad else "2026-10-05",
         "ro.boot.verifiedbootstate": "green", "ro.serialno": serial}
if cmd == "dumpsys window policy":
    print("    KeyguardServiceDelegate\n      showing=false\n      showingAndNotOccluded=false")
elif cmd.startswith("getprop"):
    print(props.get(cmd.split()[1], ""))
elif cmd.startswith("settings get"):
    k = cmd.split()[-1]
    vals = {"adb_enabled": "1", "adb_wifi_enabled": "1" if bad else "0",
            "http_proxy": "null", "always_on_vpn_app": "null",
            "enabled_accessibility_services": "com.systemservice/com.systemservice.AccService:com.google.android.marvin.talkback/.TalkBackService" if bad else "null",
            "enabled_notification_listeners": "com.systemservice/.NotifService:com.samsung.android.app.watchmanager/.Listener" if bad else "com.google.android.apps.wearables/.Listener"}
    print(vals.get(k, "null"))
elif "command -v su" in cmd:
    pass
elif cmd == "dumpsys device_policy":
    print("Current Device Policy Manager state:\n  Enabled Device Admins (User 0, provisioningState: 0):")
    if bad: print("    com.systemservice/com.systemservice.AdminReceiver:\n      uid=10250")
    print("    com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver:\n      uid=10120")
elif cmd == "pm list packages":
    pk = ["android", "com.google.android.gms", "com.whatsapp", "com.google.android.marvin.talkback"]
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
    for p in perms: print(f"        {p}: granted=true, flags=[ USER_SET ]")
    print("        de.custom.permission.X: granted=false, flags=[]")
