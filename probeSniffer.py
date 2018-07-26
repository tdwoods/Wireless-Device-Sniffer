#!/usr/bin/env python3
# -.- coding: utf-8 -.-

try:
    import os
    import sys
    import time
    import json
    import pyshark
    import sqlite3
    import datetime
    import argparse
    import threading
    import traceback
    import urllib.request as urllib2
except KeyboardInterrupt:
    print("\n[I] Stopping...")
    raise SystemExit
except:
    print("[!] Failed to import the dependencies... " +\
            "Please make sure to install all of the requirements " +\
            "and try again.")
    raise SystemExit

parser = argparse.ArgumentParser(
    usage="probeSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help='interface (in monitor mode) for capturing the packets')
parser.add_argument("--debug", action='store_true', help='turn debug mode on')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
debugMode = args.debug
monitor_iface = args.interface
alreadyStopping = False


def restart_line():
    sys.stdout.write('\r')
    sys.stdout.flush()


def statusWidget(deviceNumber):
    sys.stdout.write("Devices found: [" + str(deviceNumber) + "]")
    restart_line()
    sys.stdout.flush()


header = """
 ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____
|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \\
|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )
|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /
|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \\
|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \\
|__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__|
"""
print(header)
print("[W] Make sure to use an interface in monitor mode!\n")

externalOptionsSet = False
if debugMode:
    externalOptionsSet = True
    print("[I] Showing debug messages...")
if externalOptionsSet:
    print()

print("[I] Loading MAC database...")
resolveFile = open("oui.json", "r")
resolveObj = json.load(resolveFile)

print("[I] Initiliazing Dictionary")
deviceDictionary = {}

def stop():
    global alreadyStopping
    debug("stoping called")
    if not alreadyStopping:
        debug("setting stopping to true")
        alreadyStopping = True
        print("\n[I] Stopping...")
        print("[I] Saving results to DB-probeSniffer.db")
        saveToMYSQL(deviceDictionary)
        print("[I] Results saved to 'DB-probeSniffer.db'")
        print("[I] probeSniffer stopped.")
        raise SystemExit


def debug(msg):
    if debugMode:
        print("[DEBUG] " + msg)


def chopping():
    while True:
        if not alreadyStopping:
            channels = [1, 6, 11]
            for channel in channels:
                os.system("iwconfig " + monitor_iface + " channel " +
                          str(channel) + " > /dev/null 2>&1")
                debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " +
                      "iwconfig " + monitor_iface + " channel " + str(channel))
                debug("[CHOPPER] HI I CHANGED CHANNEL TO " + str(channel))
                time.sleep(5)
        else:
            debug("[CHOPPER] IM STOPPING TOO")
            sys.exit()

def resolveMac(mac):
    try:
        global resolveObj
        for macArray in resolveObj:
            if macArray[0] == mac[:8].upper():
                return macArray[1]
        return "COULDNT-RESOLVE"
    except:
        return "RESOLVE-ERROR"

def packetHandler(pkt):
    try:
        statusWidget(len(deviceDictionary.keys()))
        debug("packetHandler started")

        rssi = pkt.radiotap.dbm_antsignal
        mac_address = pkt.wlan.ta

        debug("resolving mac")
        vendor = resolveMac(mac_address)
        debug("vendor query done")

        debug("setting timestamp")
        currentTimeStamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        debug("checking for duplicates")
        if mac_address in deviceDictionary:
            deviceDictionary[mac_address]["timeLastSeen"] = currentTimeStamp
            deviceDictionary[mac_address]["timesCounted"] += 1
        else:
            deviceDictionary[mac_address] = {"RSSI":rssi, "Vendor":vendor,
                                   "timesCounted":0, "timeFirstSeen": currentTimeStamp,
                                   "timeLastSeen":"N/A"}
        statusWidget(len(deviceDictionary.keys()))
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN packetHandler")
        debug(traceback.format_exc())

def saveToMYSQL(deviceDictionary):
    try:
        debug("saveToMYSQL called")
        db = sqlite3.connect("DB-probeSniffer.db")
        cursor = db.cursor()
        for mac_address in deviceDictionary:
            rssi = deviceDictionary[mac_address]["RSSI"]
            vendor = deviceDictionary[mac_address]["Vendor"]
            tc = deviceDictionary[mac_address]["timesCounted"]
            tfs = deviceDictionary[mac_address]["timeFirstSeen"]
            tls = deviceDictionary[mac_address]["timeLastSeen"]
            cursor.execute("INSERT INTO probeSniffer VALUES (?, ?, ?, ?, ?, ?)", (mac_address, vendor, rssi, tc, tfs, tls))
        db.commit()
        db.close()
    except:
        debug("[!!!] CRASH IN saveToMYSQL")
        debug(traceback.format_exc())

def main():
    global alreadyStopping

    if not noSQL:
        print("[I] Setting up SQLite...")

        try:
            setupDB = sqlite3.connect("DB-probeSniffer.db")
        except:
            print("\n[!] Cant connect to database. Permission error?\n")
            exit()
        setupCursor = setupDB.cursor()
        setupCursor.execute(
            '''CREATE TABLE IF NOT EXISTS probeSniffer
                (mac_address VARCHAR(50) primary key, vendor VARCHAR(50),
                 rssi INT, timesCounted INT, timeFirstSeen VARCHAR(50),
                 timeLastSeen VARCHAR(50))''')
        setupDB.commit()
        setupDB.close()

    print("[I] Starting channelhopper in a new thread...")
    path = os.path.realpath(__file__)
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()
    print("[I] Saving requests to 'DB-probeSniffer.db'")
    print("\n[I] Sniffing started... Please wait for requests to show up...\n")
    statusWidget(len(deviceDictionary.keys()))

    while True:
        try:
            capture = pyshark.LiveCapture(interface=monitor_iface, bpf_filter='type mgt subtype probe-req')
            capture.apply_on_packets(packetHandler)
        except KeyboardInterrupt:
            stop()
        except:
            print("[!] An error occurred. Debug:")
            print(traceback.format_exc())
            print("[!] Restarting in 5 sec... Press CTRL + C to stop.")
            try:
                time.sleep(5)
            except:
                stop()

if __name__ == "__main__":
    main()
