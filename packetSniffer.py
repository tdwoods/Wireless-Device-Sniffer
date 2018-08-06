#!/usr/bin/env python3
# -.- coding: utf-8 -.-
try:
    import subprocess
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
    usage="packetSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help="interface (in monitor mode) for capturing the packets")
parser.add_argument("--debug", action="store_true", help="turn debug mode on")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
debugMode = args.debug
monitor_iface = args.interface
alreadyStopping = False

def restartLine():
    sys.stdout.write("\r")
    sys.stdout.flush()

header = "Welcome to Packet Sniffer"
print(header)
print("[W] Make sure to use an interface in monitor mode!\n")

externalOptionsSet = False
if debugMode:
    externalOptionsSet = True
    print("[I] Showing Debug Messages...")
if externalOptionsSet:
    print()

print("[I] Loading OUI Database...")
resolveFile = open("oui.json", "r")
resolveObj = json.load(resolveFile)

print("[I] Loading MAC Database...")
macFile = open("constant_mac_addresses.json","r")
macList = json.load(macFile)

print("[I] Initiliazing Dictionary")
deviceDictionary = {}

print("[I] Logging Current Time")
currentTime = datetime.datetime.now()

print("[I] Setting Stop Time")
stopDate = datetime.date.today()
stopTime = datetime.time(hour=22,minute=6,second=0)
stopTime = datetime.datetime.combine(stopDate,stopTime)

def stop():
    global alreadyStopping
    debug("stoping called")
    if not alreadyStopping:
        debug("setting stopping to true")
        alreadyStopping = True
        print("\n[I] Stopping...")
        print("[I] Saving results to " + str(datetime.date.today()) + ".db")
        saveToMYSQL()
        print("[I] Results saved to " + str(datetime.date.today()) + ".db")
        print("Stopped at: " + datetime.datetime.now().strftime("%H:%M:%S"))
        print("[I] packetSniffer stopped.")
        raise SystemExit


def debug(msg):
    if debugMode:
        print("[DEBUG] " + msg)


def chopping():
    while True:
        if not alreadyStopping:
            channels = [1, 6, 11]
            for channel in channels:
                subprocess.call("iwconfig " + monitor_iface + " channel " +
                           str(channel) + " > /dev/null 2>&1", shell=True)
                debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " +
                      "iwconfig " + monitor_iface + " channel " + str(channel))
                debug("[CHOPPER] HI I CHANGED CHANNEL TO " + str(channel))
                time.sleep(5)
        else:
            debug("[CHOPPER] IM STOPPING TOO")
            sys.exit()

def deviceUpdater():
    while True:
        if not alreadyStopping:
            restartLine()
            print("[I] " + str(len(deviceDictionary))+ " devices found")
            cpuTemp = subprocess.check_output(["cat", "/sys/class/thermal/thermal_zone0/temp"])
            cpuTemp = int(cpuTemp) / 1000
            print("[I] Cpu Temp: " + str(cpuTemp))
            print(str(currentTime) + " " + str(stopTime))
            saveToMYSQL()
            time.sleep(30)
        else:
            debug("[deviceUpdate] IM STOPPING TOO")
            sys.exit()

# def autoStopper():
#     for x in range(2):
#         if x == 0:
#             time.sleep(3600)
#         else:
#             stop()

def resolveMac(mac):
    global resolveObj
    if mac[:8] in resolveObj:
        return resolveObj[mac[:8]]
    return "COULDNT-RESOLVE"

def packetHandler(pkt):
    try:
        global currentTime
        global deviceDictionary
        # statusWidget(len(deviceDictionary.keys()))
        debug("packetHandler started")
        rssi = pkt.radiotap.dbm_antsignal
        mac_address = pkt.wlan.ta

        debug("resolving mac")
        vendor = resolveMac(mac_address)
        debug("vendor query done")

        debug("setting current time")
        currentTime = datetime.datetime.now()

        debug("checking current time against stop time")
        if currentTime < stopTime:
            raise SystemExit
        debug("adding to dictionary")
        # if vendor != "COULDNT-RESOLVE":
        #     if mac_address not in macList:
        #         debug("success added")
        if mac_address in deviceDictionary:
            deviceDictionary[mac_address]["timeLastSeen"] = currentTime.strftime("%H:%M:%S")
            deviceDictionary[mac_address]["timesCounted"] += 1
            if rssi < deviceDictionary[mac_address]["RSSI"]:
                deviceDictionary[mac_address]["RSSI"] = rssi
        else:
            deviceDictionary[mac_address] = {"RSSI":rssi, "Vendor":vendor,
                                   "timesCounted":1, "timeFirstSeen": currentTime.strftime("%H:%M:%S"),
                                   "timeLastSeen":"N/A"}
        #statusWidget(len(deviceDictionary.keys()))
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN packetHandler")
        debug(traceback.format_exc())

def saveToMYSQL():
    try:
        global deviceDictionary
        debug("saveToMYSQL called")
        db = sqlite3.connect(str(datetime.date.today()) + ".db")
        cursor = db.cursor()
        for m in deviceDictionary:
            r = deviceDictionary[m]["RSSI"]
            v = deviceDictionary[m]["Vendor"]
            tc = deviceDictionary[m]["timesCounted"]
            tfs = deviceDictionary[m]["timeFirstSeen"]
            tls = deviceDictionary[m]["timeLastSeen"]
            cursor.execute("INSERT OR REPLACE INTO packetSniffer (mac_address, vendor, rssi, timesCounted, timeFirstSeen, timeLastSeen) VALUES (?,?,?,?,?,?)", (m,v,r,tc,tfs,tls))
        db.commit()
        db.close()
    except:
        print("Crash saveSQL")
        debug("[!!!] CRASH IN saveToMYSQL")
        debug(traceback.format_exc())

def main():
    global alreadyStopping

    print("[I] Setting up SQLite...")

    try:
        setupDB = sqlite3.connect(str(datetime.date.today()) + ".db")
    except:
        print("\n[!] Cant connect to database. Permission error?\n")
        exit()
    setupCursor = setupDB.cursor()
    setupCursor.execute("DROP TABLE IF EXISTS packetSniffer")
    setupCursor.execute(
        """CREATE TABLE packetSniffer
            (mac_address VARCHAR(50) primary key, vendor VARCHAR(50),
             rssi INT, timesCounted INT, timeFirstSeen VARCHAR(50),
             timeLastSeen VARCHAR(50))""")
    setupDB.commit()
    setupDB.close()

    print("[I] Starting channelhopper in a new thread...")
    path = os.path.realpath(__file__)
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()
    #statusWidget(len(deviceDictionary.keys()))

    print("[I] Starting deviceUpdater in a new thread...")
    path = os.path.realpath(__file__)
    updater = threading.Thread(target=deviceUpdater)
    updater.daemon = True
    updater.start()

    # print("[I] Starting autoStopper in a new thread...")
    # path = os.path.realpath(__file__)
    # stopper = threading.Thread(target=autoStopper)
    # stopper.daemon = True
    # stopper.start()

    print("\n[I] Sniffing started... Please wait for requests to show up...\n")

    while True:
        try:
            capture = pyshark.LiveCapture(interface=monitor_iface, bpf_filter="type mgt subtype probe-req")
            capture.apply_on_packets(packetHandler)
        except KeyboardInterrupt:
            stop()
        except SystemExit:
            stop()
        except:
            print("[!] An error occurred. Debug:")
            print(traceback.format_exc())
            print("[!] Restarting in 5 sec... Press CTRL + C to stop.")
            try:
                time.sleep(5)
            except:
                stop()
    stop()

if __name__ == "__main__":
    main()
