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
    import concurrent.futures
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
    usage="packetSniffer.py [options]")
parser.add_argument("--debug", action="store_true", help="turn debug mode on")

args = parser.parse_args()
debugMode = args.debug
alreadyStopping = False

def restartLine():
    sys.stdout.write("\r")
    sys.stdout.flush()

print("Welcome to Daytime Sniffer")

print("[I] Selecting correct interface")
try:
    print("1")
    wirelessInterfaces = subprocess.check_output(["sudo","lshw","-C","network"],shell=True)
    print("2")
    wirelessInterfaces = str(wirelessInterfaces).split("*")
    wirelessInterfaces = [x for x in wirelessInterfaces if "Ralink" in x][0].split("\\n")
    interfaceName = [x for x in wirelessInterfaces if "logical name" in x][0].split(":")[1].strip()
    if "mon" not in interfaceName:
        print("hi")
        suprocess.call("sudo airmon-ng start " + interfaceName, shell=True)
        interfaceName += "mon"
except:
    print("[I] Error setting up interface. Are you sure adapter is plugged in?")
    sys.exit(1)

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
try:
    macFile = open("constant_devices.json","r")
    macList = json.load(macFile)
except:
    print("[I] Couldn't load mac database")
    macList = []

print("[I] Initiliazing Dictionary")
deviceDictionary = {}

print("[I] Logging Current Time")
currentTime = datetime.datetime.now()

print("[I] Setting Stop Time")
stopDate = datetime.date.today()
stopTime = datetime.time(hour=22,minute=0,second=0)
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
                subprocess.call("sudo iwconfig " + interfaceName + " channel " +
                           str(channel) + " > /dev/null 2>&1", shell=True)
                debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " +
                      "iwconfig " + interfaceName + " channel " + str(channel))
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
            cpuTemp = subprocess.check_output(["sudo", "cat", "/sys/class/thermal/thermal_zone0/temp"])
            cpuTemp = int(cpuTemp) / 1000
            print("[I] Cpu Temp: " + str(cpuTemp))
            print("[I] Time: " + str(currentTime))
            saveToMYSQL()
            time.sleep(900)
        else:
            debug("[deviceUpdate] IM STOPPING TOO")
            sys.exit()

def resolveMac(mac):
    global resolveObj
    if mac[:8].upper() in resolveObj:
        return resolveObj[mac[:8].upper() ]
    return "COULDNT-RESOLVE"

def packetHandler(pkt):
    try:
        global currentTime
        global deviceDictionary

        rssi = pkt.radiotap.dbm_antsignal
        mac_address = pkt.wlan.ta
        debug("resolving mac")
        vendor = resolveMac(mac_address)
        debug("vendor query done")

        debug("setting current time")
        currentTime = datetime.datetime.now()

        debug("adding to dictionary")
        if mac_address not in macList:
            if mac_address in deviceDictionary:
                deviceDictionary[mac_address]["timeLastSeen"] = currentTime.strftime("%H:%M:%S")
                deviceDictionary[mac_address]["timesCounted"] += 1
                if rssi < deviceDictionary[mac_address]["RSSI"]:
                    deviceDictionary[mac_address]["RSSI"] = rssi
            else:
                deviceDictionary[mac_address] = {"RSSI":rssi, "Vendor":vendor,
                                       "timesCounted":1, "timeFirstSeen": currentTime.strftime("%H:%M:%S"),
                                       "timeLastSeen":"N/A"}
    except KeyboardInterrupt:
        stop()
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

    print("[I] Starting deviceUpdater in a new thread...")
    path = os.path.realpath(__file__)
    updater = threading.Thread(target=deviceUpdater)
    updater.daemon = True
    updater.start()

    print("\n[I] Sniffing started... Please wait for requests to show up...\n")

    while True:
        try:
            timeoutPeriod = (stopTime - currentTime).total_seconds()
            capture = pyshark.LiveCapture(interface=interfaceName, bpf_filter="type mgt subtype probe-req")
            capture.apply_on_packets(packetHandler, timeout = timeoutPeriod)
        except KeyboardInterrupt:
            stop()
        except concurrent.futures.TimeoutError:
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
