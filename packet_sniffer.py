import datetime
import pyshark
import sqlite3
import subprocess
import time

data = {}
def packetHandler(packet):
    print("Packet Captured")
    if packet.wlan.ta not in data:
        data[packet.wlan.ta] = packet.radiotap.dbm_antsignal

try:
    print("Starting Capture")
    capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter = 'type mgt subtype probe-req')
    capture.sniff(timeout=10)
    capture.apply_on_packets(packetHandler)
    print("Done")
except KeyboardInterrupt:
    print(str(len(addresses)) + " Unique Addresses found")
    print(data)
