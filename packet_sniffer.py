import datetime
import pyshark
import sqlite3
import subprocess
import time

addresses = []
def packetHandler(packet):
    print("Packet Captured")
    if packet.wlan.ta not in addresses:
        addresses.append(packet.wlan.ta)


while True:
    try:
        print("Starting Capture")
        capture = LiveCapture(interface = 'wlan0mon', bpf_filter = 'type mgt subtype probe-req')
        capture.sniff(timeout=60)
        capture.apply_on_packets(packetHandler)
    except KeyboardInterrupt:
        print(len(addresses) + "Unique Addresses found")
