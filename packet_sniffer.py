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
    packet.pretty_print()
    if(len(data.keys) >= 10):
         break

try:
    print("Starting Capture")
    capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter = 'type mgt subtype probe-req')
    capture.sniff_continuously()
    capture.apply_on_packets(packetHandler)
except KeyboardInterrupt:
    print(str(len(data)) + " Unique Addresses found")
    print(data)
print("Done")
print(data)
