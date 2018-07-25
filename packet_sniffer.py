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
    capture.sniff_continously(packet_count = 5)
    capture.apply_on_packets(packetHandler)
    pkt = capture[0]
    pkt.pretty_print()
    print("Done")
except KeyboardInterrupt:
    print(str(len(data)) + " Unique Addresses found")
    print(data)
