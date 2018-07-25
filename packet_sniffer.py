import datetime
import pyshark
import sqlite3
import subprocess
import time

global continue_running = True
data = {}
def packetHandler(packet):
    print("Packet Captured")
    if packet.wlan.ta not in data:
        data[packet.wlan.ta] = packet.radiotap.dbm_antsignal
    packet.pretty_print()
    if(data >= 10) continue_running = False

while continue_running:
    try:
        print("Starting Capture")
        capture = pyshark.LiveCapture(interface = 'wlan0mon', bpf_filter = 'type mgt subtype probe-req')
        capture.sniff_continously()
        capture.apply_on_packets(packetHandler)
    except KeyboardInterrupt:
        print(str(len(data)) + " Unique Addresses found")
        print(data)
print("Done")
print(data)
