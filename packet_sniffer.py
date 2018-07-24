import os
import time

for x in range(2):
    startTime = time.time()
    os.system("tshark –n –i wlan0mon -a duration:30 –T fields -e wlan.sa > results.txt")
    num_devices = open("results.txt", r).read().split("\n")
    results.write(startTime + ': ' + num_devices)
    time.sleep(30)
