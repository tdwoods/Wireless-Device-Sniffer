import subprocess
import time

results = open('Results.txt', 'a')

for x in range(2):
    startTime = time.time()
    blah = subprocess.run(["tshark –n –i wlan0mon -a duration:30 –T fields -e wlan.sa"], stdout=subprocess.PIPE)
    num_devices = set(blah.stdout.split('\n'))
    results.write(startTime + ': ' + num_devices)
    time.sleep(30)
